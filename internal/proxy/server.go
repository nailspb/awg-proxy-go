package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/glebov/awg-proxy-go/internal/awg"
	"github.com/glebov/awg-proxy-go/internal/config"
	"github.com/glebov/awg-proxy-go/internal/router"
	"github.com/glebov/awg-proxy-go/internal/wg"
)

// serverProxy — реализация server-режима (1:N).
type serverProxy struct {
	cfg    *config.Config
	params awg.Params
	poller *router.Poller
	log    *slog.Logger
	tbl    *table
}

func newServer(cfg *config.Config, params awg.Params, poller *router.Poller, log *slog.Logger) *serverProxy {
	return &serverProxy{
		cfg:    cfg,
		params: params,
		poller: poller,
		log:    log,
		tbl:    newTable(cfg.SessionTTL),
	}
}

// Run поднимает UDP-листенер клиентов и соединение с WG-сервером и работает до ctx.Done().
func (s *serverProxy) Run(ctx context.Context) error {
	laddr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	clientConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}
	raddr, err := net.ResolveUDPAddr("udp", s.cfg.Remote)
	if err != nil {
		return fmt.Errorf("remote address: %w", err)
	}
	serverConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", s.cfg.Remote, err)
	}

	context.AfterFunc(ctx, func() {
		clientConn.Close()
		serverConn.Close()
	})

	var wgGroup sync.WaitGroup
	wgGroup.Go(func() { s.clientLoop(clientConn, serverConn) })
	wgGroup.Go(func() { s.serverLoop(clientConn, serverConn) })
	wgGroup.Go(func() { s.tbl.gcLoop(ctx) })
	wgGroup.Wait()
	return ctx.Err()
}

// clientLoop: клиент -> прокси -> WG-сервер (снятие обфускации).
func (s *serverProxy) clientLoop(client, server *net.UDPConn) {
	buf := make([]byte, maxPacket)
	for {
		n, addr, err := client.ReadFromUDP(buf)
		if err != nil {
			return // соединение закрыто
		}
		snap := s.poller.Snapshot()
		if snap == nil {
			s.log.Debug("keys snapshot not ready, dropping packet")
			continue
		}
		plain, typ, ok := s.params.Deobfuscate(buf[:n], snap.ServerPub)
		if !ok {
			continue // junk-пакет
		}
		switch typ {
		case wg.TypeInit:
			s.tbl.clientInit(addr, wg.SenderIndex(plain))
			// Если есть приватный ключ сервера — определяем клиента точно
			// (расшифровкой init) и запоминаем pubkey, чтобы не перебирать.
			if snap.ServerPriv != ([32]byte{}) {
				if pub, ok := awg.ClientPubFromInit(plain, snap.ServerPriv, snap.ServerPub); ok {
					s.tbl.setPub(addr, pub)
				}
			}
		case wg.TypeTransport:
			s.tbl.clientTraffic(addr)
		}
		if _, err := server.Write(plain); err != nil {
			s.log.Warn("forward to WG server failed", "err", err)
		}
	}
}

// serverLoop: WG-сервер -> прокси -> клиент (наложение обфускации).
func (s *serverProxy) serverLoop(client, server *net.UDPConn) {
	buf := make([]byte, maxPacket)
	for {
		n, err := server.Read(buf)
		if err != nil {
			return
		}
		snap := s.poller.Snapshot()
		if snap == nil {
			continue
		}
		plain := buf[:n]
		typ := wg.Type(plain)
		idx := wg.ReceiverIndex(plain)
		addr, pubs, ok := s.tbl.responseTargets(idx, snap.ClientPubs, typ == wg.TypeResponse)
		if !ok {
			s.log.Debug("no session for reply", "type", typ, "recv_index", idx)
			continue
		}
		// pubs — либо один точно известный ключ клиента, либо (если не
		// определили) все кандидаты: верную копию (по MAC1) клиент примет,
		// прочие отбросит.
		for _, pub := range pubs {
			out := s.params.Obfuscate(plain, pub)
			if _, err := client.WriteToUDP(out, addr); err != nil {
				s.log.Warn("send to client failed", "err", err)
				break
			}
		}
	}
}
