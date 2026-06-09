package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glebov/awg-proxy-go/internal/awg"
	"github.com/glebov/awg-proxy-go/internal/config"
	"github.com/glebov/awg-proxy-go/internal/router"
	"github.com/glebov/awg-proxy-go/internal/wg"
)

// clientProxy — реализация client-режима (1:1).
//
// Поток трафика:
//
//	wg-out (роутер) ──► (dst-nat) ──► наш UDP-listen ──► obfuscate ──► AWG-сервер
//	         ◄─── deobfuscate ──── наш UDP-listen ◄──── ответ ◄────┘
type clientProxy struct {
	cfg    *config.Config
	params awg.Params
	poller *router.Poller
	log    *slog.Logger

	// Адрес WG-сокета роутера (запоминается при первом входящем пакете
	// и используется для возврата ответов от AWG-сервера).
	routerSrc atomic.Pointer[net.UDPAddr]

	// Защита от спама лога «нет апстрима / нет адресата».
	logMu   sync.Mutex
	lastLog time.Time
}

func newClient(cfg *config.Config, params awg.Params, poller *router.Poller, log *slog.Logger) *clientProxy {
	return &clientProxy{
		cfg:    cfg,
		params: params,
		poller: poller,
		log:    log,
	}
}

// Run поднимает UDP-листенер для роутера и сокет для апстрима AWG.
func (c *clientProxy) Run(ctx context.Context) error {
	laddr, err := net.ResolveUDPAddr("udp", c.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	routerConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", c.cfg.Listen, err)
	}
	// Отдельный сокет для апстрима: не Dial'им, потому что endpoint apстрима
	// может меняться между тиками (правка peer'а на роутере). Пишем
	// WriteToUDPAddrPort с актуальным адресом из snapshot.
	awgConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("listen awg socket: %w", err)
	}
	c.log.Info("client proxy listening", "router_side", routerConn.LocalAddr(), "awg_side", awgConn.LocalAddr())

	context.AfterFunc(ctx, func() {
		routerConn.Close()
		awgConn.Close()
	})

	var wgGroup sync.WaitGroup
	wgGroup.Go(func() { c.routerLoop(routerConn, awgConn) })
	wgGroup.Go(func() { c.awgLoop(routerConn, awgConn) })
	wgGroup.Wait()
	return ctx.Err()
}

// routerLoop: роутер -> прокси -> AWG-сервер (наложение обфускации).
func (c *clientProxy) routerLoop(routerConn, awgConn *net.UDPConn) {
	buf := make([]byte, maxPacket)
	for {
		n, addr, err := routerConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Сохраняем адрес WG-сокета роутера для обратки.
		c.routerSrc.Store(addr)

		snap := c.poller.Snapshot()
		if snap == nil || snap.Upstream == nil {
			c.warnRateLimited("no upstream peer (mark one with [awgproxy] in comment)")
			continue
		}
		up := snap.Upstream
		typ := wg.Type(buf[:n])
		// Перед каждым handshake-init шлём Jc junk-пакетов: AmneziaWG-сервер
		// ждёт их от инициатора, без них handshake тихо дропается.
		if typ == wg.TypeInit {
			for _, j := range c.params.JunkPackets() {
				if _, err := awgConn.WriteToUDPAddrPort(j, up.RemoteAddr); err != nil {
					c.log.Warn("send junk to upstream failed", "err", err)
					break
				}
			}
			c.log.Debug("forwarding init", "to", up.RemoteAddr, "size", n)
		}
		out := c.params.Obfuscate(buf[:n], up.ServerPub)
		if _, err := awgConn.WriteToUDPAddrPort(out, up.RemoteAddr); err != nil {
			c.log.Warn("send to upstream failed", "err", err)
		}
	}
}

// awgLoop: AWG-сервер -> прокси -> роутер (снятие обфускации).
func (c *clientProxy) awgLoop(routerConn, awgConn *net.UDPConn) {
	buf := make([]byte, maxPacket)
	for {
		n, src, err := awgConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		snap := c.poller.Snapshot()
		if snap == nil {
			continue
		}
		plain, typ, ok := c.params.Deobfuscate(buf[:n], snap.ServerPub)
		if !ok {
			c.log.Debug("dropped junk from upstream", "from", src, "size", n)
			continue
		}
		addr := c.routerSrc.Load()
		if addr == nil {
			c.warnRateLimited("no router src yet, dropping awg reply")
			continue
		}
		if typ == wg.TypeResponse {
			c.log.Debug("got handshake response", "from", src)
		}
		if _, err := routerConn.WriteToUDP(plain, addr); err != nil {
			c.log.Warn("send to router failed", "err", err)
		}
	}
}

// warnRateLimited пишет warn не чаще раза в 5 секунд (защита от спама).
func (c *clientProxy) warnRateLimited(msg string) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	if time.Since(c.lastLog) < 5*time.Second {
		return
	}
	c.lastLog = time.Now()
	c.log.Warn(msg)
}
