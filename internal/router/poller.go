// Package router читает с RouterOS через REST API публичные ключи WireGuard:
// ключ самого интерфейса (сервера) и ключи всех пиров (клиентов).
package router

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// Режимы (зеркалят config; повторены тут, чтобы не зависеть от пакета config).
const (
	ModeServer = "server"
	ModeClient = "client"
)

// PeerMarker — префикс comment'а помеченного peer'а на роутере.
// Дублирует config.PeerMarker, чтобы не тянуть зависимость.
const PeerMarker = "[awgproxy]"

// Snapshot — снимок состояния роутера, прочитанный поллером.
type Snapshot struct {
	// Общее: ключ WG-интерфейса роутера и (опц.) его приватный ключ.
	ServerPub  [32]byte
	ServerPriv [32]byte // нулевой = нет

	// listen-port WG-интерфейса. В client-режиме используется как src-port
	// в NAT-правиле; в server-режиме игнорируется.
	WGListenPort int

	// server-режим: публичные ключи всех пиров (кандидаты для MAC1 ответа).
	ClientPubs [][32]byte

	// client-режим: единственный помеченный peer = апстрим AWG-сервера.
	// nil, если ни одного помеченного peer'а не найдено.
	Upstream *Upstream
}

// Upstream — апстрим в client-режиме (помеченный peer на роутере).
type Upstream struct {
	PeerID     string         // .id RouterOS — для PATCH/DELETE из UI
	ServerPub  [32]byte       // публичный ключ AWG-сервера (для MAC1 нашего init)
	RemoteAddr netip.AddrPort // куда форвардить (после резолва DNS)
	PSK        [32]byte
	Comment    string // оригинальный комментарий без префикса [awgproxy]
}

// Config — параметры подключения и опроса (REST API).
type Config struct {
	Address  string
	APIPort  int
	APITLS   bool
	User     string
	Password string
	Iface    string
	Interval time.Duration
	Mode     string // server | client — что собирать в Snapshot
}

// Poller периодически опрашивает роутер и хранит актуальный Snapshot.
type Poller struct {
	cfg Config
	log *slog.Logger
	cur atomic.Pointer[Snapshot]
}

func New(cfg Config, log *slog.Logger) *Poller {
	return &Poller{cfg: cfg, log: log}
}

// Snapshot возвращает последний успешно прочитанный снимок (или nil).
func (p *Poller) Snapshot() *Snapshot { return p.cur.Load() }

// Run опрашивает роутер сразу и затем каждые cfg.Interval до отмены ctx.
// onTick (если не nil) вызывается после каждого успешного тика — например,
// для NAT-реконсилера.
func (p *Poller) Run(ctx context.Context, onTick func(context.Context, *Snapshot)) {
	p.tick(ctx, onTick)
	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.tick(ctx, onTick)
		}
	}
}

func (p *Poller) tick(ctx context.Context, onTick func(context.Context, *Snapshot)) {
	snap, err := p.Fetch(ctx)
	if err != nil {
		p.log.Warn("router poll failed", "err", err)
		return
	}
	p.cur.Store(snap)
	p.log.Debug("snapshot updated",
		"clients", len(snap.ClientPubs),
		"wg_listen", snap.WGListenPort,
		"upstream", snap.Upstream != nil,
	)
	if onTick != nil {
		onTick(ctx, snap)
	}
}

// Fetch читает состояние через REST API.
func (p *Poller) Fetch(ctx context.Context) (*Snapshot, error) {
	return p.fetchAPI(ctx)
}

// pickUpstream выбирает помеченный peer для client-режима. В случае
// неоднозначности возвращает nil и пишет warn.
func (p *Poller) pickUpstream(peers []markedPeer) *Upstream {
	var marked []markedPeer
	for _, m := range peers {
		if m.disabled {
			continue
		}
		if _, ok := strings.CutPrefix(m.comment, PeerMarker); ok {
			marked = append(marked, m)
		}
	}
	switch len(marked) {
	case 0:
		return nil
	case 1:
		// ok
	default:
		p.log.Warn("multiple peers marked with [awgproxy], pick one", "count", len(marked))
		return nil
	}
	m := marked[0]
	if m.endpointAddr == "" || m.endpointPort == 0 {
		p.log.Warn("marked peer has no endpoint", "id", m.id)
		return nil
	}
	pub, err := parsePubKey(m.publicKey)
	if err != nil {
		p.log.Warn("marked peer public-key invalid", "id", m.id, "err", err)
		return nil
	}
	addr, err := resolveAddrPort(m.endpointAddr, m.endpointPort)
	if err != nil {
		p.log.Warn("marked peer endpoint resolve failed", "endpoint", m.endpointAddr, "err", err)
		return nil
	}
	var psk [32]byte
	if m.psk != "" {
		psk, _ = parsePubKey(m.psk)
	}
	u := &Upstream{
		PeerID:     m.id,
		ServerPub:  pub,
		RemoteAddr: addr,
		PSK:        psk,
	}
	if rest, ok := strings.CutPrefix(m.comment, PeerMarker); ok {
		u.Comment = strings.TrimSpace(rest)
	}
	return u
}

// markedPeer — внутреннее представление peer'а для отбора апстрима.
type markedPeer struct {
	id           string
	comment      string
	publicKey    string
	psk          string
	endpointAddr string
	endpointPort int
	disabled     bool
}

// parsePubKey декодирует один base64-ключ WireGuard (32 байта).
func parsePubKey(s string) ([32]byte, error) {
	var k [32]byte
	s = strings.TrimSpace(s)
	if s == "" {
		return k, fmt.Errorf("empty key")
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, err
	}
	if len(raw) != 32 {
		return k, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	copy(k[:], raw)
	return k, nil
}

// resolveAddrPort резолвит host:port (host может быть DNS-именем) в netip.AddrPort.
// Берём первый адрес из ответа в детерминированном порядке.
func resolveAddrPort(host string, port int) (netip.AddrPort, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a, uint16(port)), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no addresses for %s", host)
	}
	// детерминированный порядок — сортируем по строковому представлению.
	pick := ips[0]
	for _, ip := range ips[1:] {
		if ip.String() < pick.String() {
			pick = ip
		}
	}
	return netip.AddrPortFrom(pick, uint16(port)), nil
}
