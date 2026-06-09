package proxy

import (
	"context"
	"net"
	"sync"
	"time"
)

// session — состояние одного клиента (по его UDP-адресу).
type session struct {
	addr        *net.UDPAddr
	clientIndex uint32   // sender_index клиента (из init)
	pub         [32]byte // pubkey клиента, если удалось определить точно
	pubKnown    bool
	lastSeen    time.Time
}

// table — потокобезопасная таблица сессий.
type table struct {
	mu      sync.Mutex
	byAddr  map[string]*session
	byIndex map[uint32]*session // clientIndex -> session, для маршрутизации ответов
	ttl     time.Duration
}

func newTable(ttl time.Duration) *table {
	return &table{
		byAddr:  make(map[string]*session),
		byIndex: make(map[uint32]*session),
		ttl:     ttl,
	}
}

func (t *table) getLocked(addr *net.UDPAddr) *session {
	key := addr.String()
	s := t.byAddr[key]
	if s == nil {
		s = &session{addr: addr}
		t.byAddr[key] = s
	}
	return s
}

// clientInit регистрирует сессию по handshake-init клиента.
func (t *table) clientInit(addr *net.UDPAddr, clientIndex uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.getLocked(addr)
	s.clientIndex = clientIndex
	s.lastSeen = time.Now()
	t.byIndex[clientIndex] = s
}

// clientTraffic отмечает активность клиента.
func (t *table) clientTraffic(addr *net.UDPAddr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.getLocked(addr)
	s.lastSeen = time.Now()
}

// setPub фиксирует точно определённый pubkey клиента (из расшифровки init).
func (t *table) setPub(addr *net.UDPAddr, pub [32]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.getLocked(addr)
	s.pub = pub
	s.pubKnown = true
}

// responseTargets возвращает адрес клиента и набор pubkey для пересчёта MAC1
// ответа. Если pubkey известен точно (расшифровали init) — отдаём один ключ.
// Иначе для handshake-response (needPub) возвращаются ВСЕ кандидаты сразу
// (burst): клиент примет копию с верным MAC1, остальные отбросит — это сворачивает
// подбор в один round-trip вместо перебора по кандидату на каждый ретрай handshake.
// Для прочих типов (transport/cookie) MAC1 нет — отдаём один нулевой ключ.
func (t *table) responseTargets(clientIndex uint32, cands [][32]byte, needPub bool) (*net.UDPAddr, [][32]byte, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.byIndex[clientIndex]
	if s == nil {
		return nil, nil, false
	}
	s.lastSeen = time.Now()
	switch {
	case !needPub:
		return s.addr, [][32]byte{{}}, true
	case s.pubKnown:
		return s.addr, [][32]byte{s.pub}, true
	case len(cands) == 0:
		return s.addr, [][32]byte{{}}, true
	default:
		return s.addr, cands, true
	}
}

func (t *table) gc() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for k, s := range t.byAddr {
		if now.Sub(s.lastSeen) > t.ttl {
			delete(t.byAddr, k)
			delete(t.byIndex, s.clientIndex)
		}
	}
}

func (t *table) gcLoop(ctx context.Context) {
	tk := time.NewTicker(t.ttl)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.gc()
		}
	}
}
