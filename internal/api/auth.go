package api

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	sessionCookie = "awgproxy_session"
	sessionTTL    = 12 * time.Hour
)

// sessions — in-memory хранилище токенов веб-сессий. Токены не переживают
// перезапуск контейнера (после рестарта нужно войти заново) — этого достаточно.
type sessions struct {
	mu sync.Mutex
	m  map[string]time.Time // токен -> срок действия
}

func newSessions() *sessions { return &sessions{m: make(map[string]time.Time)} }

// create выдаёт новый токен сессии.
func (s *sessions) create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.m[tok] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	return tok, nil
}

// valid проверяет токен и попутно чистит просроченный.
func (s *sessions) valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, tok)
		return false
	}
	return true
}

func (s *sessions) drop(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// Ограничение перебора пароля.
const (
	maxFails    = 5               // неудач подряд до блокировки
	failWindow  = 5 * time.Minute // окно подсчёта неудач
	lockoutTime = 5 * time.Minute // длительность блокировки
)

type attempt struct {
	fails     int
	first     time.Time // начало текущего окна подсчёта
	lockUntil time.Time
}

// limiter ограничивает частоту попыток входа по ключу (IP клиента).
type limiter struct {
	mu sync.Mutex
	m  map[string]*attempt
}

func newLimiter() *limiter { return &limiter{m: make(map[string]*attempt)} }

// allowed сообщает, можно ли пробовать вход; при блокировке — сколько ждать.
func (l *limiter) allowed(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[key]
	if a == nil {
		return true, 0
	}
	if d := time.Until(a.lockUntil); d > 0 {
		return false, d
	}
	return true, 0
}

// fail регистрирует неудачу и при превышении порога ставит блокировку.
func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	a := l.m[key]
	if a == nil || now.Sub(a.first) > failWindow {
		a = &attempt{first: now}
		l.m[key] = a
	}
	a.fails++
	if a.fails >= maxFails {
		a.lockUntil = now.Add(lockoutTime)
		a.fails = 0
		a.first = now
	}
}

// reset снимает счётчик при успешном входе.
func (l *limiter) reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}
