package binapi

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Sentence — ответное предложение RouterOS API.
// Reply — !done | !re | !trap | !fatal. Words — пары "=key=value" (без префикса '=' в ключе).
type Sentence struct {
	Reply string
	Words map[string]string
}

// Trap — ошибка из !trap (ROS вернул её на запрос).
type Trap struct {
	Category string // =category=
	Message  string // =message=
}

func (t *Trap) Error() string {
	if t.Category != "" {
		return fmt.Sprintf("ros trap (%s): %s", t.Category, t.Message)
	}
	return "ros trap: " + t.Message
}

// Conn — соединение с RouterOS API (синхронное; запрос-ответ под мьютексом снаружи).
type Conn struct {
	c  net.Conn
	br *bufio.Reader
}

// Dial устанавливает TCP-соединение и логинится. tls=true → API-SSL.
// addr — "host:port" (8728 для api, 8729 для api-ssl).
func Dial(ctx context.Context, addr string, useTLS bool, user, password string) (*Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	var (
		c   net.Conn
		err error
	)
	if useTLS {
		td := &tls.Dialer{NetDialer: &d, Config: &tls.Config{InsecureSkipVerify: true}}
		c, err = td.DialContext(ctx, "tcp", addr)
	} else {
		c, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	conn := &Conn{c: c, br: bufio.NewReader(c)}
	if err := conn.login(ctx, user, password); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Close закрывает TCP-соединение. Идемпотентно.
func (c *Conn) Close() error {
	if c == nil || c.c == nil {
		return nil
	}
	err := c.c.Close()
	c.c = nil
	return err
}

// SetDeadline — таймаут на одну операцию.
func (c *Conn) SetDeadline(t time.Time) error { return c.c.SetDeadline(t) }

// Send отправляет одно предложение (cmd + аргументы), завершая пустым словом.
func (c *Conn) Send(words ...string) error {
	for _, w := range words {
		if err := writeWord(c.c, w); err != nil {
			return err
		}
	}
	return writeLength(c.c, 0)
}

// Recv читает одно предложение (до пустого слова).
func (c *Conn) Recv() (*Sentence, error) {
	first, err := readWord(c.br)
	if err != nil {
		return nil, err
	}
	if first == "" {
		// Странный кейс — пустое предложение. Возвращаем как есть.
		return &Sentence{Words: map[string]string{}}, nil
	}
	s := &Sentence{Reply: first, Words: map[string]string{}}
	for {
		w, err := readWord(c.br)
		if err != nil {
			return nil, err
		}
		if w == "" {
			return s, nil
		}
		// Слова вида "=key=value"; первое '=' разделитель.
		if len(w) > 1 && w[0] == '=' {
			rest := w[1:]
			eq := indexByte(rest, '=')
			if eq < 0 {
				s.Words[rest] = ""
			} else {
				s.Words[rest[:eq]] = rest[eq+1:]
			}
			continue
		}
		// Прочее (.tag=..., !.X — пока не используем) — пропускаем.
	}
}

// login делает modern-login (RouterOS 6.43+): один запрос /login с name+password.
// Старый challenge-response (до 6.43) намеренно не поддерживаем.
func (c *Conn) login(ctx context.Context, user, password string) error {
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
		defer c.SetDeadline(time.Time{})
	} else {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		defer c.SetDeadline(time.Time{})
	}
	if err := c.Send("/login", "=name="+user, "=password="+password); err != nil {
		return fmt.Errorf("login send: %w", err)
	}
	for {
		s, err := c.Recv()
		if err != nil {
			return fmt.Errorf("login recv: %w", err)
		}
		switch s.Reply {
		case "!done":
			return nil
		case "!trap":
			return &Trap{Category: s.Words["category"], Message: s.Words["message"]}
		case "!fatal":
			return errors.New("login fatal: " + s.Words["message"])
		}
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// EOF helper — для тестов и rec-вызовов в Client.
var ErrFatal = errors.New("binapi: fatal")

var _ = io.EOF
