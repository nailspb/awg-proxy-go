package binapi

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Dialer — параметры подключения к API.
// Mu сериализует запросы по одному коннекту (RouterOS API синхронный).
type Dialer struct {
	Address  string // host
	Port     int    // 8728 / 8729
	UseTLS   bool
	User     string
	Password string

	mu   sync.Mutex
	conn *Conn
}

// addr возвращает "host:port".
func (d *Dialer) addr() string {
	return fmt.Sprintf("%s:%d", d.Address, d.Port)
}

// ensure возвращает живой коннект, переподключаясь при необходимости.
func (d *Dialer) ensure(ctx context.Context) (*Conn, error) {
	if d.conn != nil {
		return d.conn, nil
	}
	c, err := Dial(ctx, d.addr(), d.UseTLS, d.User, d.Password)
	if err != nil {
		return nil, err
	}
	d.conn = c
	return c, nil
}

// drop закрывает коннект (вызывается при I/O-ошибке — следующий call переоткроет).
func (d *Dialer) drop() {
	if d.conn != nil {
		_ = d.conn.Close()
		d.conn = nil
	}
}

// Close закрывает соединение.
func (d *Dialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drop()
	return nil
}

// Call отправляет команду cmd с аргументами и читает ответ до !done/!trap.
// Возвращает все !re-предложения (для add — обычно одно с =ret=<id>).
// Внутренний мьютекс сериализует запросы; вызывающий код может звать конкурентно.
func (d *Dialer) Call(ctx context.Context, cmd string, words ...string) ([]map[string]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.call(ctx, cmd, words)
	if err != nil {
		d.drop()
		// Одна авто-реконнект-попытка: типичная причина — idle-timeout TCP.
		res, err = d.call(ctx, cmd, words)
		if err != nil {
			d.drop()
			return nil, err
		}
	}
	return res, nil
}

func (d *Dialer) call(ctx context.Context, cmd string, args []string) ([]map[string]string, error) {
	c, err := d.ensure(ctx)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetDeadline(deadline)
	defer c.SetDeadline(time.Time{})

	words := append([]string{cmd}, args...)
	if err := c.Send(words...); err != nil {
		return nil, fmt.Errorf("send %s: %w", cmd, err)
	}
	var rows []map[string]string
	for {
		s, err := c.Recv()
		if err != nil {
			return nil, fmt.Errorf("recv %s: %w", cmd, err)
		}
		switch s.Reply {
		case "!re":
			rows = append(rows, s.Words)
		case "!done":
			// Иногда у add/.id результат прилетает в самом !done (=ret=*1).
			if len(s.Words) > 0 {
				rows = append(rows, s.Words)
			}
			return rows, nil
		case "!trap":
			return nil, &Trap{Category: s.Words["category"], Message: s.Words["message"]}
		case "!fatal":
			return nil, fmt.Errorf("fatal: %s", s.Words["message"])
		}
	}
}

// Print выполняет команду <path>/print (опц. словами вида ".proplist=a,b" или "?name=foo").
// Возвращает список строк (каждая — map значений по полю).
func (d *Dialer) Print(ctx context.Context, path string, args ...string) ([]map[string]string, error) {
	return d.Call(ctx, path+"/print", args...)
}

// Add выполняет <path>/add с аргументами =k=v, возвращает id новой записи.
func (d *Dialer) Add(ctx context.Context, path string, kv map[string]string) (string, error) {
	rows, err := d.Call(ctx, path+"/add", kvWords(kv)...)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("add %s: no reply", path)
	}
	return rows[0]["ret"], nil
}

// Set применяет =k=v к записи с заданным id.
func (d *Dialer) Set(ctx context.Context, path, id string, kv map[string]string) error {
	args := append([]string{"=.id=" + id}, kvWords(kv)...)
	_, err := d.Call(ctx, path+"/set", args...)
	return err
}

// Remove удаляет запись по id.
func (d *Dialer) Remove(ctx context.Context, path, id string) error {
	_, err := d.Call(ctx, path+"/remove", "=.id="+id)
	return err
}

// Verify одноразово открывает соединение, логинится и закрывает его.
// Используется на /api/login: попытки ввода неверных кредов не должны оставлять
// «зависший» Dialer в кеше и плодить TCP-сессии на роутере.
func Verify(ctx context.Context, addr string, useTLS bool, user, password string) error {
	c, err := Dial(ctx, addr, useTLS, user, password)
	if err != nil {
		return err
	}
	return c.Close()
}

// kvWords превращает map в отсортированный набор "=k=v". Стабильный порядок —
// тестируемость и предсказуемость в логах ROS.
func kvWords(kv map[string]string) []string {
	if len(kv) == 0 {
		return nil
	}
	out := make([]string, 0, len(kv))
	for k, v := range kv {
		out = append(out, "="+k+"="+v)
	}
	return out
}
