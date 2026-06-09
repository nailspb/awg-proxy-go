// Package config загружает конфигурацию прокси из JSON-файла.
// Файл монтируется в контейнер в режиме rw и правится через веб-интерфейс.
package config

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"
)

// Режимы работы.
const (
	ModeServer = "server"
	ModeClient = "client"
)

// Префикс comment'а peer'а на роутере, по которому в client-режиме
// определяется апстрим — какой peer проксируем.
const PeerMarker = "[awgproxy]"

// Умолчания.
const (
	defMode      = ModeServer
	defListen    = ":51820"
	defWebListen = ":8088"
	defUser      = "admin"
	defJc        = 4
	defJmin      = 40
	defJmax      = 70
	defTTL       = 180
	defPoll      = 30
	defLog       = "info"
	defAPIPort   = 443
)

// Config — рабочая конфигурация сервиса (внутреннее представление).
type Config struct {
	Mode      string // server | client
	WebListen string
	LogLevel  slog.Level

	Listen string // UDP-адрес прокси

	// server-режим: куда форвардить деобфусцированный WG.
	Remote string

	// server-режим: публичный host:port, по которому клиенты приходят на роутер.
	// Внешний порт из него используется как dst-port в авто-правиле dst-nat.
	PublicEndpoint string

	// client-режим: куда роутер заворачивает свой WG (наш listen внутри контейнера).
	ContainerAddr string // адрес контейнера, в который роутер шлёт через dst-nat (для NAT-правила).
	Divert        bool   // авто-управлять NAT-правилом на роутере.
	Masquerade    bool   // server-режим: авто-правило srcnat masquerade для сети WG-интерфейса.

	Jc, Jmin, Jmax int
	S1, S2         int
	H1, H2, H3, H4 uint32

	SessionTTL   time.Duration
	PollInterval time.Duration

	Router RouterConn
}

// RouterConn — рабочие параметры подключения к роутеру (REST API).
type RouterConn struct {
	Address  string
	APIPort  int
	APITLS   bool
	User     string
	Password string
	WGIface  string
}

// Obfuscation — параметры обфускации AmneziaWG.
// omitzero НЕ ставим: нужно отличать «не задано» (отсутствующий блок в файле) от
// «явный 0» (например, S1=0 — валидное значение, означающее «без префикса»).
type Obfuscation struct {
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	H1   uint32 `json:"h1"`
	H2   uint32 `json:"h2"`
	H3   uint32 `json:"h3"`
	H4   uint32 `json:"h4"`
}

// RouterSettings — доступ к роутеру через REST API.
type RouterSettings struct {
	Address  string `json:"address"`
	APIPort  int    `json:"api_port,omitzero"`
	APITLS   bool   `json:"api_tls"`
	User     string `json:"user,omitzero"`
	Password string `json:"password,omitzero"`
	WGIface  string `json:"wg_iface"`
}

// ServerSettings — профиль server-режима (1:N).
type ServerSettings struct {
	Listen          string         `json:"listen,omitzero"`
	RemoteAddr      string         `json:"remote_addr"`
	RemotePort      int            `json:"remote_port,omitzero"`
	PublicEndpoint  string         `json:"public_endpoint,omitzero"`
	ClientDNS       string         `json:"client_dns,omitzero"`
	ContainerAddr   string         `json:"container_addr,omitzero"` // адрес контейнера для dst-nat правила (когда divert=on)
	Divert          bool           `json:"divert"`                  // авто-управлять dst-nat на роутере: входящий UDP на listen → контейнер
	Masquerade      bool           `json:"masquerade"`              // авто-правило srcnat masquerade для сети WG-интерфейса
	SessionTTLSec   int            `json:"session_ttl_sec,omitzero"`
	PollIntervalSec int            `json:"poll_interval_sec,omitzero"`
	Obfuscation     Obfuscation    `json:"obfuscation"`
	Router          RouterSettings `json:"router"`
}

// ClientSettings — профиль client-режима (1:1).
// remote_addr/remote_port/server_pubkey не нужны: апстрим берётся из peer'а
// на роутере, помеченного префиксом [awgproxy] в comment.
type ClientSettings struct {
	Listen          string         `json:"listen,omitzero"`
	ContainerAddr   string         `json:"container_addr,omitzero"`
	SessionTTLSec   int            `json:"session_ttl_sec,omitzero"`
	PollIntervalSec int            `json:"poll_interval_sec,omitzero"`
	Obfuscation     Obfuscation    `json:"obfuscation"`
	Router          RouterSettings `json:"router"`
	Divert          bool           `json:"divert"` // авто-управлять NAT-правилом
}

// Settings — формат JSON-файла (читается/пишется веб-интерфейсом).
type Settings struct {
	Mode      string         `json:"mode,omitzero"`
	WebListen string         `json:"web_listen,omitzero"`
	LogLevel  string         `json:"log_level,omitzero"`
	Server    ServerSettings `json:"server"`
	Client    ClientSettings `json:"client"`
}

// defaultObfuscation подставляет дефолты ТОЛЬКО когда блок полностью пуст
// (все поля = 0, т.е. файла нет / секция отсутствует). Если задано хоть одно
// значение — считаем блок осмысленным и ничего не трогаем, иначе нельзя
// сохранить явный 0 (cmp.Or 0,deflt → deflt).
func defaultObfuscation(o Obfuscation) Obfuscation {
	if o.Jc != 0 || o.Jmin != 0 || o.Jmax != 0 || o.S1 != 0 || o.S2 != 0 ||
		o.H1 != 0 || o.H2 != 0 || o.H3 != 0 || o.H4 != 0 {
		return o
	}
	return Obfuscation{
		Jc: defJc, Jmin: defJmin, Jmax: defJmax,
		H1: 1, H2: 2, H3: 3, H4: 4,
	}
}

func defaultRouter(r RouterSettings) RouterSettings {
	r.User = cmp.Or(r.User, defUser)
	r.APIPort = cmp.Or(r.APIPort, defAPIPort)
	return r
}

// withDefaults возвращает Settings с подставленными умолчаниями.
func (s Settings) withDefaults() Settings {
	s.Mode = cmp.Or(s.Mode, defMode)
	s.WebListen = cmp.Or(s.WebListen, defWebListen)
	s.LogLevel = cmp.Or(s.LogLevel, defLog)

	sv := &s.Server
	sv.Listen = cmp.Or(sv.Listen, defListen)
	sv.SessionTTLSec = cmp.Or(sv.SessionTTLSec, defTTL)
	sv.PollIntervalSec = cmp.Or(sv.PollIntervalSec, defPoll)
	sv.Obfuscation = defaultObfuscation(sv.Obfuscation)
	sv.Router = defaultRouter(sv.Router)

	cl := &s.Client
	cl.Listen = cmp.Or(cl.Listen, defListen)
	cl.SessionTTLSec = cmp.Or(cl.SessionTTLSec, defTTL)
	cl.PollIntervalSec = cmp.Or(cl.PollIntervalSec, defPoll)
	cl.Obfuscation = defaultObfuscation(cl.Obfuscation)
	cl.Router = defaultRouter(cl.Router)
	return s
}

// ToConfig переводит Settings в рабочую конфигурацию (с умолчаниями).
func (s Settings) ToConfig() *Config {
	s = s.withDefaults()
	c := &Config{
		Mode:      s.Mode,
		WebListen: s.WebListen,
		LogLevel:  parseLevel(s.LogLevel),
	}
	switch s.Mode {
	case ModeClient:
		fillClient(c, s.Client)
	default:
		fillServer(c, s.Server)
	}
	return c
}

func fillServer(c *Config, sv ServerSettings) {
	o := sv.Obfuscation
	var remote string
	if sv.RemoteAddr != "" && sv.RemotePort != 0 {
		remote = net.JoinHostPort(sv.RemoteAddr, strconv.Itoa(sv.RemotePort))
	}
	c.Listen = sv.Listen
	c.Remote = remote
	c.PublicEndpoint = sv.PublicEndpoint
	c.ContainerAddr = sv.ContainerAddr
	c.Divert = sv.Divert
	c.Masquerade = sv.Masquerade
	c.Jc, c.Jmin, c.Jmax = o.Jc, o.Jmin, o.Jmax
	c.S1, c.S2 = o.S1, o.S2
	c.H1, c.H2, c.H3, c.H4 = o.H1, o.H2, o.H3, o.H4
	c.SessionTTL = time.Duration(sv.SessionTTLSec) * time.Second
	c.PollInterval = time.Duration(sv.PollIntervalSec) * time.Second
	c.Router = routerConn(sv.Router)
}

func fillClient(c *Config, cl ClientSettings) {
	o := cl.Obfuscation
	c.Listen = cl.Listen
	c.ContainerAddr = cl.ContainerAddr
	c.Divert = cl.Divert
	c.Jc, c.Jmin, c.Jmax = o.Jc, o.Jmin, o.Jmax
	c.S1, c.S2 = o.S1, o.S2
	c.H1, c.H2, c.H3, c.H4 = o.H1, o.H2, o.H3, o.H4
	c.SessionTTL = time.Duration(cl.SessionTTLSec) * time.Second
	c.PollInterval = time.Duration(cl.PollIntervalSec) * time.Second
	c.Router = routerConn(cl.Router)
}

func routerConn(r RouterSettings) RouterConn {
	return RouterConn{
		Address:  r.Address,
		APIPort:  r.APIPort,
		APITLS:   r.APITLS,
		User:     r.User,
		Password: r.Password,
		WGIface:  r.WGIface,
	}
}

// validateRouter — проверяет только поля доступа к роутеру (адрес/пароль).
// wg_iface сюда не входит: он редактируется в Settings (выпадашка, заполняется
// списком интерфейсов с роутера) и должен валидироваться вместе с сервисной
// секцией, иначе нельзя сохранить Router до настройки Settings.
func (c *Config) validateRouter() error {
	r := c.Router
	switch {
	case r.Address == "":
		return fmt.Errorf("router.address is required")
	case r.Password == "":
		return fmt.Errorf("router.password is required")
	}
	return nil
}

// validateService — проверяет сервисные/сетевые/обфускационные поля и wg_iface
// (он живёт в UI Settings, см. validateRouter).
func (c *Config) validateService() error {
	if c.Router.WGIface == "" {
		return fmt.Errorf("router.wg_iface is required")
	}
	switch c.Mode {
	case ModeServer:
		if c.Remote == "" {
			return fmt.Errorf("server.remote_addr/port are required")
		}
		if c.Divert && c.ContainerAddr == "" {
			return fmt.Errorf("server.container_addr is required when divert is on")
		}
	case ModeClient:
		if c.ContainerAddr == "" {
			return fmt.Errorf("client.container_addr is required")
		}
	default:
		return fmt.Errorf("unsupported mode %q", c.Mode)
	}
	if c.Jmin > c.Jmax {
		return fmt.Errorf("jmin(%d) > jmax(%d)", c.Jmin, c.Jmax)
	}
	return nil
}

func (c *Config) validate() error {
	if err := c.validateRouter(); err != nil {
		return err
	}
	return c.validateService()
}

func readRaw(path string) (Settings, bool, error) {
	var s Settings
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, false, nil
	case err != nil:
		return s, false, fmt.Errorf("read config %s: %w", path, err)
	}
	// Пустой файл (например, dst mount поверх старого, или ручной truncate) —
	// трактуем как «нет конфига», иначе UI и поллер падают на parse error.
	if len(bytes.TrimSpace(data)) == 0 {
		return s, false, nil
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, false, fmt.Errorf("parse config %s: %w", path, err)
	}
	return s, true, nil
}

// Load читает конфигурацию из файла. Отсутствие файла — не ошибка (дефолты).
// Валидация НЕ запускается: неполная конфигурация (например, заполнен только
// доступ к роутеру, но ещё не выбран wg_iface) не должна валить весь стек —
// supervise/компоненты сами проверят свои предусловия и залогируют, чего им
// не хватает. Для строгой проверки используется Validate.
func Load(path string) (*Config, error) {
	s, _, err := readRaw(path)
	if err != nil {
		return nil, err
	}
	return s.ToConfig(), nil
}

// Validate выполняет полную проверку (доступ к роутеру + сервисная часть).
// Используется на сохранении и для диагностического лога на старте.
func (c *Config) Validate() error { return c.validate() }

// Read возвращает текущие настройки с умолчаниями (для веб-интерфейса).
func Read(path string) (Settings, error) {
	s, _, err := readRaw(path)
	if err != nil {
		return Settings{}, err
	}
	return s.withDefaults(), nil
}

// Секции для частичной валидации при сохранении.
const (
	SectionAll     = ""
	SectionRouter  = "router"
	SectionService = "service"
)

// Write валидирует выбранную секцию и сохраняет настройки в файл целиком.
// section=="" — полная валидация (для старых клиентов/CLI).
// section=="router" — только router-поля (адрес/пароль/iface).
// section=="service" — только сервисные/сетевые/обфускационные поля.
// Так разделы UI сохраняются независимо: ошибка в одном не блокирует другой.
func Write(path string, s Settings, section string) error {
	c := s.ToConfig()
	var err error
	switch section {
	case SectionRouter:
		err = c.validateRouter()
	case SectionService:
		err = c.validateService()
	default:
		err = c.validate()
	}
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.withDefaults(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// ActiveRouter возвращает блок router из активной (по mode) секции.
func (s Settings) ActiveRouter() RouterSettings {
	if s.Mode == ModeClient {
		return s.Client.Router
	}
	return s.Server.Router
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "none":
		return slog.LevelError + 4
	default:
		return slog.LevelInfo
	}
}
