package router

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/glebov/awg-proxy-go/internal/router/binapi"
)

// Peer — пир WireGuard в удобном для фронтенда виде.
type Peer struct {
	ID                  string `json:"id,omitempty"` // внутренний id RouterOS (напр. *5)
	Interface           string `json:"interface,omitempty"`
	Disabled            bool   `json:"disabled"`
	Name                string `json:"name"`
	Comment             string `json:"comment"`
	PublicKey           string `json:"public_key"`
	PrivateKey          string `json:"private_key"` // храним в пире, чтобы перевыпускать QR
	PresharedKey        string `json:"preshared_key"`
	AllowedAddress      string `json:"allowed_address"`
	EndpointAddress     string `json:"endpoint_address"`
	EndpointPort        string `json:"endpoint_port"`
	PersistentKeepalive string `json:"persistent_keepalive"`
	// Рантайм (только чтение, заполняется при чтении через API).
	CurrentEndpoint string `json:"current_endpoint,omitempty"`
	Rx              string `json:"rx,omitempty"`
	Tx              string `json:"tx,omitempty"`
	LastHandshake   string `json:"last_handshake,omitempty"`
}

func peerFromMap(m map[string]string) Peer {
	ce := m["current-endpoint-address"]
	if ce != "" && m["current-endpoint-port"] != "" {
		ce = ce + ":" + m["current-endpoint-port"]
	}
	return Peer{
		ID:                  m[".id"],
		Interface:           m["interface"],
		Disabled:            m["disabled"] == "true",
		Name:                m["name"],
		Comment:             m["comment"],
		PublicKey:           m["public-key"],
		PrivateKey:          m["private-key"],
		PresharedKey:        m["preshared-key"],
		AllowedAddress:      m["allowed-address"],
		EndpointAddress:     m["endpoint-address"],
		EndpointPort:        m["endpoint-port"],
		PersistentKeepalive: m["persistent-keepalive"],
		CurrentEndpoint:     ce,
		Rx:                  m["rx"],
		Tx:                  m["tx"],
		LastHandshake:       m["last-handshake"],
	}
}

// Client управляет пирами на роутере через bin-API.
type Client struct {
	cfg Config
	log *slog.Logger
}

func NewClient(cfg Config, log *slog.Logger) *Client { return &Client{cfg: cfg, log: log} }

// Verify проверяет, что креды подходят к роутеру (для авторизации веб-входа).
// Делает одноразовый Dial+Login+Close, чтобы попытки ввода неверного пароля
// не оседали персистентным коннектом в кеше Dialer.
func (c *Client) Verify(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", c.cfg.Address, c.cfg.APIPort)
	return binapi.Verify(ctx, addr, c.cfg.APITLS, c.cfg.User, c.cfg.Password)
}

// ServerKey возвращает публичный ключ WG-интерфейса роутера (base64).
func (c *Client) ServerKey(ctx context.Context) (string, error) {
	ifs, err := c.ListInterfaces(ctx)
	if err != nil {
		return "", err
	}
	for _, it := range ifs {
		if it.Name == c.cfg.Iface {
			return it.PublicKey, nil
		}
	}
	return "", fmt.Errorf("interface %q not found", c.cfg.Iface)
}

// Interface — WG-интерфейс роутера в удобном для UI виде.
type Interface struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	ListenPort string `json:"listen_port,omitempty"`
	Address    string `json:"address,omitempty"` // CIDR первого /ip/address на интерфейсе, например "10.0.0.1/24"
}

// ListInterfaces возвращает все WG-интерфейсы роутера (для выбора в UI).
// Также подмешивает /ip/address (best-effort: ошибка чтения адресов не валит весь список).
func (c *Client) ListInterfaces(ctx context.Context) ([]Interface, error) {
	rows, err := c.cfg.callPrint(ctx, "/interface/wireguard")
	if err != nil {
		return nil, err
	}
	addrs := c.ifaceAddrs(ctx)
	out := make([]Interface, 0, len(rows))
	for _, it := range rows {
		out = append(out, Interface{
			Name:       it["name"],
			PublicKey:  it["public-key"],
			ListenPort: it["listen-port"],
			Address:    addrs[it["name"]],
		})
	}
	return out, nil
}

// Address — IP-адрес на интерфейсе роутера (для подсказок в UI).
type Address struct {
	Interface string `json:"interface"`
	Address   string `json:"address"` // "x.x.x.x/N"
}

// ListAddresses возвращает все активные адреса /ip/address с роутера.
// Disabled-записи отфильтрованы.
func (c *Client) ListAddresses(ctx context.Context) ([]Address, error) {
	rows, err := c.cfg.callPrint(ctx, "/ip/address")
	if err != nil {
		return nil, err
	}
	out := make([]Address, 0, len(rows))
	for _, r := range rows {
		if r["disabled"] == "true" {
			continue
		}
		out = append(out, Address{Interface: r["interface"], Address: r["address"]})
	}
	return out, nil
}

// ifaceAddrs строит iface→первый адрес из /ip/address. Ошибки не возвращает —
// при недоступности отдаём пустую карту (адрес опциональный).
func (c *Client) ifaceAddrs(ctx context.Context) map[string]string {
	rows, err := c.cfg.callPrint(ctx, "/ip/address")
	if err != nil {
		c.log.Warn("list ip addresses failed", "err", err)
		return nil
	}
	m := make(map[string]string, len(rows))
	for _, r := range rows {
		if r["disabled"] == "true" {
			continue
		}
		iface := r["interface"]
		if _, ok := m[iface]; !ok {
			m[iface] = r["address"]
		}
	}
	return m
}

// ListPeers возвращает пиров выбранного интерфейса.
func (c *Client) ListPeers(ctx context.Context) ([]Peer, error) {
	rows, err := c.cfg.callPrint(ctx, "/interface/wireguard/peers")
	if err != nil {
		return nil, err
	}
	peers := make([]Peer, 0, len(rows))
	for _, r := range rows {
		if r["interface"] == c.cfg.Iface {
			peers = append(peers, peerFromMap(r))
		}
	}
	return peers, nil
}

// AddPeer создаёт нового пира.
func (c *Client) AddPeer(ctx context.Context, p Peer) error {
	_, err := c.cfg.callAdd(ctx, "/interface/wireguard/peers", c.body(p, true))
	return err
}

// UpdatePeer изменяет существующего пира по id.
func (c *Client) UpdatePeer(ctx context.Context, id string, p Peer) error {
	if id == "" {
		return fmt.Errorf("peer id required")
	}
	return c.cfg.callSet(ctx, "/interface/wireguard/peers", id, c.body(p, false))
}

// SetDisabled включает/выключает пира.
func (c *Client) SetDisabled(ctx context.Context, id string, disabled bool) error {
	if id == "" {
		return fmt.Errorf("peer id required")
	}
	return c.cfg.callSet(ctx, "/interface/wireguard/peers", id,
		map[string]string{"disabled": boolStr(disabled)})
}

// DeletePeer удаляет пира по id.
func (c *Client) DeletePeer(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("peer id required")
	}
	return c.cfg.callRemove(ctx, "/interface/wireguard/peers", id)
}

// body собирает поля пира для записи (формат RouterOS). withIface — добавлять ли
// interface (нужно при создании, не нужно при правке).
func (c *Client) body(p Peer, withIface bool) map[string]string {
	m := map[string]string{
		"name":                 p.Name,
		"allowed-address":      p.AllowedAddress,
		"endpoint-address":     p.EndpointAddress,
		"endpoint-port":        p.EndpointPort,
		"persistent-keepalive": p.PersistentKeepalive,
		"preshared-key":        p.PresharedKey,
		"comment":              p.Comment,
		"disabled":             boolStr(p.Disabled),
	}
	// Приватный ключ храним в самом пире — RouterOS выведет public-key из него.
	// Без приватного задаём публичный ключ напрямую (внешний клиент).
	if p.PrivateKey != "" {
		m["private-key"] = p.PrivateKey
	} else {
		m["public-key"] = p.PublicKey
	}
	if withIface {
		m["interface"] = c.cfg.Iface
	}
	// Пустые числовые поля RouterOS не принимает; в add/set убираем их.
	for k, v := range m {
		if v == "" && numericField(k) {
			delete(m, k)
		}
	}
	return m
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// numericField — поле, которое RouterOS отвергает пустым ("an integer required").
// Такие пропускаем при set/add, чтобы не сломать запрос; текстовые поля наоборот
// шлём даже пустыми — иначе их не очистить (привет, [awgproxy]-маркер).
func numericField(k string) bool {
	return k == "endpoint-port" || k == "persistent-keepalive"
}
