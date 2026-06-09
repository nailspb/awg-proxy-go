package router

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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

// rosPeer — пир в представлении REST API RouterOS (все значения — строки).
type rosPeer struct {
	ID                     string `json:".id"`
	Interface              string `json:"interface"`
	Disabled               string `json:"disabled"`
	Name                   string `json:"name"`
	Comment                string `json:"comment"`
	PublicKey              string `json:"public-key"`
	PrivateKey             string `json:"private-key"`
	PresharedKey           string `json:"preshared-key"`
	AllowedAddress         string `json:"allowed-address"`
	EndpointAddress        string `json:"endpoint-address"`
	EndpointPort           string `json:"endpoint-port"`
	PersistentKeepalive    string `json:"persistent-keepalive"`
	CurrentEndpointAddress string `json:"current-endpoint-address"`
	CurrentEndpointPort    string `json:"current-endpoint-port"`
	Rx                     string `json:"rx"`
	Tx                     string `json:"tx"`
	LastHandshake          string `json:"last-handshake"`
}

func (r rosPeer) toPeer() Peer {
	ce := r.CurrentEndpointAddress
	if ce != "" && r.CurrentEndpointPort != "" {
		ce = ce + ":" + r.CurrentEndpointPort
	}
	return Peer{
		ID:                  r.ID,
		Interface:           r.Interface,
		Disabled:            r.Disabled == "true",
		Name:                r.Name,
		Comment:             r.Comment,
		PublicKey:           r.PublicKey,
		PrivateKey:          r.PrivateKey,
		PresharedKey:        r.PresharedKey,
		AllowedAddress:      r.AllowedAddress,
		EndpointAddress:     r.EndpointAddress,
		EndpointPort:        r.EndpointPort,
		PersistentKeepalive: r.PersistentKeepalive,
		CurrentEndpoint:     ce,
		Rx:                  r.Rx,
		Tx:                  r.Tx,
		LastHandshake:       r.LastHandshake,
	}
}

// Client управляет пирами на роутере через REST API.
type Client struct {
	cfg Config
	log *slog.Logger
}

func NewClient(cfg Config, log *slog.Logger) *Client { return &Client{cfg: cfg, log: log} }

// Verify проверяет, что креды подходят к роутеру (для авторизации веб-входа):
// успешный REST-запрос = валидные логин/пароль.
func (c *Client) Verify(ctx context.Context) error {
	_, err := c.cfg.apiReq(ctx, http.MethodGet, "/rest/system/identity", nil)
	return err
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
	data, err := c.cfg.apiReq(ctx, http.MethodGet, "/rest/interface/wireguard", nil)
	if err != nil {
		return nil, err
	}
	var ifaces []struct {
		Name       string `json:"name"`
		PublicKey  string `json:"public-key"`
		ListenPort string `json:"listen-port"`
	}
	if err := json.Unmarshal(data, &ifaces); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	addrs := c.ifaceAddrs(ctx)
	out := make([]Interface, 0, len(ifaces))
	for _, it := range ifaces {
		out = append(out, Interface{
			Name:       it.Name,
			PublicKey:  it.PublicKey,
			ListenPort: it.ListenPort,
			Address:    addrs[it.Name],
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
	data, err := c.cfg.apiReq(ctx, http.MethodGet, "/rest/ip/address", nil)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Interface string `json:"interface"`
		Address   string `json:"address"`
		Disabled  string `json:"disabled"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, fmt.Errorf("decode addresses: %w", err)
	}
	out := make([]Address, 0, len(rows))
	for _, r := range rows {
		if r.Disabled == "true" {
			continue
		}
		out = append(out, Address{Interface: r.Interface, Address: r.Address})
	}
	return out, nil
}

// ifaceAddrs строит iface→первый адрес из /ip/address. Ошибки не возвращает —
// при недоступности отдаём пустую карту (адрес опциональный).
func (c *Client) ifaceAddrs(ctx context.Context) map[string]string {
	data, err := c.cfg.apiReq(ctx, http.MethodGet, "/rest/ip/address", nil)
	if err != nil {
		c.log.Warn("list ip addresses failed", "err", err)
		return nil
	}
	var rows []struct {
		Interface string `json:"interface"`
		Address   string `json:"address"`
		Disabled  string `json:"disabled"`
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		c.log.Warn("decode ip addresses failed", "err", err)
		return nil
	}
	m := make(map[string]string, len(rows))
	for _, r := range rows {
		if r.Disabled == "true" {
			continue
		}
		if _, ok := m[r.Interface]; !ok {
			m[r.Interface] = r.Address
		}
	}
	return m
}

// ListPeers возвращает пиров выбранного интерфейса.
func (c *Client) ListPeers(ctx context.Context) ([]Peer, error) {
	data, err := c.cfg.apiReq(ctx, http.MethodGet, "/rest/interface/wireguard/peers", nil)
	if err != nil {
		return nil, err
	}
	var ros []rosPeer
	if err := json.Unmarshal(data, &ros); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	peers := make([]Peer, 0, len(ros))
	for _, r := range ros {
		if r.Interface == c.cfg.Iface {
			peers = append(peers, r.toPeer())
		}
	}
	return peers, nil
}

// AddPeer создаёт нового пира.
func (c *Client) AddPeer(ctx context.Context, p Peer) error {
	return c.write(ctx, http.MethodPut, "/rest/interface/wireguard/peers", c.body(p, true))
}

// UpdatePeer изменяет существующего пира по id.
func (c *Client) UpdatePeer(ctx context.Context, id string, p Peer) error {
	if id == "" {
		return fmt.Errorf("peer id required")
	}
	return c.write(ctx, http.MethodPatch, "/rest/interface/wireguard/peers/"+id, c.body(p, false))
}

// SetDisabled включает/выключает пира.
func (c *Client) SetDisabled(ctx context.Context, id string, disabled bool) error {
	if id == "" {
		return fmt.Errorf("peer id required")
	}
	return c.write(ctx, http.MethodPatch, "/rest/interface/wireguard/peers/"+id,
		map[string]string{"disabled": boolStr(disabled)})
}

// DeletePeer удаляет пира по id.
func (c *Client) DeletePeer(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("peer id required")
	}
	_, err := c.cfg.apiReq(ctx, http.MethodDelete, "/rest/interface/wireguard/peers/"+id, nil)
	return err
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
	return m
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// numericField — поле, которое RouterOS отвергает пустым ("an integer required").
// Такие пропускаем при PATCH, чтобы не сломать запрос; текстовые поля наоборот
// шлём даже пустыми — иначе их не очистить (привет, [awgproxy]-маркер).
func numericField(k string) bool {
	return k == "endpoint-port" || k == "persistent-keepalive"
}

func (c *Client) write(ctx context.Context, method, path string, body map[string]string) error {
	var b any
	if body != nil {
		m := make(map[string]string, len(body))
		for k, v := range body {
			if v == "" && numericField(k) {
				continue
			}
			m[k] = v
		}
		b = m
	}
	_, err := c.cfg.apiReq(ctx, method, path, b)
	return err
}
