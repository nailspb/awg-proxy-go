package router

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// httpClient — единый клиент с keep-alive пулом: иначе на каждый /rest вызов
// открывался бы свой TCP/TLS-коннект, и роутер показывал бы лавину сессий
// пользователя на каждом тике поллера.
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // доверенная сеть роутера
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	},
}

func (c Config) apiURL(path string) string {
	scheme := "http"
	if c.APITLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, c.Address, c.APIPort, path)
}

// apiReq выполняет REST-запрос к RouterOS и возвращает тело ответа.
// body (если не nil) сериализуется в JSON.
func (c Config) apiReq(ctx context.Context, method, path string, body any) ([]byte, error) {
	if c.Password == "" {
		return nil, fmt.Errorf("password required for API")
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiURL(path), rdr)
	if err != nil {
		return nil, err
	}
	// Путь отправляем как есть: RouterOS-идентификатор пира вида "*5" иначе
	// был бы экранирован в "%2A5", и роутер вернул бы invalid resource identifier.
	req.URL.Opaque = path
	req.SetBasicAuth(c.User, c.Password)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, data)
	}
	return data, nil
}

// fetchAPI читает состояние через REST API RouterOS (/rest/...).
func (p *Poller) fetchAPI(ctx context.Context) (*Snapshot, error) {
	data, err := p.cfg.apiReq(ctx, http.MethodGet, "/rest/interface/wireguard", nil)
	if err != nil {
		return nil, fmt.Errorf("api interface: %w", err)
	}
	var ifaces []struct {
		Name       string `json:"name"`
		PublicKey  string `json:"public-key"`
		PrivateKey string `json:"private-key"`
		ListenPort string `json:"listen-port"`
	}
	if err := json.Unmarshal(data, &ifaces); err != nil {
		return nil, fmt.Errorf("api interface decode: %w", err)
	}
	var serverPub, serverPriv [32]byte
	var listenPort int
	found := false
	for _, it := range ifaces {
		if it.Name != p.cfg.Iface {
			continue
		}
		if serverPub, err = parsePubKey(it.PublicKey); err != nil {
			return nil, fmt.Errorf("api interface key: %w", err)
		}
		if it.PrivateKey != "" {
			serverPriv, _ = parsePubKey(it.PrivateKey)
		}
		if it.ListenPort != "" {
			listenPort, _ = strconv.Atoi(it.ListenPort)
		}
		found = true
		break
	}
	if !found {
		return nil, fmt.Errorf("api: interface %q not found", p.cfg.Iface)
	}

	peers, err := p.cfg.apiReq(ctx, http.MethodGet, "/rest/interface/wireguard/peers", nil)
	if err != nil {
		return nil, fmt.Errorf("api peers: %w", err)
	}
	var ros []rosPeer
	if err := json.Unmarshal(peers, &ros); err != nil {
		return nil, fmt.Errorf("api peers decode: %w", err)
	}

	snap := &Snapshot{
		ServerPub:    serverPub,
		ServerPriv:   serverPriv,
		WGListenPort: listenPort,
	}
	var marked []markedPeer
	for _, r := range ros {
		if r.Interface != p.cfg.Iface {
			continue
		}
		if p.cfg.Mode == ModeClient {
			port, _ := strconv.Atoi(r.EndpointPort)
			marked = append(marked, markedPeer{
				id:           r.ID,
				comment:      r.Comment,
				publicKey:    r.PublicKey,
				psk:          r.PresharedKey,
				endpointAddr: r.EndpointAddress,
				endpointPort: port,
				disabled:     r.Disabled == "true",
			})
			continue
		}
		k, err := parsePubKey(r.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("api peer key: %w", err)
		}
		snap.ClientPubs = append(snap.ClientPubs, k)
	}
	if p.cfg.Mode == ModeClient {
		snap.Upstream = p.pickUpstream(marked)
	}
	return snap, nil
}
