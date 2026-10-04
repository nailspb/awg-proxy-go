package router

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/glebov/awg-proxy-go/internal/router/binapi"
)

// dialerKey идентифицирует коннект по кредам — один Dialer на креды, чтобы
// reload конфига без смены адреса/пароля не плодил новые TCP-сессии и
// записи в Active Users RouterOS.
type dialerKey struct {
	addr string
	port int
	tls  bool
	user string
	pass string
}

var (
	dialerMu sync.Mutex
	dialers  = map[dialerKey]*binapi.Dialer{}
)

// Dialer возвращает (создавая лениво) общий binapi.Dialer для текущих кредов.
// Все REST-эквивалентные операции идут через него; коннект — один на креды.
func (c Config) Dialer() *binapi.Dialer {
	if c.Address == "" {
		return nil
	}
	k := dialerKey{addr: c.Address, port: c.APIPort, tls: c.APITLS, user: c.User, pass: c.Password}
	dialerMu.Lock()
	defer dialerMu.Unlock()
	if d, ok := dialers[k]; ok {
		return d
	}
	d := &binapi.Dialer{
		Address:  c.Address,
		Port:     c.APIPort,
		UseTLS:   c.APITLS,
		User:     c.User,
		Password: c.Password,
	}
	dialers[k] = d
	return d
}

// callPrint — хелпер: <path>/print [+ args].
func (c Config) callPrint(ctx context.Context, path string, args ...string) ([]map[string]string, error) {
	d := c.Dialer()
	if d == nil {
		return nil, fmt.Errorf("no router credentials")
	}
	return d.Print(ctx, path, args...)
}

// callAdd — хелпер: <path>/add, возвращает .id новой записи.
func (c Config) callAdd(ctx context.Context, path string, kv map[string]string) (string, error) {
	d := c.Dialer()
	if d == nil {
		return "", fmt.Errorf("no router credentials")
	}
	return d.Add(ctx, path, kv)
}

// callSet — хелпер: <path>/set с .id=id.
func (c Config) callSet(ctx context.Context, path, id string, kv map[string]string) error {
	d := c.Dialer()
	if d == nil {
		return fmt.Errorf("no router credentials")
	}
	return d.Set(ctx, path, id, kv)
}

// callRemove — хелпер: <path>/remove с .id=id.
func (c Config) callRemove(ctx context.Context, path, id string) error {
	d := c.Dialer()
	if d == nil {
		return fmt.Errorf("no router credentials")
	}
	return d.Remove(ctx, path, id)
}

// fetchAPI читает состояние через binapi RouterOS.
func (p *Poller) fetchAPI(ctx context.Context) (*Snapshot, error) {
	ifaces, err := p.cfg.callPrint(ctx, "/interface/wireguard")
	if err != nil {
		return nil, fmt.Errorf("api interface: %w", err)
	}
	var serverPub, serverPriv [32]byte
	var listenPort int
	found := false
	for _, it := range ifaces {
		if it["name"] != p.cfg.Iface {
			continue
		}
		if serverPub, err = parsePubKey(it["public-key"]); err != nil {
			return nil, fmt.Errorf("api interface key: %w", err)
		}
		if pk := it["private-key"]; pk != "" {
			serverPriv, _ = parsePubKey(pk)
		}
		if lp := it["listen-port"]; lp != "" {
			listenPort, _ = strconv.Atoi(lp)
		}
		found = true
		break
	}
	if !found {
		return nil, fmt.Errorf("api: interface %q not found", p.cfg.Iface)
	}

	peers, err := p.cfg.callPrint(ctx, "/interface/wireguard/peers")
	if err != nil {
		return nil, fmt.Errorf("api peers: %w", err)
	}
	snap := &Snapshot{
		ServerPub:    serverPub,
		ServerPriv:   serverPriv,
		WGListenPort: listenPort,
	}
	var marked []markedPeer
	for _, r := range peers {
		if r["interface"] != p.cfg.Iface {
			continue
		}
		if p.cfg.Mode == ModeClient {
			port, _ := strconv.Atoi(r["endpoint-port"])
			marked = append(marked, markedPeer{
				id:           r[".id"],
				comment:      r["comment"],
				publicKey:    r["public-key"],
				psk:          r["preshared-key"],
				endpointAddr: r["endpoint-address"],
				endpointPort: port,
				disabled:     r["disabled"] == "true",
			})
			continue
		}
		k, err := parsePubKey(r["public-key"])
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
