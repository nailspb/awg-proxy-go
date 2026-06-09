package router

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
)

// Префиксы маркеров «наших» NAT-правил. Per-instance суффикс — имя WG-интерфейса
// (cfg.Iface): два контейнера на одном роутере обслуживают разные ifaces, поэтому
// их правила не пересекаются — каждый видит/правит только своё.
const (
	natCommentPrefix  = "awgproxy-divert:"
	masqCommentPrefix = "awgproxy-masquerade:"
)

func (c Config) natComment() string  { return natCommentPrefix + c.Iface }
func (c Config) masqComment() string { return masqCommentPrefix + c.Iface }

// Chains для DivertRule.
const (
	ChainOutput = "output" // client-режим: трафик WG-роутера наружу заворачиваем в контейнер
	ChainDstNat = "dstnat" // server-режим: входящий UDP с WAN перенаправляем в контейнер
)

// DivertRule — желаемое состояние NAT-правила.
//
// client-режим (Chain=output): src-port=WG-listen, dst-address=AWG-сервер,
// dst-port=AWG-порт, to-addresses=контейнер, to-ports=прокси.
//
// server-режим (Chain=dstnat): dst-port=listen-порт прокси (внешний),
// to-addresses=контейнер, to-ports=listen-порт прокси. SrcPort/DstAddress не
// используются (поля игнорируются).
type DivertRule struct {
	Chain      string     // output | dstnat
	SrcPort    int        // только Chain=output: listen-port WG-интерфейса на роутере
	DstAddress netip.Addr // только Chain=output: адрес апстрима AWG-сервера (резолвнутый)
	DstPort    int        // порт назначения, по которому матчим
	ToAddress  netip.Addr // адрес контейнера на veth
	ToPort     int        // порт прокси внутри контейнера
}

// NatReconciler — управляет NAT-правилом на роутере (идемпотентно).
type NatReconciler struct {
	cfg     Config
	log     *slog.Logger
	lastLog string // защита лога от спама: пишем только при смене состояния
}

func NewNatReconciler(cfg Config, log *slog.Logger) *NatReconciler {
	return &NatReconciler{cfg: cfg, log: log}
}

// Ensure приводит NAT-правило к want. Безопасно вызывать многократно.
func (n *NatReconciler) Ensure(ctx context.Context, want DivertRule) error {
	if err := want.validate(); err != nil {
		return err
	}
	cur, err := n.list(ctx)
	if err != nil {
		return err
	}
	wantFields := want.fields()
	wantFields["comment"] = n.cfg.natComment() // привязка правила к конкретному iface (мульти-инстанс)

	// Лишние правила (если по ошибке наплодили) — удаляем, оставляем первое.
	for i := 1; i < len(cur); i++ {
		_, _ = n.cfg.apiReq(ctx, http.MethodDelete, "/rest/ip/firewall/nat/"+cur[i].ID, nil)
		n.log.Warn("nat divert: removed duplicate rule", "id", cur[i].ID)
	}

	if len(cur) == 0 {
		if _, err := n.cfg.apiReq(ctx, http.MethodPut, "/rest/ip/firewall/nat", wantFields); err != nil {
			return fmt.Errorf("add nat: %w", err)
		}
		n.logTransition("installed", "src_port", want.SrcPort, "dst", want.DstAddress, "to", want.ToAddress)
		return nil
	}

	existing := cur[0]
	// Смена chain (переключение режима server↔client) — PATCH тут не годится,
	// удаляем старое правило и создаём с нуля.
	if existing.Chain != want.Chain {
		if _, err := n.cfg.apiReq(ctx, http.MethodDelete, "/rest/ip/firewall/nat/"+existing.ID, nil); err != nil {
			return fmt.Errorf("delete stale nat: %w", err)
		}
		if _, err := n.cfg.apiReq(ctx, http.MethodPut, "/rest/ip/firewall/nat", wantFields); err != nil {
			return fmt.Errorf("recreate nat: %w", err)
		}
		n.logTransition("rebuilt", "chain", want.Chain)
		return nil
	}
	diff := diffFields(existing, wantFields)
	if len(diff) == 0 {
		n.logTransition("active")
		return nil
	}
	if _, err := n.cfg.apiReq(ctx, http.MethodPatch, "/rest/ip/firewall/nat/"+existing.ID, diff); err != nil {
		return fmt.Errorf("update nat: %w", err)
	}
	n.logTransition("updated", "fields", diff)
	return nil
}

// Remove удаляет «наши» NAT-правила.
func (n *NatReconciler) Remove(ctx context.Context) error {
	cur, err := n.list(ctx)
	if err != nil {
		return err
	}
	for _, r := range cur {
		if _, err := n.cfg.apiReq(ctx, http.MethodDelete, "/rest/ip/firewall/nat/"+r.ID, nil); err != nil {
			return fmt.Errorf("delete nat %s: %w", r.ID, err)
		}
	}
	if len(cur) > 0 {
		n.logTransition("removed")
	}
	return nil
}

func (r DivertRule) validate() error {
	switch r.Chain {
	case ChainOutput:
		if r.SrcPort <= 0 || r.SrcPort > 65535 {
			return fmt.Errorf("invalid src-port %d", r.SrcPort)
		}
		if !r.DstAddress.IsValid() {
			return fmt.Errorf("invalid dst-address")
		}
	case ChainDstNat:
		// src-port / dst-address не используются
	default:
		return fmt.Errorf("invalid chain %q", r.Chain)
	}
	switch {
	case r.DstPort <= 0 || r.DstPort > 65535:
		return fmt.Errorf("invalid dst-port %d", r.DstPort)
	case !r.ToAddress.IsValid():
		return fmt.Errorf("invalid to-address")
	case r.ToPort <= 0 || r.ToPort > 65535:
		return fmt.Errorf("invalid to-port %d", r.ToPort)
	}
	return nil
}

// fields — поля правила в нотации RouterOS. Для dstnat src-port/dst-address
// не нужны и НЕ отправляются (RouterOS на создании не принимает пустую строку
// в полях с типом range). При смене chain старое правило удаляется и создаётся
// заново (см. Ensure), поэтому «протекание» полей output-режима невозможно.
func (r DivertRule) fields() map[string]string {
	f := map[string]string{
		"chain":        r.Chain,
		"protocol":     "udp",
		"action":       "dst-nat",
		"dst-port":     strconv.Itoa(r.DstPort),
		"to-addresses": r.ToAddress.String(),
		"to-ports":     strconv.Itoa(r.ToPort),
		"disabled":     "false",
		// comment ставит реконсилер: он завязан на iface (мульти-инстанс).
	}
	if r.Chain == ChainOutput {
		f["src-port"] = strconv.Itoa(r.SrcPort)
		f["dst-address"] = r.DstAddress.String()
	}
	return f
}

// logTransition пишет лог только когда состояние меняется (action != прошлого).
func (n *NatReconciler) logTransition(action string, attrs ...any) {
	if action == n.lastLog {
		return
	}
	n.lastLog = action
	n.log.Info("nat divert "+action, attrs...)
}

// natRule — представление правила firewall/nat в REST.
type natRule struct {
	ID          string `json:".id"`
	Chain       string `json:"chain"`
	Protocol    string `json:"protocol"`
	Action      string `json:"action"`
	SrcAddress  string `json:"src-address"`
	SrcPort     string `json:"src-port"`
	DstAddress  string `json:"dst-address"`
	DstPort     string `json:"dst-port"`
	ToAddresses string `json:"to-addresses"`
	ToPorts     string `json:"to-ports"`
	Comment     string `json:"comment"`
	Disabled    string `json:"disabled"`
}

func (n *NatReconciler) list(ctx context.Context) ([]natRule, error) {
	data, err := n.cfg.apiReq(ctx, http.MethodGet, "/rest/ip/firewall/nat", nil)
	if err != nil {
		return nil, err
	}
	var all []natRule
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("decode nat list: %w", err)
	}
	want := n.cfg.natComment()
	var ours []natRule
	for _, r := range all {
		if r.Comment == want {
			ours = append(ours, r)
		}
	}
	return ours, nil
}

// diffFields возвращает поля want, значения которых отличаются от got.
func diffFields(got natRule, want map[string]string) map[string]string {
	cur := map[string]string{
		"chain":        got.Chain,
		"protocol":     got.Protocol,
		"action":       got.Action,
		"src-port":     got.SrcPort,
		"dst-address":  got.DstAddress,
		"dst-port":     got.DstPort,
		"to-addresses": got.ToAddresses,
		"to-ports":     got.ToPorts,
		"comment":      got.Comment,
		"disabled":     got.Disabled,
	}
	diff := map[string]string{}
	for k, v := range want {
		if cur[k] != v {
			diff[k] = v
		}
	}
	return diff
}

// MasqueradeReconciler — управляет srcnat-masquerade правилом для сети WG-интерфейса.
// Маркер правила завязан на iface (см. Config.masqComment) — у разных контейнеров
// разные iface, поэтому реконсилеры не пересекаются.
type MasqueradeReconciler struct {
	cfg     Config
	log     *slog.Logger
	lastLog string
}

func NewMasqueradeReconciler(cfg Config, log *slog.Logger) *MasqueradeReconciler {
	return &MasqueradeReconciler{cfg: cfg, log: log}
}

// Ensure приводит masquerade-правило к виду:
//
//	chain=srcnat action=masquerade src-address=<network> comment=awgproxy-masquerade
func (m *MasqueradeReconciler) Ensure(ctx context.Context, network netip.Prefix) error {
	if !network.IsValid() {
		return fmt.Errorf("invalid network")
	}
	want := map[string]string{
		"chain":       "srcnat",
		"action":      "masquerade",
		"src-address": network.String(),
		"comment":     m.cfg.masqComment(),
		"disabled":    "false",
	}
	cur, err := m.list(ctx)
	if err != nil {
		return err
	}
	// Лишние дубли — снести, оставить первый.
	for i := 1; i < len(cur); i++ {
		_, _ = m.cfg.apiReq(ctx, http.MethodDelete, "/rest/ip/firewall/nat/"+cur[i].ID, nil)
		m.log.Warn("masquerade: removed duplicate rule", "id", cur[i].ID)
	}
	if len(cur) == 0 {
		if _, err := m.cfg.apiReq(ctx, http.MethodPut, "/rest/ip/firewall/nat", want); err != nil {
			return fmt.Errorf("add masquerade: %w", err)
		}
		m.logTransition("installed", "src", network)
		return nil
	}
	existing := cur[0]
	diff := diffMasqFields(existing, want)
	if len(diff) == 0 {
		m.logTransition("active")
		return nil
	}
	if _, err := m.cfg.apiReq(ctx, http.MethodPatch, "/rest/ip/firewall/nat/"+existing.ID, diff); err != nil {
		return fmt.Errorf("update masquerade: %w", err)
	}
	m.logTransition("updated", "fields", diff)
	return nil
}

// Remove удаляет «наше» masquerade-правило.
func (m *MasqueradeReconciler) Remove(ctx context.Context) error {
	cur, err := m.list(ctx)
	if err != nil {
		return err
	}
	for _, r := range cur {
		if _, err := m.cfg.apiReq(ctx, http.MethodDelete, "/rest/ip/firewall/nat/"+r.ID, nil); err != nil {
			return fmt.Errorf("delete masquerade %s: %w", r.ID, err)
		}
	}
	if len(cur) > 0 {
		m.logTransition("removed")
	}
	return nil
}

func (m *MasqueradeReconciler) list(ctx context.Context) ([]natRule, error) {
	data, err := m.cfg.apiReq(ctx, http.MethodGet, "/rest/ip/firewall/nat", nil)
	if err != nil {
		return nil, err
	}
	var all []natRule
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("decode nat list: %w", err)
	}
	want := m.cfg.masqComment()
	var ours []natRule
	for _, r := range all {
		if r.Comment == want {
			ours = append(ours, r)
		}
	}
	return ours, nil
}

func diffMasqFields(got natRule, want map[string]string) map[string]string {
	cur := map[string]string{
		"chain":       got.Chain,
		"action":      got.Action,
		"src-address": got.SrcAddress,
		"comment":     got.Comment,
		"disabled":    got.Disabled,
	}
	diff := map[string]string{}
	for k, v := range want {
		if cur[k] != v {
			diff[k] = v
		}
	}
	return diff
}

func (m *MasqueradeReconciler) logTransition(action string, attrs ...any) {
	if action == m.lastLog {
		return
	}
	m.lastLog = action
	m.log.Info("masquerade "+action, attrs...)
}
