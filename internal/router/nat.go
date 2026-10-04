package router

import (
	"context"
	"fmt"
	"log/slog"
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
	path    string // /ip/firewall/nat или /ipv6/firewall/nat
}

func NewNatReconciler(cfg Config, log *slog.Logger) *NatReconciler {
	return &NatReconciler{cfg: cfg, log: log, path: "/ip/firewall/nat"}
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
		_ = n.cfg.callRemove(ctx, n.path, cur[i].ID)
		n.log.Warn("nat divert: removed duplicate rule", "id", cur[i].ID)
	}

	if len(cur) == 0 {
		if _, err := n.cfg.callAdd(ctx, n.path, wantFields); err != nil {
			return fmt.Errorf("add nat: %w", err)
		}
		n.logTransition("installed", "src_port", want.SrcPort, "dst", want.DstAddress, "to", want.ToAddress)
		return nil
	}

	existing := cur[0]
	// Смена chain (переключение режима server↔client) — set тут не годится,
	// удаляем старое правило и создаём с нуля.
	if existing.Chain != want.Chain {
		if err := n.cfg.callRemove(ctx, n.path, existing.ID); err != nil {
			return fmt.Errorf("delete stale nat: %w", err)
		}
		if _, err := n.cfg.callAdd(ctx, n.path, wantFields); err != nil {
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
	if err := n.cfg.callSet(ctx, n.path, existing.ID, diff); err != nil {
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
		if err := n.cfg.callRemove(ctx, n.path, r.ID); err != nil {
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
		if r.DstAddress.Is6() != r.ToAddress.Is6() {
			return fmt.Errorf("dst-address %s and to-address %s are of different families", r.DstAddress, r.ToAddress)
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
	if r.ToAddress.Is6() {
		// /ipv6/firewall/nat: поле to-address (не to-addresses), адреса — префиксы.
		// Пишем сразу с /128 — в таком виде RouterOS их печатает, иначе diff
		// находил бы расхождение на каждом тике.
		delete(f, "to-addresses")
		f["to-address"] = netip.PrefixFrom(r.ToAddress, 128).String()
		if r.Chain == ChainOutput {
			f["dst-address"] = netip.PrefixFrom(r.DstAddress, 128).String()
		}
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

// natRule — представление правила firewall/nat (binapi).
type natRule struct {
	ID          string
	Chain       string
	Protocol    string
	Action      string
	SrcAddress  string
	SrcPort     string
	DstAddress  string
	DstPort     string
	ToAddresses string
	ToPorts     string
	Comment     string
	Disabled    string
	ToAddress   string // /ipv6/firewall/nat: вместо to-addresses
}

func natRuleFromMap(m map[string]string) natRule {
	return natRule{
		ID:          m[".id"],
		Chain:       m["chain"],
		Protocol:    m["protocol"],
		Action:      m["action"],
		SrcAddress:  m["src-address"],
		SrcPort:     m["src-port"],
		DstAddress:  m["dst-address"],
		DstPort:     m["dst-port"],
		ToAddresses: m["to-addresses"],
		ToPorts:     m["to-ports"],
		Comment:     m["comment"],
		Disabled:    m["disabled"],
		ToAddress:   m["to-address"],
	}
}

func (n *NatReconciler) list(ctx context.Context) ([]natRule, error) {
	rows, err := n.cfg.callPrint(ctx, n.path)
	if err != nil {
		return nil, err
	}
	want := n.cfg.natComment()
	var ours []natRule
	for _, r := range rows {
		if r["comment"] == want {
			ours = append(ours, natRuleFromMap(r))
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
		"to-address":   got.ToAddress,
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
		_ = m.cfg.callRemove(ctx, "/ip/firewall/nat", cur[i].ID)
		m.log.Warn("masquerade: removed duplicate rule", "id", cur[i].ID)
	}
	if len(cur) == 0 {
		if _, err := m.cfg.callAdd(ctx, "/ip/firewall/nat", want); err != nil {
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
	if err := m.cfg.callSet(ctx, "/ip/firewall/nat", existing.ID, diff); err != nil {
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
		if err := m.cfg.callRemove(ctx, "/ip/firewall/nat", r.ID); err != nil {
			return fmt.Errorf("delete masquerade %s: %w", r.ID, err)
		}
	}
	if len(cur) > 0 {
		m.logTransition("removed")
	}
	return nil
}

func (m *MasqueradeReconciler) list(ctx context.Context) ([]natRule, error) {
	rows, err := m.cfg.callPrint(ctx, "/ip/firewall/nat")
	if err != nil {
		return nil, err
	}
	want := m.cfg.masqComment()
	var ours []natRule
	for _, r := range rows {
		if r["comment"] == want {
			ours = append(ours, natRuleFromMap(r))
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

// NewNatReconciler6 — тот же реконсилер, но для /ipv6/firewall/nat. Маркер
// правила тот же (awgproxy-divert:<iface>): таблицы v4 и v6 раздельные, так что
// правила не пересекаются.
func NewNatReconciler6(cfg Config, log *slog.Logger) *NatReconciler {
	return &NatReconciler{cfg: cfg, log: log.With("family", "ipv6"), path: "/ipv6/firewall/nat"}
}
