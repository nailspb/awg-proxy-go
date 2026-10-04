package router

import (
	"context"
	"fmt"
	"strings"
)

// normalizeIfaceAddress расширяет /32 (типовой формат wg-quick) до /24, иначе
// маршрут к соседям по WG-сети не появится. Кастомные маски (16/23/...) и IPv6
// не трогаем — пользователь поставил их сознательно.
func normalizeIfaceAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || strings.Contains(addr, ":") {
		return addr
	}
	slash := strings.IndexByte(addr, '/')
	if slash < 0 {
		return addr + "/24"
	}
	if addr[slash+1:] == "32" {
		return addr[:slash] + "/24"
	}
	return addr
}

// SetInterface обновляет приватный ключ WG-интерфейса и (опц.) адрес `/ip/address`
// на этом интерфейсе. Используется в импорте AmneziaWG-конфига в client-режиме.
// Любой из параметров может быть пустым — тогда соответствующая часть не трогается.
func (c *Client) SetInterface(ctx context.Context, privateKey, address string) error {
	address = normalizeIfaceAddress(address)
	ifaces, err := c.cfg.callPrint(ctx, "/interface/wireguard")
	if err != nil {
		return err
	}
	var ifaceID string
	for _, it := range ifaces {
		if it["name"] == c.cfg.Iface {
			ifaceID = it[".id"]
			break
		}
	}
	if ifaceID == "" {
		return fmt.Errorf("interface %q not found", c.cfg.Iface)
	}

	if privateKey != "" {
		if err := c.cfg.callSet(ctx, "/interface/wireguard", ifaceID,
			map[string]string{"private-key": privateKey}); err != nil {
			return fmt.Errorf("set private-key: %w", err)
		}
	}
	if address == "" {
		return nil
	}

	addrs, err := c.cfg.callPrint(ctx, "/ip/address")
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	var existing []string
	for _, r := range addrs {
		if r["interface"] == c.cfg.Iface {
			existing = append(existing, r[".id"])
		}
	}
	if len(existing) == 0 {
		if _, err := c.cfg.callAdd(ctx, "/ip/address",
			map[string]string{"interface": c.cfg.Iface, "address": address}); err != nil {
			return fmt.Errorf("add address: %w", err)
		}
		return nil
	}
	// Первый адрес приводим к нужному, лишние не трогаем.
	if err := c.cfg.callSet(ctx, "/ip/address", existing[0],
		map[string]string{"address": address}); err != nil {
		return fmt.Errorf("update address: %w", err)
	}
	return nil
}
