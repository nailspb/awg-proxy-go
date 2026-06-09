package router

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	data, err := c.cfg.apiReq(ctx, http.MethodGet, "/rest/interface/wireguard", nil)
	if err != nil {
		return err
	}
	var ifaces []struct {
		ID   string `json:".id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &ifaces); err != nil {
		return fmt.Errorf("decode interfaces: %w", err)
	}
	var ifaceID string
	for _, it := range ifaces {
		if it.Name == c.cfg.Iface {
			ifaceID = it.ID
			break
		}
	}
	if ifaceID == "" {
		return fmt.Errorf("interface %q not found", c.cfg.Iface)
	}

	if privateKey != "" {
		if _, err := c.cfg.apiReq(ctx, http.MethodPatch, "/rest/interface/wireguard/"+ifaceID,
			map[string]string{"private-key": privateKey}); err != nil {
			return fmt.Errorf("set private-key: %w", err)
		}
	}
	if address == "" {
		return nil
	}

	addrs, err := c.cfg.apiReq(ctx, http.MethodGet, "/rest/ip/address", nil)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	var rows []struct {
		ID        string `json:".id"`
		Interface string `json:"interface"`
		Address   string `json:"address"`
	}
	if err := json.Unmarshal(addrs, &rows); err != nil {
		return fmt.Errorf("decode addresses: %w", err)
	}
	var existing []string
	for _, r := range rows {
		if r.Interface == c.cfg.Iface {
			existing = append(existing, r.ID)
		}
	}
	if len(existing) == 0 {
		if _, err := c.cfg.apiReq(ctx, http.MethodPut, "/rest/ip/address",
			map[string]string{"interface": c.cfg.Iface, "address": address}); err != nil {
			return fmt.Errorf("add address: %w", err)
		}
		return nil
	}
	// Первый адрес приводим к нужному, лишние не трогаем.
	if _, err := c.cfg.apiReq(ctx, http.MethodPatch, "/rest/ip/address/"+existing[0],
		map[string]string{"address": address}); err != nil {
		return fmt.Errorf("update address: %w", err)
	}
	return nil
}
