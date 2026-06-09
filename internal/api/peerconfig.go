package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/glebov/awg-proxy-go/internal/config"
	qrcode "github.com/skip2/go-qrcode"
)

// peerConfigReq — данные от фронтенда для сборки клиентского конфига.
type peerConfigReq struct {
	PrivateKey   string `json:"private_key"`
	Address      string `json:"address"`
	PresharedKey string `json:"preshared_key"`
	Name         string `json:"name"`
}

// peerConfig собирает клиентский AmneziaWG-конфиг и QR-код для нового пира.
func (s *Server) peerConfig(w http.ResponseWriter, r *http.Request) {
	var req peerConfigReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	if req.PrivateKey == "" || req.Address == "" {
		s.fail(w, http.StatusBadRequest, fmt.Errorf("private_key and address are required"))
		return
	}
	settings, err := config.Read(s.cfgPath)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	if settings.Server.PublicEndpoint == "" {
		s.fail(w, http.StatusBadRequest, fmt.Errorf("set server.public_endpoint in settings first"))
		return
	}
	cl, err := s.routerClient()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	serverKey, err := cl.ServerKey(r.Context())
	if err != nil {
		s.fail(w, http.StatusBadGateway, err)
		return
	}

	conf := renderClientConfig(settings, serverKey, req)
	png, err := qrcode.Encode(conf, qrcode.Medium, 320)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"config": conf,
		"qr":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

// renderClientConfig формирует текст клиентского конфига AmneziaWG.
func renderClientConfig(s config.Settings, serverKey string, req peerConfigReq) string {
	o := s.Server.Obfuscation
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", req.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", req.Address)
	if s.Server.ClientDNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", s.Server.ClientDNS)
	}
	// Параметры обфускации AmneziaWG (должны совпадать с сервером).
	fmt.Fprintf(&b, "Jc = %d\n", o.Jc)
	fmt.Fprintf(&b, "Jmin = %d\n", o.Jmin)
	fmt.Fprintf(&b, "Jmax = %d\n", o.Jmax)
	fmt.Fprintf(&b, "S1 = %d\n", o.S1)
	fmt.Fprintf(&b, "S2 = %d\n", o.S2)
	fmt.Fprintf(&b, "H1 = %d\n", o.H1)
	fmt.Fprintf(&b, "H2 = %d\n", o.H2)
	fmt.Fprintf(&b, "H3 = %d\n", o.H3)
	fmt.Fprintf(&b, "H4 = %d\n", o.H4)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", serverKey)
	if req.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", req.PresharedKey)
	}
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", s.Server.PublicEndpoint)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}
