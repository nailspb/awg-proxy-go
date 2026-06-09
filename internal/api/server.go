// Package api предоставляет веб-интерфейс настройки: REST поверх config-файла
// и статику фронтенда (встроена через embed).
package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/glebov/awg-proxy-go/internal/buildinfo"
	"github.com/glebov/awg-proxy-go/internal/config"
	"github.com/glebov/awg-proxy-go/internal/router"
)

//go:embed web
var webFS embed.FS

type Server struct {
	cfgPath string
	poller  func() *router.Poller // текущий поллер (меняется при горячей перезагрузке)
	onSaved func()                // вызывается после успешного сохранения конфига
	auth    *sessions             // токены веб-сессий
	limit   *limiter              // ограничение перебора пароля
	log     *slog.Logger

	// Кеш доступности роутера (чтобы не пинговать на каждый запрос).
	reachMu  sync.Mutex
	reachKey string
	reachAt  time.Time
	reachOK  bool
}

const (
	reachTimeout  = 1500 * time.Millisecond
	reachCacheTTL = 10 * time.Second
)

func New(cfgPath string, poller func() *router.Poller, onSaved func(), log *slog.Logger) *Server {
	return &Server{cfgPath: cfgPath, poller: poller, onSaved: onSaved, auth: newSessions(), limit: newLimiter(), log: log}
}

// Handler собирает маршруты REST + статику.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Авторизация (открытые маршруты).
	mux.HandleFunc("GET /api/auth", s.authStatus)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/version", s.getVersion)
	// Данные за авторизацией.
	mux.HandleFunc("GET /api/config", s.protect(s.getConfig))
	mux.HandleFunc("PUT /api/config", s.protect(s.putConfig))
	mux.HandleFunc("GET /api/status", s.protect(s.getStatus))
	mux.HandleFunc("GET /api/peers", s.protect(s.listPeers))
	mux.HandleFunc("POST /api/peers", s.protect(s.addPeer))
	mux.HandleFunc("PATCH /api/peers/{id}", s.protect(s.updatePeer))
	mux.HandleFunc("DELETE /api/peers/{id}", s.protect(s.deletePeer))
	mux.HandleFunc("POST /api/keypair", s.protect(s.keypair))
	mux.HandleFunc("POST /api/peer-config", s.protect(s.peerConfig))
	mux.HandleFunc("GET /api/router/interfaces", s.protect(s.listRouterInterfaces))
	mux.HandleFunc("GET /api/router/addresses", s.protect(s.listRouterAddresses))
	mux.HandleFunc("GET /api/net/auto", s.protect(s.netAuto))
	mux.HandleFunc("POST /api/router/interface", s.protect(s.setRouterInterface))

	sub, _ := fs.Sub(webFS, "web")
	files := http.FileServerFS(sub)
	// Страница входа — отдельная, не требует авторизации и обслуживается
	// раньше общего файл-сервера (Go 1.22 mux: более конкретный паттерн
	// имеет приоритет).
	mux.HandleFunc("GET /login", s.serveLogin)
	mux.Handle("/", s.gateStatic(files))
	return mux
}

// gateStatic — шлюз статики: если требуется авторизация и куки нет,
// редиректит на /login (с next=<исходный путь>). Так главная не отдаёт
// ни HTML, ни ассеты приложения неавторизованному пользователю.
// Отдаёт статику с no-store (фронт меняется часто, кеш только мешает).
func (s *Server) gateStatic(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authRequired() && !s.authed(r) {
			target := "/login"
			if p := r.URL.Path; p != "" && p != "/" {
				target += "?next=" + url.QueryEscape(p)
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		next.ServeHTTP(w, r)
	}
}

// serveLogin отдаёт страницу входа. Авторизованный сразу улетает на главную
// (или next, если он относительный).
func (s *Server) serveLogin(w http.ResponseWriter, r *http.Request) {
	if s.authed(r) {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusFound)
		return
	}
	data, err := webFS.ReadFile("web/login.html")
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// safeNext пропускает только относительные пути (защита от open-redirect).
func safeNext(s string) string {
	if strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") {
		return s
	}
	return "/"
}

// authRequired — нужна ли авторизация: задан адрес роутера И роутер доступен
// (есть с чем и где сверять креды). Нет настроек или роутер недоступен — пускаем
// без входа, чтобы не запереть себя при лежащем роутере.
func (s *Server) authRequired() bool {
	// Аварийный обход: AWGPROXY_NO_AUTH=1 полностью отключает авторизацию.
	// Нужно, например, когда стоят кривые/неизвестные креды роутера и лимитер
	// уже залочил вход — поставить переменную, перезапустить контейнер, зайти,
	// поправить креды, убрать переменную.
	if v := os.Getenv("AWGPROXY_NO_AUTH"); v == "1" || v == "true" {
		return false
	}
	st, err := config.Read(s.cfgPath)
	if err != nil || st.ActiveRouter().Address == "" {
		return false
	}
	return s.routerReachable(st)
}

// routerReachable быстро проверяет TCP-доступность роутера (порт REST API).
// Результат кешируется на reachCacheTTL.
func (s *Server) routerReachable(st config.Settings) bool {
	rt := st.ActiveRouter()
	addr := net.JoinHostPort(rt.Address, strconv.Itoa(rt.APIPort))

	s.reachMu.Lock()
	if s.reachKey == addr && time.Since(s.reachAt) < reachCacheTTL {
		ok := s.reachOK
		s.reachMu.Unlock()
		return ok
	}
	s.reachMu.Unlock()

	conn, err := net.DialTimeout("tcp", addr, reachTimeout)
	ok := err == nil
	if conn != nil {
		conn.Close()
	}
	s.reachMu.Lock()
	s.reachKey, s.reachAt, s.reachOK = addr, time.Now(), ok
	s.reachMu.Unlock()
	if !ok {
		s.log.Warn("router unreachable, web auth disabled", "addr", addr)
	}
	return ok
}

func (s *Server) authed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	return err == nil && s.auth.valid(c.Value)
}

// protect пропускает запрос, если авторизация не нужна или сессия валидна.
func (s *Server) protect(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authRequired() || s.authed(r) {
			h(w, r)
			return
		}
		s.fail(w, http.StatusUnauthorized, fmt.Errorf("authentication required"))
	}
}

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"required":      s.authRequired(),
		"authenticated": s.authed(r),
	})
}

// login сверяет введённые логин/пароль с роутером и заводит сессию.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	if !s.authRequired() {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	key := clientIP(r)
	if ok, wait := s.limit.allowed(key); !ok {
		secs := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		s.log.Warn("login locked out", "ip", key, "retry_s", secs)
		s.fail(w, http.StatusTooManyRequests, fmt.Errorf("too many attempts, retry in %ds", secs))
		return
	}
	st, err := config.Read(s.cfgPath)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	rt := st.ActiveRouter()
	// Проверяем именно введённый пароль (REST /system/identity).
	cl := router.NewClient(router.Config{
		Address:  rt.Address,
		APIPort:  rt.APIPort,
		APITLS:   rt.APITLS,
		User:     req.Username,
		Password: req.Password,
	}, s.log)
	if err := cl.Verify(r.Context()); err != nil {
		s.limit.fail(key)
		s.log.Warn("web login rejected", "user", req.Username, "ip", key, "err", err)
		s.fail(w, http.StatusUnauthorized, fmt.Errorf("router rejected credentials"))
		return
	}
	s.limit.reset(key)
	tok, err := s.auth.create()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL / time.Second),
	})
	s.log.Info("web login ok", "user", req.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// clientIP — IP клиента без порта (ключ для лимитера попыток входа).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.auth.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	settings, err := config.Read(s.cfgPath)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	var settings config.Settings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	// section=router|service — частичная валидация (разделы UI сохраняются
	// независимо, ошибка в одном не блокирует другой). Без параметра — полная.
	section := r.URL.Query().Get("section")
	if err := config.Write(s.cfgPath, settings, section); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	s.log.Info("config saved via web", "section", section)
	if s.onSaved != nil {
		s.onSaved()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (s *Server) getStatus(w http.ResponseWriter, _ *http.Request) {
	st := struct {
		Mode         string `json:"mode"`
		PollOK       bool   `json:"poll_ok"`
		ServerKey    bool   `json:"server_key"`
		Clients      int    `json:"clients"`
		WGListenPort int    `json:"wg_listen_port,omitempty"`
		// client-режим: статус апстрима
		UpstreamReady   bool   `json:"upstream_ready"`
		UpstreamAddr    string `json:"upstream_addr,omitempty"`
		UpstreamComment string `json:"upstream_comment,omitempty"`
	}{}
	settings, _ := config.Read(s.cfgPath)
	st.Mode = settings.Mode
	if p := s.poller(); p != nil {
		if snap := p.Snapshot(); snap != nil {
			st.PollOK = true
			st.ServerKey = snap.ServerPub != ([32]byte{})
			st.Clients = len(snap.ClientPubs)
			st.WGListenPort = snap.WGListenPort
			if u := snap.Upstream; u != nil {
				st.UpstreamReady = true
				st.UpstreamAddr = u.RemoteAddr.String()
				st.UpstreamComment = u.Comment
			}
		}
	}
	writeJSON(w, http.StatusOK, st)
}

// routerClient строит клиент управления пирами из текущего сохранённого конфига
// (берёт router-секцию активного режима).
func (s *Server) routerClient() (*router.Client, error) {
	settings, err := config.Read(s.cfgPath)
	if err != nil {
		return nil, err
	}
	c := settings.ToConfig()
	r := c.Router
	return router.NewClient(router.Config{
		Address:  r.Address,
		APIPort:  r.APIPort,
		APITLS:   r.APITLS,
		User:     r.User,
		Password: r.Password,
		Iface:    r.WGIface,
		Interval: c.PollInterval,
	}, s.log), nil
}

func (s *Server) listPeers(w http.ResponseWriter, r *http.Request) {
	cl, err := s.routerClient()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	peers, err := cl.ListPeers(r.Context())
	if err != nil {
		s.fail(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, peers)
}

func (s *Server) addPeer(w http.ResponseWriter, r *http.Request) {
	var p router.Peer
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	cl, err := s.routerClient()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	if err := cl.AddPeer(r.Context(), p); err != nil {
		s.fail(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (s *Server) updatePeer(w http.ResponseWriter, r *http.Request) {
	var p router.Peer
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	cl, err := s.routerClient()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	id := r.PathValue("id")
	// disabled передаётся как отдельный частичный апдейт (toggle) либо вместе с полями.
	if err := cl.UpdatePeer(r.Context(), id, p); err != nil {
		s.fail(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) deletePeer(w http.ResponseWriter, r *http.Request) {
	cl, err := s.routerClient()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	if err := cl.DeletePeer(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) getVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version": buildinfo.Version,
		"build":   buildinfo.Build,
	})
}

// listRouterAddresses отдаёт все активные /ip/address с роутера (для подсказок
// в datalist выбора публичного endpoint host).
func (s *Server) listRouterAddresses(w http.ResponseWriter, r *http.Request) {
	cl, err := s.routerClient()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	addrs, err := cl.ListAddresses(r.Context())
	if err != nil {
		s.fail(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, addrs)
}

// listRouterInterfaces отдаёт список WG-интерфейсов роутера (для выпадашки в Settings).
func (s *Server) listRouterInterfaces(w http.ResponseWriter, r *http.Request) {
	cl, err := s.routerClient()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	ifs, err := cl.ListInterfaces(r.Context())
	if err != nil {
		s.fail(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, ifs)
}

// setRouterInterface применяет private-key и/или address на WG-интерфейсе роутера.
// Любое поле может быть пустым — соответствующая часть пропускается.
func (s *Server) setRouterInterface(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PrivateKey string `json:"private_key"`
		Address    string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.fail(w, http.StatusBadRequest, err)
		return
	}
	cl, err := s.routerClient()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	if err := cl.SetInterface(r.Context(), req.PrivateKey, req.Address); err != nil {
		s.fail(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "applied"})
}

func (s *Server) keypair(w http.ResponseWriter, _ *http.Request) {
	priv, pub, err := router.GenerateKeypair()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"private": priv, "public": pub})
}

func (s *Server) fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
