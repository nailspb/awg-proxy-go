// Command awgproxy — AWG-прокси (server/client) для контейнера RouterOS 7.23.
package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/glebov/awg-proxy-go/internal/api"
	"github.com/glebov/awg-proxy-go/internal/config"
	"github.com/glebov/awg-proxy-go/internal/proxy"
	"github.com/glebov/awg-proxy-go/internal/router"
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		slog.Error("resolve binary path", "err", err)
		os.Exit(1)
	}
	cfgPath := filepath.Join(filepath.Dir(exe), "config.json")

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(cfgPath)}))
	// Лог пути и mtime: помогает увидеть, подхватился ли смонтированный конфиг.
	if st, err := os.Stat(cfgPath); err == nil {
		log.Info("config file", "path", cfgPath, "size", st.Size(), "mtime", st.ModTime())
	} else {
		log.Warn("config file missing", "path", cfgPath, "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Текущий поллер (обновляется при горячей перезагрузке) и сигнал перезагрузки.
	var curPoller atomic.Pointer[router.Poller]
	reload := make(chan struct{}, 1)
	triggerReload := func() {
		select {
		case reload <- struct{}{}:
		default:
		}
	}

	// Веб-интерфейс работает поверх перезагрузок стека.
	web := &http.Server{
		Handler: api.New(cfgPath, curPoller.Load, triggerReload, log).Handler(),
	}
	startWeb(ctx, cfgPath, web, log)

	// Супервизор: применяет конфиг и перезапускает стек при сохранении из веба.
	supervise(ctx, cfgPath, &curPoller, reload, log)
}

// supervise держит прокси-стек живым и пересоздаёт его при перезагрузке конфига.
// Сбой подключения к роутеру или невалидный конфиг не валят сервис — веб остаётся доступен.
//
// prevRcfg хранится между итерациями: если в новой конфигурации поменялся WG-интерфейс,
// надо снести правила со старым iface-суффиксом (новый реконсилер их по комменту уже
// не увидит). Делаем это ДО запуска нового стека, чтобы не плодить дубли.
func supervise(ctx context.Context, cfgPath string, curPoller *atomic.Pointer[router.Poller], reload <-chan struct{}, log *slog.Logger) {
	var prevRcfg *router.Config
	for {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			log.Error("config read failed, waiting for change via web", "err", err)
			if !waitReload(ctx, reload) {
				return
			}
			continue
		}
		// Валидация — мягкая: предупреждение в лог, но стек поднимаем.
		// Иначе сохранённый частично заполненный конфиг (Router заполнен, Settings нет)
		// блокирует ВСЁ — поллер не стартует, NAT не реконсилится, роутер не пингуется.
		if vErr := cfg.Validate(); vErr != nil {
			log.Warn("config has issues, starting partial stack", "err", vErr)
		}

		newRcfg := buildRouterConfig(cfg)
		// Перед стартом нового стека — почистить хвосты от прошлой конфигурации,
		// если поменялся iface (или вообще пропал доступ к роутеру).
		cleanupStaleRules(ctx, prevRcfg, newRcfg, log)
		prevRcfg = &newRcfg

		cctx, ccancel := context.WithCancel(ctx)
		done := startStack(cctx, cfg, newRcfg, log, curPoller)

		select {
		case <-ctx.Done():
			ccancel()
			<-done
			return
		case <-reload:
			log.Info("config changed, reloading")
		case <-done:
			log.Warn("proxy stopped (bad address?), waiting for change via web")
			if !waitReload(ctx, reload) {
				ccancel()
				return
			}
		}
		ccancel()
		<-done
	}
}

// buildRouterConfig собирает router.Config из верхнеуровневого конфига приложения.
func buildRouterConfig(cfg *config.Config) router.Config {
	r := cfg.Router
	return router.Config{
		Address:  r.Address,
		APIPort:  r.APIPort,
		APITLS:   r.APITLS,
		User:     r.User,
		Password: r.Password,
		Iface:    r.WGIface,
		Interval: cfg.PollInterval,
		Mode:     cfg.Mode,
	}
}

// cleanupStaleRules сносит правила, которые остались от прошлой конфигурации и
// в новой уже не управляются. На сегодня единственный такой кейс — смена WGIface:
// маркер правил содержит суффикс iface, новый реконсилер фильтрует по новому, а
// старые «осиротевшие» уже не увидит. Используем prev (со старым iface) — у него
// маркер ещё совпадёт со старыми правилами.
func cleanupStaleRules(ctx context.Context, prev *router.Config, next router.Config, log *slog.Logger) {
	if prev == nil || prev.Iface == "" || prev.Iface == next.Iface {
		return
	}
	if prev.Address == "" || prev.Password == "" {
		return // прошлый конфиг был неполным — правил не ставили
	}
	log.Info("wg iface changed, cleaning rules from previous iface", "old", prev.Iface, "new", next.Iface)
	go cleanupDivert(ctx, *prev, log)
	go cleanupMasquerade(ctx, *prev, log)
}

// startStack запускает поллер роутера и прокси под дочерним контекстом.
func startStack(ctx context.Context, cfg *config.Config, rcfg router.Config, log *slog.Logger, curPoller *atomic.Pointer[router.Poller]) <-chan struct{} {
	ctx, cancel := context.WithCancel(ctx)
	r := cfg.Router
	poller := router.New(rcfg, log)
	curPoller.Store(poller)

	// onTick — крючок(и) поллера для NAT-реконсилеров. Каждый сам решает, что делать;
	// если в конфиге опция выключена — соответствующее правило сносится один раз при
	// старте (могло остаться от прошлой конфигурации).
	var hooks []func(context.Context, *router.Snapshot)
	if cfg.Divert {
		switch cfg.Mode {
		case config.ModeClient:
			if h := makeClientDivertHook(rcfg, cfg, log); h != nil {
				hooks = append(hooks, h)
			}
		case config.ModeServer:
			if h := makeServerDivertHook(rcfg, cfg, log); h != nil {
				hooks = append(hooks, h)
			}
		}
	} else if r.Address != "" {
		go cleanupDivert(ctx, rcfg, log)
	}
	if cfg.Masquerade && cfg.Mode == config.ModeServer && r.Address != "" {
		if h := makeMasqueradeHook(rcfg, log); h != nil {
			hooks = append(hooks, h)
		}
	} else if r.Address != "" {
		go cleanupMasquerade(ctx, rcfg, log)
	}
	var onTick func(context.Context, *router.Snapshot)
	if len(hooks) > 0 {
		onTick = func(ctx context.Context, s *router.Snapshot) {
			for _, h := range hooks {
				h(ctx, s)
			}
		}
	}

	log.Info("starting awgproxy",
		"mode", cfg.Mode, "listen", cfg.Listen, "remote", cfg.Remote,
		"router", r.Address, "divert", cfg.Divert)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		var wg sync.WaitGroup
		wg.Go(func() { poller.Run(ctx, onTick) })
		// Прокси может упасть из-за неполного конфига (пустой Listen/Remote, etc.) —
		// НЕ валим вместе с ним поллер: пока пользователь чинит конфиг в веб-UI,
		// поллер должен опрашивать роутер, NAT-реконсилеры — работать, веб-интерфейс
		// — иметь свежие данные о пирах/интерфейсах. Стек завершится только по reload
		// или shutdown (ctx.Done) — тогда поллер сам выйдет и done закроется.
		wg.Go(func() {
			if err := proxy.New(cfg, poller, log).Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("proxy stopped with error, poller stays up", "err", err)
			}
		})
		wg.Wait()
	}()
	return done
}

// makeClientDivertHook возвращает onTick-крючок для client-режима. После каждого
// УСПЕШНОГО опроса:
//   - есть помеченный peer и известен listen-port → правило ставим/обновляем;
//   - помеченного peer'а нет → правило сносим (оператор снял галку — снимаем NAT).
//
// onTick дёргается только из poller.tick на удачном фетче, так что snap здесь
// всегда отражает реальное состояние роутера (а не «ещё не успели прочитать»).
func makeClientDivertHook(rcfg router.Config, cfg *config.Config, log *slog.Logger) func(context.Context, *router.Snapshot) {
	rec := router.NewNatReconciler(rcfg, log)
	containerAddr, err := netip.ParseAddr(cfg.ContainerAddr)
	if err != nil {
		log.Error("invalid container_addr, divert disabled", "addr", cfg.ContainerAddr, "err", err)
		return nil
	}
	toPort, err := portFromListen(cfg.Listen)
	if err != nil {
		log.Error("invalid listen, divert disabled", "listen", cfg.Listen, "err", err)
		return nil
	}
	return func(ctx context.Context, snap *router.Snapshot) {
		if snap.Upstream == nil || snap.WGListenPort == 0 {
			// Нет апстрима — снимаем правило (если оно было).
			if err := rec.Remove(ctx); err != nil {
				log.Warn("nat remove failed", "err", err)
			}
			return
		}
		want := router.DivertRule{
			Chain:      router.ChainOutput,
			SrcPort:    snap.WGListenPort,
			DstAddress: snap.Upstream.RemoteAddr.Addr(),
			DstPort:    int(snap.Upstream.RemoteAddr.Port()),
			ToAddress:  containerAddr,
			ToPort:     toPort,
		}
		if err := rec.Ensure(ctx, want); err != nil {
			log.Warn("nat reconcile failed", "err", err)
		}
	}
}

// makeServerDivertHook — серверный аналог: создаёт chain=dstnat dst-port=<внешний>
// → to-addresses=<контейнер>:<внутренний>. Внешний порт берётся из public_endpoint
// (то, что слушают извне на роутере), внутренний — из listen (то, на чём прокси
// слушает в контейнере). Если public_endpoint пуст/некорректен — деградируем
// до listen-порта (поведение «один и тот же порт снаружи и внутри»).
// Параметры не зависят от снапшота, но привязка к onTick гарантирует регулярное
// переподтверждение (если правило кто-то снёс вручную — восстановим на тике).
func makeServerDivertHook(rcfg router.Config, cfg *config.Config, log *slog.Logger) func(context.Context, *router.Snapshot) {
	rec := router.NewNatReconciler(rcfg, log)
	containerAddr, err := netip.ParseAddr(cfg.ContainerAddr)
	if err != nil {
		log.Error("invalid container_addr, divert disabled", "addr", cfg.ContainerAddr, "err", err)
		return nil
	}
	toPort, err := portFromListen(cfg.Listen)
	if err != nil {
		log.Error("invalid listen, divert disabled", "listen", cfg.Listen, "err", err)
		return nil
	}
	dstPort := toPort
	if cfg.PublicEndpoint != "" {
		if p, err := portFromEndpoint(cfg.PublicEndpoint); err == nil {
			dstPort = p
		} else {
			log.Warn("invalid public_endpoint, fall back to listen-port for dst-nat", "endpoint", cfg.PublicEndpoint, "err", err)
		}
	}
	want := router.DivertRule{
		Chain:     router.ChainDstNat,
		DstPort:   dstPort,
		ToAddress: containerAddr,
		ToPort:    toPort,
	}
	return func(ctx context.Context, _ *router.Snapshot) {
		if err := rec.Ensure(ctx, want); err != nil {
			log.Warn("nat reconcile failed", "err", err)
		}
	}
}

// portFromEndpoint извлекает порт из "host:port" (поддержка IPv6 в [].).
func portFromEndpoint(ep string) (int, error) {
	_, port, err := net.SplitHostPort(ep)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(port)
}

// cleanupDivert убирает «наше» NAT-правило при выключенном divert (например,
// оператор снял галку — старое правило не должно остаться болтаться на роутере).
func cleanupDivert(ctx context.Context, rcfg router.Config, log *slog.Logger) {
	rec := router.NewNatReconciler(rcfg, log)
	if err := rec.Remove(ctx); err != nil {
		log.Warn("nat cleanup failed", "err", err)
	}
}

// makeMasqueradeHook — server-режим: на каждом тике подтверждает srcnat-masquerade
// для сети WG-интерфейса. Сеть берётся из /ip/address роутера (через ListInterfaces),
// поэтому смена адреса iface подхватывается без перезапуска.
func makeMasqueradeHook(rcfg router.Config, log *slog.Logger) func(context.Context, *router.Snapshot) {
	rec := router.NewMasqueradeReconciler(rcfg, log)
	cl := router.NewClient(rcfg, log)
	return func(ctx context.Context, _ *router.Snapshot) {
		ifs, err := cl.ListInterfaces(ctx)
		if err != nil {
			log.Warn("masquerade: list interfaces failed", "err", err)
			return
		}
		var addr string
		for _, it := range ifs {
			if it.Name == rcfg.Iface {
				addr = it.Address
				break
			}
		}
		if addr == "" {
			log.Warn("masquerade: wg iface has no /ip/address, skip", "iface", rcfg.Iface)
			return
		}
		p, err := netip.ParsePrefix(addr)
		if err != nil {
			log.Warn("masquerade: bad iface address", "addr", addr, "err", err)
			return
		}
		if err := rec.Ensure(ctx, p.Masked()); err != nil {
			log.Warn("masquerade reconcile failed", "err", err)
		}
	}
}

// cleanupMasquerade — снимаем правило когда тоггл выключен (или режим не server).
func cleanupMasquerade(ctx context.Context, rcfg router.Config, log *slog.Logger) {
	rec := router.NewMasqueradeReconciler(rcfg, log)
	if err := rec.Remove(ctx); err != nil {
		log.Warn("masquerade cleanup failed", "err", err)
	}
}

// portFromListen извлекает порт из ":51820"/"127.0.0.1:51820".
func portFromListen(listen string) (int, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(port)
}

func startWeb(ctx context.Context, cfgPath string, web *http.Server, log *slog.Logger) {
	web.Addr = webAddr(cfgPath)
	context.AfterFunc(ctx, func() { _ = web.Close() })
	go func() {
		log.Info("web UI listening", "addr", web.Addr)
		if err := web.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("web server stopped with error", "err", err)
		}
	}()
}

// waitReload блокируется до сигнала перезагрузки; false — если сервис завершается.
func waitReload(ctx context.Context, reload <-chan struct{}) bool {
	select {
	case <-ctx.Done():
		return false
	case <-reload:
		return true
	}
}

// startupConfig читает эффективную конфигурацию без валидации — для компонентов,
// которые поднимаются один раз и переживают перезагрузки (логгер, веб-сервер).
func startupConfig(cfgPath string) *config.Config {
	s, _ := config.Read(cfgPath)
	return s.ToConfig()
}

func logLevel(cfgPath string) slog.Level { return startupConfig(cfgPath).LogLevel }
func webAddr(cfgPath string) string      { return startupConfig(cfgPath).WebListen }
