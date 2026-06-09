// Package proxy реализует AWG-прокси в двух режимах:
//   - server (1:N): принимает обфусцированный трафик от внешних клиентов,
//     снимает обфускацию и пересылает на локальный WG-сервер RouterOS;
//     ответы обфусцирует обратно по таблице сессий.
//   - client (1:1): принимает чистый WG от роутерного WG-интерфейса
//     (заворачивается на роутере dst-nat'ом), обфусцирует и шлёт на
//     реальный AWG-сервер; ответы деобфусцирует и возвращает.
package proxy

import (
	"context"
	"log/slog"

	"github.com/glebov/awg-proxy-go/internal/awg"
	"github.com/glebov/awg-proxy-go/internal/config"
	"github.com/glebov/awg-proxy-go/internal/router"
)

// Runner — единый интерфейс прокси, который запускает выбранный режим.
type Runner interface {
	Run(ctx context.Context) error
}

// New возвращает реализацию прокси под cfg.Mode.
func New(cfg *config.Config, poller *router.Poller, log *slog.Logger) Runner {
	params := awg.Params{
		H1: cfg.H1, H2: cfg.H2, H3: cfg.H3, H4: cfg.H4,
		S1: cfg.S1, S2: cfg.S2,
		Jc: cfg.Jc, Jmin: cfg.Jmin, Jmax: cfg.Jmax,
	}
	switch cfg.Mode {
	case config.ModeClient:
		return newClient(cfg, params, poller, log)
	default:
		return newServer(cfg, params, poller, log)
	}
}

const maxPacket = 65535
