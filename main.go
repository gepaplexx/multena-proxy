package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"runtime"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"

	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/slok/go-http-metrics/middleware/std"
)

type App struct {
	Jwks                *keyfunc.JWKS
	Cfg                 *Config
	TlS                 *tls.Config
	ServiceAccountToken string
	LabelStore          Labelstore
	i                   *mux.Router
	e                   *mux.Router
	healthy             bool
}

var Commit string

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	log.Info().Msg("-------Init Proxy-------")
	log.Info().Msgf("Commit: %s", Commit)
	log.Debug().Str("go_version", runtime.Version()).Msg("")
	log.Debug().Str("go_os", runtime.GOOS).Str("go_arch", runtime.GOARCH).Msg("")
	log.Debug().Str("go_compiler", runtime.Compiler).Msg("")

	app := App{}
	app.WithConfig().
		WithSAT().
		WithTLSConfig().
		WithJWKS().
		WithLabelStore().
		WithHealthz().
		WithRoutes().
		StartServer()

	log.Info().Any("config", app.Cfg)
	log.Info().Msg("------Init Complete------")
	select {}
}

// StartServer starts the HTTP server for the proxy and metrics.
func (a *App) StartServer() {
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", a.Cfg.Web.Host, a.Cfg.Web.MetricsPort), a.i); err != nil {
			log.Fatal().Err(err).Msg("Error while serving metrics")
		}
	}()

	go func() {
		mdlw := middleware.New(middleware.Config{
			Recorder: metrics.NewRecorder(metrics.Config{}),
			Service:  "multena",
		})

		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", a.Cfg.Web.Host, a.Cfg.Web.ProxyPort), std.Handler("/", mdlw, a.e)); err != nil {
			log.Fatal().Err(err).Msg("Error while serving proxy")
		}
	}()
}
