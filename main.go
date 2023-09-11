package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/slok/go-http-metrics/middleware/std"
)

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
		logConfig().
		WithSAT().
		WithTLSConfig().
		WithJWKS().
		WithLabelStore().
		WithRoutes().
		WithHealthz().
		WithThanos().
		WithLoki().
		StartServer()

	log.Info().Any("config", app.Cfg)
	log.Info().Msg("------Init Complete------")
	select {}
}

func (a *App) WithConfig() *App {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/config/config/")
	v.AddConfigPath("./configs")
	err := v.MergeInConfig()
	if err != nil {
		return nil
	}
	a.Cfg = &Config{}
	err = v.Unmarshal(a.Cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Error while unmarshalling config file")
	}
	v.OnConfigChange(func(e fsnotify.Event) {
		log.Info().Str("file", e.Name).Msg("Config file changed")
		err := v.Unmarshal(a.Cfg)
		if err != nil {
			log.Error().Err(err).Msg("Error while unmarshalling config file")
			a.healthy = false
		}
		zerolog.SetGlobalLevel(zerolog.Level(a.Cfg.Log.Level))
	})
	v.WatchConfig()
	zerolog.SetGlobalLevel(zerolog.Level(a.Cfg.Log.Level))
	return a
}

func (a *App) WithSAT() *App {
	if a.Cfg.Dev.Enabled {
		a.ServiceAccountToken = a.Cfg.Web.ServiceAccountToken
		return a
	}
	sa, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Fatal().Err(err).Msg("Error while reading service account token")
	}
	a.ServiceAccountToken = string(sa)
	return a
}

func (a *App) WithTLSConfig() *App {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if a.Cfg.Web.TrustedRootCaPath != "" {
		err := filepath.Walk(a.Cfg.Web.TrustedRootCaPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || strings.Contains(info.Name(), "..") {
				return nil
			}

			certs, err := os.ReadFile(path)
			if err != nil {
				log.Error().Err(err).Msg("Error while reading trusted CA")
				return err
			}
			log.Debug().Str("path", path).Msg("Adding trusted CA")
			certs = append(certs, []byte("\n")...)
			rootCAs.AppendCertsFromPEM(certs)

			return nil
		})
		if err != nil {
			log.Error().Err(err).Msg("Error while traversing directory")
		}
	}

	var certificates []tls.Certificate

	lokiCert, err := tls.LoadX509KeyPair(a.Cfg.Loki.Cert, a.Cfg.Loki.Key)
	if err != nil {
		log.Error().Err(err).Msg("Error while loading loki certificate")
	} else {
		log.Debug().Str("path", a.Cfg.Loki.Cert).Msg("Adding Loki certificate")
		certificates = append(certificates, lokiCert)
	}

	thanosCert, err := tls.LoadX509KeyPair(a.Cfg.Thanos.Cert, a.Cfg.Thanos.Key)
	if err != nil {
		log.Error().Err(err).Msg("Error while loading thanos certificate")
	} else {
		log.Debug().Str("path", a.Cfg.Thanos.Cert).Msg("Adding Thanos certificate")
		certificates = append(certificates, thanosCert)
	}

	config := &tls.Config{
		InsecureSkipVerify: a.Cfg.Web.InsecureSkipVerify,
		RootCAs:            rootCAs,
		Certificates:       certificates,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = config
	return a
}

func (a *App) WithJWKS() *App {
	log.Info().Msg("Init Keycloak config")
	jwksURL := a.Cfg.Web.JwksCertURL
	log.Info().Str("url", jwksURL).Msg("JWKS URL")

	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			if err != nil {
				log.Error().Err(err).Msg("Error refreshing Keyfunc")
			}
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		log.Fatal().Err(err).Msg("Error init jwks")
	}
	log.Info().Msg("Finished Keycloak config")
	a.Jwks = jwks
	return a
}

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
