package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/slok/go-http-metrics/middleware/std"
	"go.uber.org/zap"
)

var Commit string

type App struct {
	Jwks                *keyfunc.JWKS
	Cfg                 *Config
	Tls                 *tls.Config
	ServiceAccountToken string
	LabelStore          Labelstore
}

type Config struct {
	Log struct {
		Level     string `mapstructure:"level"`
		LogTokens bool   `mapstructure:"log_tokens"`
	} `mapstructure:"log"`

	LabelStore struct {
		typ string `mapstructure:"type"`
	} `mapstructure:"labelstore"`

	Web struct {
		ProxyPort              int    `mapstructure:"proxy_port"`
		MetricsPort            int    `mapstructure:"metrics_port"`
		Host                   string `mapstructure:"host"`
		InsecureSkipVerify     bool   `mapstructure:"insecure_skip_verify"`
		TrustedRootCaPath      string `mapstructure:"trusted_root_ca_path"`
		JwksCertURL            string `mapstructure:"jwks_cert_url"`
		KeycloakTokenGroupName string `mapstructure:"keycloak_token_group_name"`
		ServiceAccountToken    string `mapstructure:"service_account_token"`
	} `mapstructure:"web"`

	Admin struct {
		Bypass bool   `mapstructure:"bypass"`
		Group  string `mapstructure:"group"`
	} `mapstructure:"admin"`

	Dev struct {
		Enabled  bool   `mapstructure:"enabled"`
		Username string `mapstructure:"username"`
	} `mapstructure:"dev"`

	Db struct {
		Enabled      bool   `mapstructure:"enabled"`
		User         string `mapstructure:"user"`
		PasswordPath string `mapstructure:"password_path"`
		Host         string `mapstructure:"host"`
		Port         int    `mapstructure:"port"`
		DbName       string `mapstructure:"dbName"`
		Query        string `mapstructure:"query"`
		TokenKey     string `mapstructure:"token_key"`
	} `mapstructure:"db"`

	Thanos struct {
		URL          string `mapstructure:"url"`
		TenantLabel  string `mapstructure:"tenant_label"`
		UseMutualTLS bool   `mapstructure:"use_mutual_tls"`
		Cert         string `mapstructure:"cert"`
		Key          string `mapstructure:"key"`
	} `mapstructure:"thanos"`
	Loki struct {
		URL          string `mapstructure:"url"`
		TenantLabel  string `mapstructure:"tenant_label"`
		UseMutualTLS bool   `mapstructure:"use_mutual_tls"`
		Cert         string `mapstructure:"cert"`
		Key          string `mapstructure:"key"`
	} `mapstructure:"loki"`
}

func main() {
	defer func(Logger *zap.Logger) {
		err := Logger.Sync()
		if err != nil {
			fmt.Printf("{\"level\":\"error\",\"error\":\"%s/\"}", err)
			return
		}
	}(Logger)

	Logger.Info("-------Init Proxy-------")
	Logger.Info("Commit: ", zap.String("commit", Commit))

	app := App{}
	app.WithConfig()
	Logger.Info("Config ", zap.Any("cfg", app.Cfg))
	app.UpdateLogLevel()
	app.NewTLSConfig()
	app.WithJWKS()
	e, i, err := app.NewRoutes()

	Logger.Info("Config ", zap.Any("cfg", app.Cfg))
	Logger.Info("------Init Complete------")

	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", app.Cfg.Web.Host, app.Cfg.Web.MetricsPort), i); err != nil {
			Logger.Panic("Error while serving metrics", zap.Error(err))
		}
	}()

	if err != nil {
		Logger.Panic("Error while initializing application", zap.Error(err))
	}

	mdlw := middleware.New(middleware.Config{
		Recorder: metrics.NewRecorder(metrics.Config{}),
		Service:  "multena",
	})
	err = http.ListenAndServe(fmt.Sprintf("%s:%d", app.Cfg.Web.Host, app.Cfg.Web.ProxyPort),
		std.Handler("/", mdlw, e))

	if err != nil {
		Logger.Panic("Error while serving", zap.Error(err))
	}
}

func (a *App) WithConfig() {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/config/labels/")
	v.AddConfigPath("./configs")
	err := v.MergeInConfig()
	if err != nil {
		return
	}
	a.Cfg = &Config{}
	err = v.Unmarshal(a.Cfg)
	if err != nil {
		Logger.Panic("Error while unmarshalling config file", zap.Error(err))
	}
	v.OnConfigChange(func(e fsnotify.Event) {
		Logger.Info("Config file changed", zap.String("file", e.Name))
		err := v.Unmarshal(a.Cfg)
		if err != nil {
			Logger.Panic("Error while unmarshalling config file", zap.Error(err))
		}
	})
	if err != nil { // Handle errors reading the config file
		Logger.Panic("Error while unmarshalling config file", zap.Error(err))
	}
	v.WatchConfig()
}

func (a *App) ReadServerAccountToken() {
	sa, err := os.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		Logger.Panic("Error while reading service account token", zap.Error(err))
	}
	a.Cfg.Web.ServiceAccountToken = string(sa)
}

func (a *App) NewTLSConfig() {
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
				Logger.Error("Error while reading trusted CA", zap.Error(err))
				return err
			}
			Logger.Debug("Adding trusted CA", zap.String("path", path))
			certs = append(certs, []byte("\n")...)
			rootCAs.AppendCertsFromPEM(certs)

			return nil
		})
		if err != nil {
			Logger.Error("Error while traversing directory", zap.Error(err))
		}
	}

	var certificates []tls.Certificate

	lokiCert, err := tls.LoadX509KeyPair(a.Cfg.Loki.Cert, a.Cfg.Loki.Key)
	if err != nil {
		Logger.Error("Error while loading loki certificate", zap.Error(err))
	} else {
		Logger.Debug("Adding Loki certificate", zap.String("path", a.Cfg.Loki.Cert))
		certificates = append(certificates, lokiCert)
	}

	thanosCert, err := tls.LoadX509KeyPair(a.Cfg.Thanos.Cert, a.Cfg.Thanos.Key)
	if err != nil {
		Logger.Error("Error while loading thanos certificate", zap.Error(err))
	} else {
		Logger.Debug("Adding Thanos certificate", zap.String("path", a.Cfg.Loki.Cert))
		certificates = append(certificates, thanosCert)
	}

	config := &tls.Config{
		InsecureSkipVerify: a.Cfg.Web.InsecureSkipVerify,
		RootCAs:            rootCAs,
		Certificates:       certificates,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = config
}

func (a *App) WithJWKS() {
	Logger.Info("Init Keycloak config")
	jwksURL := a.Cfg.Web.JwksCertURL
	Logger.Info("JWKS URL", zap.String("url", jwksURL))

	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			if err != nil {
				Logger.Error("Error serving Keyfunc", zap.Error(err))
			}
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		Logger.Panic("Error init jwks", zap.Error(err))
	}
	Logger.Info("Finished Keycloak config")
	a.Jwks = jwks
}
