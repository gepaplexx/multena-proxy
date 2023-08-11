package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"github.com/gepaplexx/multena-proxy/log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type App struct {
	Jwks                *keyfunc.JWKS
	Db                  *sql.DB
	Cfg                 *Config
	Tls                 *tls.Config
	ServiceAccountToken string
}

var Commit string

//var Logger *zap.Logger

type Config struct {
	Log struct {
		Level     string `mapstructure:"level"`
		LogTokens bool   `mapstructure:"log_tokens"`
	} `mapstructure:"log"`

	TenantProvider string `mapstructure:"tenant_provider"`

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

// init is an in-built function that gets called before the main function. It performs initializations needed
// for the service such as initializing logging, loading configuration, and setting up services like JWKS
// and database based on the loaded configuration.
func init() {
	initLogging()
	initConfig()
	updateLogLevel()
	Logger.Info("-------Init Proxy-------")
	Logger.Info("Commit: ", zap.String("commit", Commit))
	Logger.Info("Set http client to ignore self signed certificates")
	Logger.Info("Config ", zap.Any("cfg", Cfg))
	initTLSConfig()
	ServiceAccountToken = Cfg.Dev.ServiceAccountToken
	if !strings.HasSuffix(os.Args[0], ".test") {
		Logger.Debug("Not in test mode")
		initJWKS()
		if !Cfg.Dev.Enabled {
			sa, err := os.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")
			if err != nil {
				Logger.Panic("Error while reading service account token", zap.Error(err))
			}
			ServiceAccountToken = string(sa)
		}
	} else {
		if Cfg.Dev.Enabled {
			panic("Dev mode is not supported in test mode")
		}
	}
	log.L.Info("------Init Complete------")
}

func (a *App) NewApp() {
	a.NewConfig()
	a.NewTLSConfig()
	a.NewJWKS()
}

func (a *App) NewConfig() {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/config/labels/")
	v.AddConfigPath("./configs")
	err := v.Unmarshal(a.Cfg)
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
				logger.Error("Error while reading trusted CA", zap.Error(err))
				return err
			}
			logger.Debug("Adding trusted CA", zap.String("path", path))
			certs = append(certs, []byte("\n")...)
			rootCAs.AppendCertsFromPEM(certs)

			return nil
		})
		if err != nil {
			logger.Error("Error while traversing directory", zap.Error(err))
		}
	}

	var certificates []tls.Certificate

	lokiCert, err := tls.LoadX509KeyPair(a.Cfg.Loki.Cert, a.Cfg.Loki.Key)
	if err != nil {
		logger.Error("Error while loading loki certificate", zap.Error(err))
	} else {
		logger.Debug("Adding Loki certificate", zap.String("path", a.Cfg.Loki.Cert))
		certificates = append(certificates, lokiCert)
	}

	thanosCert, err := tls.LoadX509KeyPair(a.Cfg.Thanos.Cert, a.Cfg.Thanos.Key)
	if err != nil {
		logger.Error("Error while loading thanos certificate", zap.Error(err))
	} else {
		logger.Debug("Adding Thanos certificate", zap.String("path", a.Cfg.Loki.Cert))
		certificates = append(certificates, thanosCert)
	}

	config := &tls.Config{
		InsecureSkipVerify: a.Cfg.Web.InsecureSkipVerify,
		RootCAs:            rootCAs,
		Certificates:       certificates,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = config
}

func (a *App) NewJWKS() {
	logger.Info("Init Keycloak config")
	jwksURL := a.Cfg.Web.JwksCertURL

	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			if err != nil {
				logger.Error("Error serving Keyfunc", zap.Error(err))
			}
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		logger.Panic("Error init jwks", zap.Error(err))
	}
	logger.Info("Finished Keycloak config")
	a.Jwks = jwks
}
