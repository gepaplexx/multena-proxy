package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/fsnotify/fsnotify"
	"github.com/go-sql-driver/mysql"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Commit              string
	DB                  *sql.DB
	Jwks                *keyfunc.JWKS
	ServiceAccountToken string
	Logger              *zap.Logger
	Cfg                 *Config
	V                   *viper.Viper
	GetLabelsFunc       func(token KeycloakToken) map[string]bool
	atomicLevel         zap.AtomicLevel
)

type Config struct {
	Log struct {
		Level     string `mapstructure:"level"`
		LogTokens bool   `mapstructure:"log_tokens"`
	} `mapstructure:"log"`

	TenantProvider string `mapstructure:"tenant_provider"`

	Web struct {
		ProxyPort          int    `mapstructure:"proxy_port"`
		MetricsPort        int    `mapstructure:"metrics_port"`
		Host               string `mapstructure:"host"`
		InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
		TrustedRootCaPath  string `mapstructure:"trusted_root_ca_path"`
		JwksCertURL        string `mapstructure:"jwks_cert_url"`
	} `mapstructure:"web"`

	Admin struct {
		Bypass bool   `mapstructure:"bypass"`
		Group  string `mapstructure:"group"`
	} `mapstructure:"admin"`

	Dev struct {
		Enabled             bool   `mapstructure:"enabled"`
		Username            string `mapstructure:"username"`
		ServiceAccountToken string `mapstructure:"service_account_token"`
	} `mapstructure:"dev"`

	Db struct {
		Enabled      bool   `mapstructure:"enabled"`
		User         string `mapstructure:"user"`
		PasswordPath string `mapstructure:"password_path"`
		Host         string `mapstructure:"host"`
		Port         int    `mapstructure:"port"`
		DbName       string `mapstructure:"dbName"`
		Query        string `mapstructure:"query"`
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

	Users  map[string][]string `mapstructure:"users"`
	Groups map[string][]string `mapstructure:"groups"`
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

	if Cfg.Db.Enabled {
		initDB()
	}

	if Cfg.TenantProvider == "configmap" {
		GetLabelsFunc = GetLabelsCM
	}
	if Cfg.TenantProvider == "mysql" {
		GetLabelsFunc = GetLabelsDB
	}
	if GetLabelsFunc == nil {
		Logger.Panic("Tenant provider not supported")
	}

	Logger.Info("------Init Complete------")
}

// initConfig initializes the configuration object (Cfg) and sets up the viper object (V) with the correct
// configuration files and paths. It loads the necessary configuration files based on the tenant provider setting.
func initConfig() {
	Cfg = &Config{}
	V = viper.NewWithOptions(viper.KeyDelimiter("::"))
	loadConfig("config")
	if Cfg.TenantProvider == "configmap" {
		loadConfig("labels")
	}
}

// onConfigChange is a callback function that reloads the configuration when any changes are detected in the
// configuration files. It also triggers updating of services such as JWKS and logging levels based on the new
// configuration.
func onConfigChange(e fsnotify.Event) {
	// Todo: change log level on reload
	Cfg = &Config{}
	var configs []string
	if Cfg.TenantProvider == "configmap" {
		configs = []string{"config", "labels"}
	} else {
		configs = []string{"config"}
	}

	for _, name := range configs {
		V.SetConfigName(name) // name of config file (without extension)
		err := V.MergeInConfig()
		if err != nil { // Handle errors reading the config file
			Logger.Panic("Error while reading config file", zap.Error(err))
		}
		err = V.Unmarshal(Cfg)
		if err != nil { // Handle errors reading the config file
			Logger.Panic("Error while unmarshalling config file", zap.Error(err))
		}
	}
	Logger.Info("Config reloaded", zap.Any("config", Cfg))
	Logger.Info("Config file changed", zap.String("file", e.Name))
	updateLogLevel()
	initTLSConfig()
	initJWKS()
}

// loadConfig reads in a configuration file of a given name and merges it with existing configuration.
// It also sets up a watch on the configuration file for any changes.
func loadConfig(configName string) {
	V.SetConfigName(configName) // name of config file (without extension)
	V.SetConfigType("yaml")
	Logger.Info("Looking for config in /etc/config/", zap.String("configName", configName))
	V.AddConfigPath(fmt.Sprintf("/etc/config/%s/", configName))
	V.AddConfigPath("./configs")
	err := V.MergeInConfig() // Find and read the config file
	if err != nil {          // Handle errors reading the config file
		Logger.Panic("Error while reading config file", zap.Error(err))
	}
	err = V.Unmarshal(Cfg)
	if err != nil { // Handle errors reading the config file
		Logger.Panic("Error while unmarshalling config file", zap.Error(err))
	}
	V.OnConfigChange(onConfigChange)
	V.WatchConfig()
}

// initLogging sets up the global logging object (Logger) with the specified logging level and configuration.
// It returns the Logger object.
func initLogging() *zap.Logger {
	atomicLevel = zap.NewAtomicLevel()
	atomicLevel.SetLevel(getZapLevel("info"))

	rawJSON := []byte(`{
		"level": "info",
		"encoding": "json",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stdout"],
		"encoderConfig": {
		  "messageKey": "msg",
		  "levelKey": "level",
		  "levelEncoder": "lowercase"
		}
	  }`)

	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}
	cfg.Level = atomicLevel
	Logger = zap.Must(cfg.Build())

	Logger.Debug("logger construction succeeded")
	Logger.Debug("Go Version", zap.String("version", runtime.Version()))
	Logger.Debug("Go OS/Arch", zap.String("os", runtime.GOOS), zap.String("arch", runtime.GOARCH))
	Logger.Debug("Config", zap.Any("cfg", Cfg))
	return Logger
}

// getZapLevel translates a string representation of a logging level into a zapcore.Level.
func getZapLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	default: // unknown level or not set, default to info
		return zapcore.InfoLevel
	}
}

// updateLogLevel updates the global logging level based on the logging level specified in the configuration.
func updateLogLevel() {
	atomicLevel.SetLevel(getZapLevel(strings.ToLower(Cfg.Log.Level)))
}

// initTLSConfig sets up the global HTTP client's TLS configuration. This includes adding trusted CAs and
// client certificates from the configuration and handling self-signed certificates.
func initTLSConfig() {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if Cfg.Web.TrustedRootCaPath != "" {
		err := filepath.Walk(Cfg.Web.TrustedRootCaPath, func(path string, info os.FileInfo, err error) error {
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

	lokiCert, err := tls.LoadX509KeyPair(Cfg.Loki.Cert, Cfg.Loki.Key)
	if err != nil {
		Logger.Error("Error while loading loki certificate", zap.Error(err))
	} else {
		Logger.Debug("Adding Loki certificate", zap.String("path", Cfg.Loki.Cert))
		certificates = append(certificates, lokiCert)
	}

	thanosCert, err := tls.LoadX509KeyPair(Cfg.Thanos.Cert, Cfg.Thanos.Key)
	if err != nil {
		Logger.Error("Error while loading thanos certificate", zap.Error(err))
	} else {
		Logger.Debug("Adding Thanos certificate", zap.String("path", Cfg.Loki.Cert))
		certificates = append(certificates, thanosCert)
	}

	config := &tls.Config{
		InsecureSkipVerify: Cfg.Web.InsecureSkipVerify,
		RootCAs:            rootCAs,
		Certificates:       certificates,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = config
}

// initJWKS sets up the JWKS service for validating JWT tokens. It uses the JWKS endpoint specified in the configuration.
func initJWKS() {
	Logger.Info("Init Keycloak config")
	jwksURL := Cfg.Web.JwksCertURL

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

	// Create the JWKS from the resource at the given URL.
	err := error(nil)
	Jwks, err = keyfunc.Get(jwksURL, options)
	if err != nil {
		Logger.Panic("Error init jwks", zap.Error(err))
	}
	Logger.Info("Finished Keycloak config")
}

// initDB sets up a global database connection using the database configuration provided in the configuration file.
func initDB() {
	password, err := os.ReadFile(Cfg.Db.PasswordPath)
	if err != nil {
		Logger.Panic("Could not read db password", zap.Error(err))
	}
	cfg := mysql.Config{
		User:                 Cfg.Db.User,
		Passwd:               string(password),
		Net:                  "tcp",
		AllowNativePasswords: true,
		Addr:                 fmt.Sprintf("%s:%d", Cfg.Db.Host, Cfg.Db.Port),
		DBName:               Cfg.Db.DbName,
	}
	// Get a database handle.
	DB, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		Logger.Panic("Error opening DB connection", zap.Error(err))
	}
}
