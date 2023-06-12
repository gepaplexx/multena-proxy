package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/MicahParks/keyfunc/v2"
	"github.com/fsnotify/fsnotify"
	"github.com/go-sql-driver/mysql"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

var (
	Commit              string
	DB                  *sql.DB
	Jwks                *keyfunc.JWKS
	ServiceAccountToken string
	Logger              *zap.Logger
	Cfg                 *Config
	V                   *viper.Viper
)

// init carries out the main initialization routine for the Proxy. It logs the commit information,
// configures the HTTP client to ignore self-signed certificates, reads the service account token,
// initializes JWKS if not in development mode, and establishes a database connection if enabled in the config.
func init() {
	InitConfig()
	InitLogging()
	Logger.Info("-------Init Proxy-------")
	Logger.Info("Commit: ", zap.String("commit", Commit))
	Logger.Info("Set http client to ignore self signed certificates")
	Logger.Info("Config ", zap.Any("cfg", Cfg))
	ServiceAccountToken = Cfg.Dev.ServiceAccountToken
	if !strings.HasSuffix(os.Args[0], ".test") {
		fmt.Println("Not in test mode")
		InitJWKS()
		sa, err := os.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			Logger.Panic("Error while reading service account token", zap.Error(err))
		}
		ServiceAccountToken = string(sa)
	}

	if Cfg.Db.Enabled {
		InitDB()
	}

	if Cfg.Proxy.InsecureSkipVerify {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	Logger.Info("------Init Complete------")
}

// InitConfig initializes the configuration from the files `config` and `labels` using Viper.
func InitConfig() {
	Cfg = &Config{}
	V = viper.NewWithOptions(viper.KeyDelimiter("::"))
	loadConfig("config")
	loadConfig("labels")
}

// onConfigChange is a callback that gets triggered when a configuration file changes.
// It reloads the configuration from the files `config` and `labels`.
func onConfigChange(e fsnotify.Event) {
	//Todo: change log level on reload
	Cfg = &Config{}
	configs := []string{"config", "labels"}
	for _, name := range configs {
		V.SetConfigName(name) // name of config file (without extension)
		err := V.MergeInConfig()
		if err != nil { // Handle errors reading the config file
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
		err = V.Unmarshal(Cfg)
		if err != nil { // Handle errors reading the config file
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
	}
	fmt.Printf("{\"level\":\"info\",\"config\":\"%+v/\"}", Cfg)
	fmt.Printf("{\"level\":\"info\",\"message\":\"Config file changed: %s/\"}", e.Name)
}

// loadConfig loads the configuration from the specified file. It looks for the config file
// in the `/etc/config/` directory and the `./configs` directory.
func loadConfig(configName string) {
	V.SetConfigName(configName) // name of config file (without extension)
	V.SetConfigType("yaml")
	fmt.Printf("{\"level\":\"info\",\"message\":\"Looking for config in /etc/config/%s/\"}\n", configName)
	V.AddConfigPath(fmt.Sprintf("/etc/config/%s/", configName))
	V.AddConfigPath("./configs")
	err := V.MergeInConfig() // Find and read the config file
	if err != nil {          // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	err = V.Unmarshal(Cfg)
	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	V.OnConfigChange(onConfigChange)
	V.WatchConfig()
}

// InitLogging initializes the logger based on the log level specified in the config file.
func InitLogging() *zap.Logger {
	rawJSON := []byte(`{
		"level": "` + strings.ToLower(Cfg.Proxy.LogLevel) + `",
		"encoding": "json",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stdout"],
		"encoderConfig": {
		  "messageKey": "message",
		  "levelKey": "level",
		  "levelEncoder": "lowercase"
		}
	  }`)

	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}
	Logger = zap.Must(cfg.Build())

	Logger.Debug("logger construction succeeded")
	Logger.Debug("Go Version", zap.String("version", runtime.Version()))
	Logger.Debug("Go OS/Arch", zap.String("os", runtime.GOOS), zap.String("arch", runtime.GOARCH))
	Logger.Debug("Config", zap.Any("cfg", Cfg))
	return Logger
}

// InitJWKS initializes the JWKS (JSON Web Key Set) from a specified URL. It sets up the refresh parameters
// for the JWKS and handles any errors that occur during the refresh.
func InitJWKS() {
	Logger.Info("Init Keycloak config")
	jwksURL := Cfg.Proxy.JwksCertURL

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

// InitDB establishes a connection to the database if the `Db.Enabled` configuration setting is `true`.
// It reads the database password from a file, sets up the database connection configuration,
// and opens the database connection.
func InitDB() {
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
