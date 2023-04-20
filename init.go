package main

import (
	"crypto/tls"
	"crypto/x509"
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
	DB                  *sql.DB
	Jwks                *keyfunc.JWKS
	ServiceAccountToken string
	Logger              *zap.Logger
	C                   *Cfg
	V                   *viper.Viper
)

func init() {
	InitConfig()
	InitLogging()
}

func doInit() {
	Logger.Info("-------Init Proxy-------")
	Logger.Info("Set http client to ignore self signed certificates")
	Logger.Info("Config ", zap.Any("cfg", C))
	ServiceAccountToken = C.Dev.ServiceAccountToken
	if !C.Dev.Enabled {
		sa, err := os.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			Logger.Panic("Error while reading service account token", zap.Error(err))
		}
		ServiceAccountToken = string(sa)
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return nil
	}}
	InitJWKS()

	if C.Db.Enabled {
		InitDB()
	}
	Logger.Info("------Init Complete------")
}

func InitConfig() {
	C = &Cfg{}
	V = viper.NewWithOptions(viper.KeyDelimiter("::"))
	loadConfig("config")
	loadConfig("users")
	loadConfig("groups")
}

func onConfigChange(e fsnotify.Event) {
	//Todo: change log level on reload
	C = &Cfg{}
	configs := []string{"config", "users", "groups"}
	for _, name := range configs {
		V.SetConfigName(name) // name of config file (without extension)
		err := V.MergeInConfig()
		err = V.Unmarshal(C)
		if err != nil { // Handle errors reading the config file
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
	}
	fmt.Printf("{\"level\":\"info\",\"config\":\"%+v/\"}", C)
	fmt.Printf("{\"level\":\"info\",\"message\":\"Config file changed: %s/\"}", e.Name)
}

func loadConfig(configName string) {
	V.SetConfigName(configName) // name of config file (without extension)
	V.SetConfigType("yaml")
	fmt.Printf("{\"level\":\"info\",\"message\":\"Looking for config in /etc/config/%s/\"}\n", configName)
	V.AddConfigPath(fmt.Sprintf("/etc/config/%s/", configName))
	V.AddConfigPath("./configs")
	err := V.MergeInConfig() // Find and read the config file
	if V.GetInt("version") == 2 {
		fmt.Println("{\"level\":\"info\",\"message\":\"Using v2 config\"}")
	} else {
		fmt.Println("{\"level\":\"error\",\"message\":\"Unsupported config version\"}")
		panic("Unsupported config version")
	}
	err = V.Unmarshal(C)
	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	V.OnConfigChange(onConfigChange)
	V.WatchConfig()
}

// InitLogging initializes the logger
// The log level is set in the config file
// The log level can be set to debug, info, warn, error, dpanic, panic, or fatal
func InitLogging() *zap.Logger {
	rawJSON := []byte(`{
		"level": "` + strings.ToLower(C.Proxy.LogLevel) + `",
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
	Logger.Debug("Config", zap.Any("cfg", C))
	return Logger
}

func InitJWKS() {
	Logger.Info("Init Keycloak config")
	jwksURL := C.Proxy.JwksCertURL

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

func InitDB() {
	if C.Db.Enabled {
		password, err := os.ReadFile(C.Db.PasswordPath)
		if err != nil {
			Logger.Panic("Could not read db password", zap.Error(err))
		}
		cfg := mysql.Config{
			User:                 C.Db.User,
			Passwd:               string(password),
			Net:                  "tcp",
			AllowNativePasswords: true,
			Addr:                 C.Db.Host + ":" + fmt.Sprint(C.Db.Port),
			DBName:               C.Db.DbName,
		}
		// Get a database handle.
		DB, err = sql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			Logger.Panic("Error opening DB connection", zap.Error(err))
		}
	}
}
