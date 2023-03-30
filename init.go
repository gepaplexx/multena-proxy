package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/fsnotify/fsnotify"
	"github.com/go-sql-driver/mysql"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	DB                  *sql.DB
	Jwks                *keyfunc.JWKS
	ClientSet           *kubernetes.Clientset
	ServiceAccountToken string
	Logger              *zap.Logger
	C                   *Cfg
	V                   *viper.Viper
)

func doInit() {

	InitConfig()
	InitLogging()
	Logger.Info("Init Proxy")
	Logger.Info("Set http client to ignore self signed certificates")
	Logger.Info("Config ", zap.Any("cfg", C))

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	InitJWKS()
	InitKubeClient()
	InitDB()
	Logger.Info("Init Complete")
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
	fmt.Printf("%+v", C)
	fmt.Println("Config file changed:", e.Name)

}

func loadConfig(configName string) {
	V.SetConfigName(configName) // name of config file (without extension)
	V.SetConfigType("yaml")
	fmt.Println("Looking for config in", fmt.Sprintf("/etc/config/%s/", configName)) // REQUIRED if the config file does not have the extension in the name
	V.AddConfigPath(fmt.Sprintf("/etc/config/%s/", configName))                      // path to look for the config file in
	V.AddConfigPath("./configs")
	err := V.MergeInConfig() // Find and read the config file
	if V.GetInt("version") == 1 {
		fmt.Println("Using v1 config")
	} else {
		fmt.Println("Supported versions: 1")
		panic("Unsupported config version")
	}
	err = V.Unmarshal(C)
	fmt.Printf("%+v", C)
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
	return Logger
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

func CloseDB() {
	Logger.Panic("error while serving", zap.Error(DB.Close()))
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

func InitKubeClient() {
	Logger.Info("Init Kubernetes Client")

	if C.Dev.Enabled {
		Logger.Info("Init Kubernetes Client with local kubeconfig")
		ServiceAccountToken = C.Dev.ServiceAccountToken

		var kubeconfig *string
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
		flag.Parse()

		err := error(nil)
		Config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			Logger.Panic("Error building config from kubeconfig", zap.Error(err))
		}

		ClientSet, err = kubernetes.NewForConfig(Config)
		if err != nil {
			Logger.Panic("Error init kubeconfig", zap.Error(err))
		}

	} else {
		sa, err := os.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			Logger.Panic("Failed to read service account token", zap.Error(err))
		}
		ServiceAccountToken = string(sa)

		Logger.Info("Init Kubernetes Client with in cluster config")
		// creates the in-cluster config
		config, err := rest.InClusterConfig()
		if err != nil {
			Logger.Panic("Error while creating inClusterConfig", zap.Error(err))
		}
		// creates the clientset
		ClientSet, err = kubernetes.NewForConfig(config)
		if err != nil {
			Logger.Panic("Error init kubeconfig", zap.Error(err))
		}
	}
	Logger.Info("Kubeconfig", zap.Any("config", ClientSet))
	Logger.Info("Finished Kubernetes Client")
}
