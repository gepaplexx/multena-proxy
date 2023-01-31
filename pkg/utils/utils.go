package utils

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var (
	Logger              *zap.Logger
	ClientSet           *kubernetes.Clientset
	ServiceAccountToken string
	Jwks                *keyfunc.JWKS
)

func InitializeLogger() {
	rawJSON := []byte(`{
		"level": "` + strings.ToLower(os.Getenv("LOG_LEVEL")) + `",
		"encoding": "json",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stderr"],
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
	Logger := zap.Must(cfg.Build())

	Logger.Info("logger construction succeeded")
}

func LogPanic(msg string, err error) {
	if err != nil {
		Logger.Panic(msg, zap.String("error", err.Error()))
	}
}

func LogError(msg string, err error) {
	if err != nil {
		Logger.Error(msg, zap.String("error", err.Error()))
	}
}

func InitKubeClient() {
	Logger.Info("Init Kubernetes Client")
	sa, err := os.ReadFile("/run/secrets/kubernetes.io/serviceaccount/token")
	LogPanic("Failed to read service account token", err)
	ServiceAccountToken = string(sa)
	if os.Getenv("DEV") == "true" {
		Logger.Info("Init Kubernetes Client with local kubeconfig")
		var kubeconfig *string
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
		flag.Parse()

		config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
		LogPanic("Kubeconfig error", err)
		ClientSet, err = kubernetes.NewForConfig(config)
		LogPanic("Kubeconfig error", err)
	} else {
		Logger.Info("Init Kubernetes Client with in cluster config")
		// creates the in-cluster config
		config, err := rest.InClusterConfig()
		LogPanic("Kubeconfig error", err)
		// creates the clientset
		ClientSet, err = kubernetes.NewForConfig(config)
		LogPanic("Kubeconfig error", err)
	}
	Logger.Info("Kubeconfig", zap.String("config", fmt.Sprintf("%+v", ClientSet)))
	Logger.Info("Finished Kubernetes Client")
}

func InitJWKS() {
	Logger.Info("Init Keycloak config")
	jwksURL := os.Getenv("KEYCLOAK_CERT_URL")

	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			LogError("There was an error with the jwt.Keyfunc", err)
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	// Create the JWKS from the resource at the given URL.
	err := error(nil)
	Jwks, err = keyfunc.Get(jwksURL, options)
	LogPanic("Failed to create JWKS from resource at the given URL.", err)
	Logger.Info("Finished Keycloak config")
}
