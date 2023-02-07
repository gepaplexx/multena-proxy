package utils

import (
	"flag"
	"fmt"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"os"
	"path/filepath"
)

var (
	ServiceAccountToken string
)

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
