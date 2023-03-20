package utils

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type Cfg struct {
	Version int `mapstructure:"version"`
	Dev     struct {
		Enabled             bool   `mapstructure:"enabled"`
		ServiceAccountToken string `mapstructure:"service_account_token"`
	} `mapstructure:"dev"`
	Proxy struct {
		LogLevel          string `mapstructure:"log_level"`
		Provider          string `mapstructure:"provider"`
		UpstreamURL       string `mapstructure:"upstream_url"`
		UpstreamBypassURL string `mapstructure:"upstream_bypass_url"`
		JwksCertURL       string `mapstructure:"jwks_cert_url"`
		TenantLabel       string `mapstructure:"tenant_label"`
		AdminGroup        string `mapstructure:"admin_group"`
		Port              int    `mapstructure:"port"`
	} `mapstructure:"proxy"`
	Db struct {
		Enabled      bool   `mapstructure:"enabled"`
		User         string `mapstructure:"user"`
		PasswordPath string `mapstructure:"password_path"`
		Host         string `mapstructure:"host"`
		Port         int    `mapstructure:"port"`
		DbName       string `mapstructure:"db_name"`
	} `mapstructure:"db"`
	Users  map[string][]string `mapstructure:"users"`
	Groups map[string][]string `mapstructure:"groups"`
}

var (
	C *Cfg
	V *viper.Viper
)

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
	V.SetConfigName(configName)     // name of config file (without extension)
	V.SetConfigType("yaml")         // REQUIRED if the config file does not have the extension in the name
	V.AddConfigPath("/etc/config/") // path to look for the config file in
	V.AddConfigPath("./")
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

func InitViper() {
	C = &Cfg{}
	V = viper.New()
	loadConfig("config")
	loadConfig("users")
	loadConfig("groups")
}
