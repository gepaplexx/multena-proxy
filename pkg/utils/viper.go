package utils

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type Cfg struct {
	Dev struct {
		Enabled             bool   `mapstructure:"enabled"`
		ServiceAccountToken string `mapstructure:"service_account_token"`
	} `mapstructure:"dev"`
	TokenExchange struct {
		Enabled      bool   `mapstructure:"enabled"`
		ClientSecret string `mapstructure:"client_secret"`
		URL          string `mapstructure:"url"`
	} `mapstructure:"token_exchange"`
	Proxy struct {
		Version           int    `mapstructure:"version"`
		LogLevel          string `mapstructure:"log_level"`
		Provider          string `mapstructure:"provider"`
		UpstreamURL       string `mapstructure:"upstream_url"`
		UpstreamBypassURL string `mapstructure:"upstream_bypass_url"`
		JwksCertURL       string `mapstructure:"jwks_cert_url"`
		TenantLabel       string `mapstructure:"tenant_label"`
		AdminGroup        string `mapstructure:"admin_group"`
	} `mapstructure:"proxy"`
	Db struct {
		Enabled      bool   `mapstructure:"enabled"`
		User         string `mapstructure:"user"`
		PasswordPath string `mapstructure:"password_path"`
		Host         string `mapstructure:"host"`
		Port         int    `mapstructure:"port"`
		DbName       string `mapstructure:"db_name"`
	} `mapstructure:"db"`
	Users map[string][]string `mapstructure:"users"`
}

var (
	C *Cfg
	V *viper.Viper
)

func InitViper() {
	C = &Cfg{}
	V = viper.New()
	V.SetConfigName("config")       // name of config file (without extension)
	V.SetConfigType("yaml")         // REQUIRED if the config file does not have the extension in the name
	V.AddConfigPath("/etc/config/") // path to look for the config file in
	V.AddConfigPath("./")
	err := V.ReadInConfig() // Find and read the config file
	if err != nil {         // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	V.OnConfigChange(func(e fsnotify.Event) {
		err = V.Unmarshal(C)
		if err != nil { // Handle errors reading the config file
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
		fmt.Println("Config file changed:", e.Name)
	})
	V.WatchConfig()
	V.SetConfigName("users")
	V.SetConfigType("yaml")
	V.AddConfigPath("/etc/config/")
	V.AddConfigPath("./")
	err = V.MergeInConfig()
	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	err = V.Unmarshal(C)
	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	V.OnConfigChange(func(e fsnotify.Event) {
		err = V.Unmarshal(C)
		if err != nil { // Handle errors reading the config file
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
		fmt.Println("Config file changed:", e.Name)
	})
	V.WatchConfig()
}
