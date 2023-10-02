package main

import (
	"crypto/tls"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/gorilla/mux"
)

type App struct {
	Jwks                *keyfunc.JWKS
	Cfg                 *Config
	TlS                 *tls.Config
	ServiceAccountToken string
	LabelStore          Labelstore
	i                   *mux.Router
	e                   *mux.Router
	healthy             bool
}

type Config struct {
	Log struct {
		Level     int  `mapstructure:"level"`
		LogTokens bool `mapstructure:"log_tokens"`
	} `mapstructure:"log"`

	Web struct {
		ProxyPort           int    `mapstructure:"proxy_port"`
		MetricsPort         int    `mapstructure:"metrics_port"`
		Host                string `mapstructure:"host"`
		InsecureSkipVerify  bool   `mapstructure:"insecure_skip_verify"`
		TrustedRootCaPath   string `mapstructure:"trusted_root_ca_path"`
		LabelStoreKind      string `mapstructure:"label_store_kind"`
		JwksCertURL         string `mapstructure:"jwks_cert_url"`
		OAuthGroupName      string `mapstructure:"oauth_group_name"`
		ServiceAccountToken string `mapstructure:"service_account_token"`
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
		URL          string            `mapstructure:"url"`
		TenantLabel  string            `mapstructure:"tenant_label"`
		UseMutualTLS bool              `mapstructure:"use_mutual_tls"`
		Cert         string            `mapstructure:"cert"`
		Key          string            `mapstructure:"key"`
		Header       map[string]string `mapstructure:"header"`
	} `mapstructure:"thanos"`
	Loki struct {
		URL          string            `mapstructure:"url"`
		TenantLabel  string            `mapstructure:"tenant_label"`
		UseMutualTLS bool              `mapstructure:"use_mutual_tls"`
		Cert         string            `mapstructure:"cert"`
		Key          string            `mapstructure:"key"`
		Header       map[string]string `mapstructure:"header"`
	} `mapstructure:"loki"`
}
