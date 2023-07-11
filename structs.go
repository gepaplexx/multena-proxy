package main

import "github.com/golang-jwt/jwt/v5"

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
		URL         string `mapstructure:"url"`
		TenantLabel string `mapstructure:"tenant_label"`
		Cert        string `mapstructure:"cert"`
		Key         string `mapstructure:"key"`
	} `mapstructure:"thanos"`
	Loki struct {
		URL         string `mapstructure:"url"`
		TenantLabel string `mapstructure:"tenant_label"`
		Cert        string `mapstructure:"cert"`
		Key         string `mapstructure:"key"`
	} `mapstructure:"loki"`

	Users  map[string][]string `mapstructure:"users"`
	Groups map[string][]string `mapstructure:"groups"`
}

type KeycloakToken struct {
	AuthTime       int      `json:"auth_time,omitempty"`
	SessionState   string   `json:"session_state"`
	Acr            string   `json:"acr"`
	AllowedOrigins []string `json:"allowed-origins"`
	RealmAccess    struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess struct {
		RealmManagement struct {
			Roles []string `json:"roles"`
		} `json:"realm-management"`
		Broker struct {
			Roles []string `json:"roles"`
		} `json:"broker"`
		Account struct {
			Roles []string `json:"roles"`
		} `json:"account"`
	} `json:"resource_access"`
	Scope             string   `json:"scope"`
	Sid               string   `json:"sid"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
	ApaGroupsOrg      []string `json:"apa/groups_org"`
	PreferredUsername string   `json:"preferred_username"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	Email             string   `json:"email"`
	jwt.RegisteredClaims
}
