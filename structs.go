package main

import "github.com/golang-jwt/jwt/v5"

type Config struct {
	Dev struct {
		Enabled             bool   `mapstructure:"enabled"`
		Username            string `mapstructure:"username"`
		ServiceAccountToken string `mapstructure:"service_account_token"`
	} `mapstructure:"dev"`
	Proxy struct {
		LogLevel           string `mapstructure:"log_level"`
		Provider           string `mapstructure:"provider"`
		ThanosUrl          string `mapstructure:"thanos_url"`
		LokiUrl            string `mapstructure:"loki_url"`
		JwksCertURL        string `mapstructure:"jwks_cert_url"`
		AdminGroup         string `mapstructure:"admin_group"`
		InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
		LogTokens          bool   `mapstructure:"log_tokens"`
		Port               int    `mapstructure:"port"`
		MetricsPort        int    `mapstructure:"metrics_port"`
		Host               string `mapstructure:"host"`
		TenantLabels       struct {
			Thanos string `mapstructure:"thanos"`
			Loki   string `mapstructure:"loki"`
		} `mapstructure:"tenant_labels"`
	} `mapstructure:"proxy"`
	Db struct {
		Enabled      bool   `mapstructure:"enabled"`
		User         string `mapstructure:"user"`
		PasswordPath string `mapstructure:"password_path"`
		Host         string `mapstructure:"host"`
		Port         int    `mapstructure:"port"`
		DbName       string `mapstructure:"db_name"`
		Query        string `mapstructure:"query"`
	} `mapstructure:"db"`
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
