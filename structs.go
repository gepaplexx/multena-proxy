package main

import (
	jwt "github.com/golang-jwt/jwt/v4"
)

type TokenExchange struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	IssuedTokenType  string `json:"issued_token_type"`
	AccountLinkURL   string `json:"account-link-url"`
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
	PreferredUsername string   `json:"preferred_username"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	Email             string   `json:"email"`
	jwt.RegisteredClaims
}
