package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type KeycloakToken struct {
	Groups            []string `json:"-"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	jwt.RegisteredClaims
}

func getBearerToken(r *http.Request) (string, error) {
	authToken := r.Header.Get("Authorization")
	if authToken == "" {
		return "", errors.New("no Authorization header found")
	}
	splitToken := strings.Split(authToken, "Bearer")
	if len(splitToken) != 2 {
		return "", errors.New("invalid Authorization header")
	}
	return strings.TrimSpace(splitToken[1]), nil
}

func parseJwtToken(tokenString string, a *App) (KeycloakToken, *jwt.Token, error) {
	var keycloakToken KeycloakToken
	var claimsMap jwt.MapClaims

	token, err := jwt.ParseWithClaims(tokenString, &claimsMap, a.Jwks.Keyfunc)
	if err != nil {
		return keycloakToken, nil, err
	}

	if v, ok := claimsMap["preferred_username"].(string); ok {
		keycloakToken.PreferredUsername = v
	}
	if v, ok := claimsMap["email"].(string); ok {
		keycloakToken.Email = v
	}

	if v, ok := claimsMap[a.Cfg.Web.KeycloakTokenGroupName].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				keycloakToken.Groups = append(keycloakToken.Groups, s)
			}
		}
	}
	return keycloakToken, token, err
}

func isValidToken(token *jwt.Token, cfg Config) bool {
	return token.Valid || cfg.Dev.Enabled
}

func isAdmin(token KeycloakToken, a *App) bool {
	return ContainsIgnoreCase(token.Groups, a.Cfg.Admin.Group) && a.Cfg.Admin.Bypass
}
