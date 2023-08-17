package main

import (
	"context"
	"errors"
	"fmt"
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

func (a *App) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken, err := getBearerToken(r)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

		keycloakToken, token, err := parseJwtToken(authToken, a)
		if err != nil && !a.Cfg.Dev.Enabled {
			logAndWriteError(w, http.StatusForbidden, err, "error parsing Keycloak token\n")
			return
		}

		if !isValidToken(token, *a.Cfg) {
			logAndWriteError(w, http.StatusForbidden, nil, "invalid token")
			return
		}

		r = withSkipContext(r, isAdmin(keycloakToken, *a.Cfg))
		r = withKeyCloakContext(r, keycloakToken)
		next.ServeHTTP(w, r)
	})
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
	parseFunc := func(token *jwt.Token) (interface{}, error) {
		return nil, fmt.Errorf("unable to verify token")
	}

	if !a.Cfg.Dev.Enabled {
		parseFunc = a.Jwks.Keyfunc
	}

	token, err := jwt.ParseWithClaims(tokenString, &claimsMap, parseFunc)
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

func isAdmin(token KeycloakToken, cfg Config) bool {
	return ContainsIgnoreCase(token.Groups, cfg.Admin.Group) && cfg.Admin.Bypass
}

func withKeyCloakContext(r *http.Request, keycloakToken KeycloakToken) *http.Request {
	ctx := context.WithValue(r.Context(), KeycloakCtxToken, keycloakToken)
	return r.WithContext(ctx)
}

func withSkipContext(r *http.Request, skip bool) *http.Request {
	ctx := context.WithValue(r.Context(), SkipCtx, skip)
	return r.WithContext(ctx)
}
