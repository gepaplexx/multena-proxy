package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

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

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken, err := getBearerToken(r)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

		keycloakToken, token, err := parseJwtToken(authToken)
		if err != nil && !Cfg.Dev.Enabled {
			logAndWriteError(w, http.StatusForbidden, err, "error parsing Keycloak token\n")
			return
		}

		if !isValidToken(token) {
			logAndWriteError(w, http.StatusForbidden, nil, "invalid token")
			return
		}

		newReq := requestWithContext(r, keycloakToken)
		next.ServeHTTP(w, newReq)
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

// parseJwtToken parses a JWT token string into a Keycloak token and a JWT token. It returns an error if parsing fails.
func parseJwtToken(tokenString string) (KeycloakToken, *jwt.Token, error) {
	keycloakToken := KeycloakToken{}
	token, err := jwt.ParseWithClaims(tokenString, keycloakToken, func(token *jwt.Token) (interface{}, error) {
		return nil, fmt.Errorf("unable to verify token")
	})
	if !Cfg.Dev.Enabled {
		token, err = jwt.ParseWithClaims(tokenString, &keycloakToken, Jwks.Keyfunc)
	}
	return keycloakToken, token, err
}

// isValidToken checks whether a JWT token is valid or not.
func isValidToken(token *jwt.Token) bool {
	return token.Valid || Cfg.Dev.Enabled
}

// isAdmin checks if a user belongs to the admin group. It can bypass some checks for admin users.
func isAdmin(token KeycloakToken) bool {
	return (ContainsIgnoreCase(token.Groups, Cfg.Admin.Group) || ContainsIgnoreCase(token.ApaGroupsOrg, Cfg.Admin.Group)) && Cfg.Admin.Bypass
}

func requestWithContext(r *http.Request, keycloakToken KeycloakToken) *http.Request {
	ctx := context.WithValue(r.Context(), KeycloakCtxToken, keycloakToken)
	return r.WithContext(ctx)
}
