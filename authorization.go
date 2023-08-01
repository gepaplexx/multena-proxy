package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

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
	ctx := context.WithValue(r.Context(), kkToken{}, keycloakToken)
	return r.WithContext(ctx)
}
