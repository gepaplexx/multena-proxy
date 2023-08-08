package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// KeycloakToken struct represents the structure of a Keycloak JWT token. It holds
// the various details associated with a user.
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

// authMiddleware function is a special function that checks the requestor's ticket (authToken)
// before allowing them to enter the server. If the ticket isn't valid, they are not allowed in.
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

// getBearerToken function checks for a special 'Authorization' ticket in the request.
// If it's not present or incorrect, it reports an error.
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

// parseJwtToken function tries to understand the details of the ticket (JWT token).
// It checks whether the ticket is genuine and has not been tampered with.
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

// isValidToken function checks whether the ticket (token) is still valid.
// Even if the ticket is genuine, it might be expired, in which case it won't be valid.
func isValidToken(token *jwt.Token) bool {
	return token.Valid || Cfg.Dev.Enabled
}

// isAdmin function checks whether the user is an admin or not based on their ticket (token).
// Admins have special permissions and access in the server.
func isAdmin(token KeycloakToken) bool {
	return (ContainsIgnoreCase(token.Groups, Cfg.Admin.Group) || ContainsIgnoreCase(token.ApaGroupsOrg, Cfg.Admin.Group)) && Cfg.Admin.Bypass
}

// requestWithContext function takes the ticket (token) and attaches it to the request,
// so it's easier to find and check it later.
func requestWithContext(r *http.Request, keycloakToken KeycloakToken) *http.Request {
	ctx := context.WithValue(r.Context(), KeycloakCtxToken, keycloakToken)
	return r.WithContext(ctx)
}
