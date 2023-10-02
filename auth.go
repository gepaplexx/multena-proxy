package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/exp/maps"

	"github.com/golang-jwt/jwt/v5"
)

type OAuthToken struct {
	Groups            []string `json:"-"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	jwt.RegisteredClaims
}

func getToken(r *http.Request, a *App) (OAuthToken, error) {
	authToken, err := trimBearerToken(r)
	if err != nil {
		return OAuthToken{}, err
	}
	oauthToken, token, err := parseJwtToken(authToken, a)
	if err != nil {
		return OAuthToken{}, fmt.Errorf("error parsing token")
	}
	if !token.Valid {
		return OAuthToken{}, fmt.Errorf("invalid token")
	}
	return oauthToken, nil
}

func trimBearerToken(r *http.Request) (string, error) {
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

func parseJwtToken(tokenString string, a *App) (OAuthToken, *jwt.Token, error) {
	var oAuthToken OAuthToken
	var claimsMap jwt.MapClaims

	token, err := jwt.ParseWithClaims(tokenString, &claimsMap, a.Jwks.Keyfunc)
	if err != nil {
		return oAuthToken, nil, err
	}

	if v, ok := claimsMap["preferred_username"].(string); ok {
		oAuthToken.PreferredUsername = v
	}
	if v, ok := claimsMap["email"].(string); ok {
		oAuthToken.Email = v
	}

	if v, ok := claimsMap[a.Cfg.Web.OAuthGroupName].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				oAuthToken.Groups = append(oAuthToken.Groups, s)
			}
		}
	}
	return oAuthToken, token, err
}

func validateLabels(token OAuthToken, a *App) (map[string]bool, bool, error) {
	if isAdmin(token, a) {
		log.Debug().Str("user", token.PreferredUsername).Bool("Admin", true).Msg("Skipping label enforcement")
		return nil, true, nil
	}

	tenantLabels, skip := a.LabelStore.GetLabels(token)
	if skip {
		log.Debug().Str("user", token.PreferredUsername).Bool("Admin", false).Msg("Skipping label enforcement")
		return nil, true, nil
	}
	log.Debug().Str("user", token.PreferredUsername).Strs("labels", maps.Keys(tenantLabels)).Msg("")

	if len(tenantLabels) < 1 {
		return nil, false, fmt.Errorf("no tenant labels found")
	}
	return tenantLabels, false, nil
}

func isAdmin(token OAuthToken, a *App) bool {
	return ContainsIgnoreCase(token.Groups, a.Cfg.Admin.Group) && a.Cfg.Admin.Bypass
}
