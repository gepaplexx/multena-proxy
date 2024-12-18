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

// OAuthToken represents the structure of an OAuth token.
// It holds user-related information extracted from the token.
type OAuthToken struct {
	Groups            []string `json:"-,omitempty"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	jwt.RegisteredClaims
}

// getToken retrieves the OAuth token from the incoming HTTP request.
// It extracts, parses, and validates the token from the Authorization header.
func getToken(r *http.Request, a *App) (OAuthToken, error) {
	authToken := r.Header.Get("Authorization")
	if authToken == "" {
		if a.Cfg.Alert.Enabled && r.Header.Get(a.Cfg.Alert.TokenHeader) != "" {
			authToken = r.Header.Get(a.Cfg.Alert.TokenHeader)
		} else {
			return OAuthToken{}, errors.New("no Authorization header found")
		}
	}
	log.Trace().Str("authToken", authToken).Msg("AuthToken")
	splitToken := strings.Split(authToken, "Bearer")
	log.Trace().Strs("splitToken", splitToken).Msg("SplitToken")
	if len(splitToken) != 2 {
		return OAuthToken{}, errors.New("invalid Authorization header")
	}

	oauthToken, token, err := parseJwtToken(strings.TrimSpace(splitToken[1]), a)
	if err != nil {
		return OAuthToken{}, fmt.Errorf("error parsing token")
	}
	if !token.Valid {
		return OAuthToken{}, fmt.Errorf("invalid token")
	}
	return oauthToken, nil
}

// parseJwtToken parses the JWT token string and constructs an OAuthToken from the parsed claims.
// It returns the constructed OAuthToken, the parsed jwt.Token, and any error that occurred during parsing.
func parseJwtToken(tokenString string, a *App) (OAuthToken, *jwt.Token, error) {
	var oAuthToken OAuthToken
	var claimsMap jwt.MapClaims

	token, err := jwt.ParseWithClaims(tokenString, &claimsMap, a.Jwks.Keyfunc)
	if err != nil {
		log.Error().Err(err).Msg("Error parsing token")
		return oAuthToken, nil, err
	}

	if !token.Valid {
		log.Trace().Msg("Token is invalid")
	}

	if v, ok := claimsMap["preferred_username"].(string); ok {
		oAuthToken.PreferredUsername = v
		log.Trace().Str("preferred_username", v).Msg("PreferredUsername")
	}

	if v, ok := claimsMap["email"].(string); ok {
		if !strings.Contains(v, "@") {
			log.Warn().Str("email", v).Msg("Email does not contain '@', therefore not an email. Could be sus")
		}
		log.Trace().Str("email", v).Msg("Email")
		oAuthToken.Email = v
	}

	if v, ok := claimsMap[a.Cfg.Web.OAuthGroupName].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				log.Trace().Str("group", s).Msg("Group")
				oAuthToken.Groups = append(oAuthToken.Groups, s)
			}
		}
	}

	return oAuthToken, token, err
}

// validateLabels validates the labels in the OAuth token.
// It checks if the user is an admin and skips label enforcement if true.
// Returns a map representing valid labels, a boolean indicating whether label enforcement should be skipped,
// and any error that occurred during validation.
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
