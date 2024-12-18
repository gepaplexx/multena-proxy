package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetToken_ValidToken(t *testing.T) {
	app, tokens := setupTestMain()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["userTenant"])

	token, err := getToken(req, &app)

	assert.NoError(t, err)
	assert.Equal(t, "user", token.PreferredUsername)
	assert.Equal(t, "test@email.com", token.Email)
}

func TestGetToken_MissingAuthorizationHeader(t *testing.T) {
	app, _ := setupTestMain()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token, err := getToken(req, &app)

	assert.Error(t, err)
	assert.Equal(t, OAuthToken{}, token)
}

func TestGetToken_InvalidAuthorizationFormat(t *testing.T) {
	app, _ := setupTestMain()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "InvalidToken")

	token, err := getToken(req, &app)

	assert.Error(t, err)
	assert.Equal(t, OAuthToken{}, token)
}

func TestParseJwtToken_ValidToken(t *testing.T) {
	app, tokens := setupTestMain()
	tokenString := tokens["groupTenant"]

	oauthToken, _, err := parseJwtToken(tokenString, &app)

	assert.NoError(t, err)
	assert.Equal(t, "not-a-user", oauthToken.PreferredUsername)
	assert.Equal(t, "test@email.com", oauthToken.Email)
}

func TestParseJwtToken_InvalidToken(t *testing.T) {
	app, _ := setupTestMain()
	tokenString := "invalidToken"

	oauthToken, _, err := parseJwtToken(tokenString, &app)

	assert.Error(t, err)
	assert.Equal(t, OAuthToken{}, oauthToken)
}

func TestValidateLabels_AdminUser(t *testing.T) {
	app, tokens := setupTestMain()
	tokenString := tokens["adminUserToken"]

	oauthToken, _, _ := parseJwtToken(tokenString, &app)

	app.Cfg.Admin.Group = "admins"
	app.Cfg.Admin.Bypass = true

	tenantLabels, skip, err := validateLabels(oauthToken, &app)

	assert.NoError(t, err)
	assert.True(t, skip)
	assert.Nil(t, tenantLabels)
}

func TestValidateLabels_NonAdminUserWithValidLabels(t *testing.T) {
	app, tokens := setupTestMain()
	tokenString := tokens["userTenant"]

	oauthToken, _, _ := parseJwtToken(tokenString, &app)

	tenantLabels, skip, err := validateLabels(oauthToken, &app)

	assert.NoError(t, err)
	assert.False(t, skip)
	assert.NotNil(t, tenantLabels)
	assert.Contains(t, tenantLabels, "allowed_user")
}

func TestValidateLabels_NonAdminUserWithoutLabels(t *testing.T) {
	app, tokens := setupTestMain()
	tokenString := tokens["noTenant"]

	oauthToken, _, _ := parseJwtToken(tokenString, &app)

	tenantLabels, skip, err := validateLabels(oauthToken, &app)

	assert.Error(t, err)
	assert.False(t, skip)
	assert.Nil(t, tenantLabels)
}

func TestIsAdmin_ValidAdminUser(t *testing.T) {
	app, tokens := setupTestMain()
	tokenString := tokens["adminUserToken"]

	oauthToken, _, _ := parseJwtToken(tokenString, &app)

	app.Cfg.Admin.Group = "admins"
	app.Cfg.Admin.Bypass = true

	isAdmin := isAdmin(oauthToken, &app)

	assert.True(t, isAdmin)
}

func TestIsAdmin_NonAdminUser(t *testing.T) {
	app, tokens := setupTestMain()
	tokenString := tokens["userTenant"]

	oauthToken, _, _ := parseJwtToken(tokenString, &app)

	app.Cfg.Admin.Group = "admins"
	app.Cfg.Admin.Bypass = true

	isAdmin := isAdmin(oauthToken, &app)

	assert.False(t, isAdmin)
}
