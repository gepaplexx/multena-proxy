package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog/log"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func genJWKS(username, email string, groups []string, pk *ecdsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"preferred_username": username,
		"email":              email,
		"groups":             groups,
	})
	token.Header["kid"] = "testKid"
	return token.SignedString(pk)
}

func setupTestMain() (App, map[string]string) {
	// Generate a new private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate private key: %s\n", err)
		return App{}, nil
	}

	// Encode the private key to PEM format.
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		fmt.Printf("Failed to marshal private key: %s\n", err)
		return App{}, nil
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode the public key to PEM format.
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Printf("Failed to marshal public key: %s\n", err)
		return App{}, nil
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Generate a key pair
	pk, _ := jwt.ParseECPrivateKeyFromPEM(privateKeyPEM)
	pubkey, _ := jwt.ParseECPublicKeyFromPEM(publicKeyPEM)

	jwks := []struct {
		name     string
		Username string
		Email    string
		Groups   []string
	}{
		{
			name:     "noTenant",
			Username: "not-a-user",
			Email:    "test@email.com",
			Groups:   []string{},
		},
		{
			name:     "userTenant",
			Username: "user",
			Email:    "test@email.com",
			Groups:   []string{""},
		},
		{
			name:     "groupTenant",
			Username: "not-a-user",
			Email:    "test@email.com",
			Groups:   []string{"group1"},
		},
		{
			name:     "groupsTenant",
			Username: "not-a-user",
			Email:    "test@email.com",
			Groups:   []string{"group1", "group2"},
		},
		{
			name:     "noGroupsTenant",
			Username: "test-user",
			Email:    "test@email.com",
			Groups:   []string{},
		},
		{
			name:     "userAndGroupTenant",
			Username: "user",
			Email:    "test@email.com",
			Groups:   []string{"group1", "group2"},
		},
		{
			name:     "adminUserToken",
			Username: "admin",
			Email:    "admin-email@example.com",
			Groups:   []string{"admins"},
		},
		{
			name:     "userWithOutProperEmail",
			Username: "not-an-email",
			Email:    "testmail",
			Groups:   []string{"group1"},
		},
	}
	tokens := make(map[string]string, len(jwks))
	for _, jwk := range jwks {
		token, _ := genJWKS(jwk.Username, jwk.Email, jwk.Groups, pk)
		tokens[jwk.name] = token
	}

	// Base64url encoding
	x := base64.RawURLEncoding.EncodeToString(pubkey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(pubkey.Y.Bytes())

	// Set up the JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintf(w, `{"keys":[{"kty":"EC","kid":"testKid","alg":"ES256","use":"sig","x":"%s","y":"%s","crv":"P-256"}]}`, x, y)
		if err != nil {
			return
		}
	}))
	app := App{}
	app.WithConfig()
	// defer jwksServer.Close()
	app.Cfg.Web.JwksCertURL = jwksServer.URL
	app.WithJWKS()

	// Set up the upstream server
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintln(w, "Upstream server response")
		if err != nil {
			return
		}
	}))
	// defer upstreamServer.Close()
	app.Cfg.Thanos.URL = upstreamServer.URL
	app.Cfg.Loki.URL = upstreamServer.URL
	app.Cfg.Thanos.TenantLabel = "tenant_id"
	app.Cfg.Loki.TenantLabel = "tenant_id"

	cmh := ConfigMapHandler{
		labels: map[string]map[string]bool{
			"user":   {"allowed_user": true, "also_allowed_user": true},
			"group1": {"allowed_group1": true, "also_allowed_group1": true},
			"group2": {"allowed_group2": true, "also_allowed_group2": true},
			"admins": {"admin_label": true},
		},
	}

	app.LabelStore = &cmh
	return app, tokens
}

func Test_reverseProxy(t *testing.T) {
	app, tokens := setupTestMain()
	log.Level(2)

	cases := []struct {
		name             string
		setAuthorization bool
		authorization    string
		expectedStatus   int
		expectedBody     string
		URL              string
	}{
		{
			name:           "Missing_headers",
			URL:            "/api/v1/query_range",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "no Authorization header found\n",
		},
		{
			name:             "Malformed_authorization_header:_B",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "B",
			expectedBody:     "invalid Authorization header\n",
		},
		{
			name:             "Malformed_authorization_header:_Bearer",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer ",
			expectedBody:     "error parsing token\nno tenant labels found\n",
		},
		{
			name:             "Malformed_authorization_header:_Bearer_skk",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer " + "skk",
			expectedBody:     "error parsing token\nno tenant labels found\n",
		},
		{
			name:             "Missing_tenant_labels_for_user",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer " + tokens["noTenant"],
			expectedBody:     "no tenant labels found\n",
		},
		{
			name:             "Valid_token_and_headers_no_query",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["groupTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "user not allowed with tenant label forbidden_tenant\n",
		},
		{
			name:             "Not_a_User_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["noTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "no tenant labels found\n",
		},
		{
			name:             "User_belongs_to_no_groups_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["noGroupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "no tenant labels found\n",
		},
		{
			name:             "User_belongs_to_multiple_groups_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=\"allowed_group1\"}",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups_accessing_allowed_tenants",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=~\"allowed_group1|also_allowed_group2\"}",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query={tenant_id=\"also_allowed_group1\"} != 1337",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups_accessing_allowed_tenants",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query={tenant_id=~\"allowed_group1|allowed_group2\"} != 1337",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_query_range_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/query_range?direction=backward&end=1690463973787000000&limit=1000&query=sum by (level) (count_over_time({tenant_id=\"allowed_group1\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method | printf \"%-4s\"}} {{.path | printf \"%-60s\"}} {{.url | urldecode}}`[1m]))&start=1690377573787000000&step=60000ms",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_index_stats_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/index/stats?query={tenant_id=\"allowed_user\"}&start=1690377573724000000&end=1690463973724000000",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_query_range_with_forbidden_tenant",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id=\"forbidden_tenant\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method}} {{.path}} {{.url | urldecode}}`&start=1690377573693000000&step=86400000ms",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "unauthorized label forbidden_tenant\n",
		},
		//{
		//	name:             "Email_query",
		//	authorization:    "Bearer " + tokens["userWithOutProperEmail"],
		//	setAuthorization: true,
		//	URL:              "/loki/api/v1/query?&query=up",
		//	expectedStatus:   http.StatusOK,
		//	expectedBody:     "Upstream server response\n",
		//},
	}

	app.WithRoutes()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a request
			req, err := http.NewRequest("GET", tc.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			// Set headers based on the test case.
			if tc.setAuthorization {
				req.Header.Add("Authorization", tc.authorization)
			}

			// Prepare the response recorder
			rr := httptest.NewRecorder()

			log.Debug().Str("URL", tc.URL).Str("Authorization", tc.authorization).Msg("Request")
			// Call the function
			app.e.ServeHTTP(rr, req)

			// Check the status code
			assert.Equal(t, tc.expectedStatus, rr.Code)

			// Check the response body
			if tc.expectedBody != "" {
				assert.Contains(t, rr.Body.String(), tc.expectedBody)
			}
		})
	}
}

func TestAlertAuth(t *testing.T) {
	app, tokens := setupTestMain()
	app.Cfg.Alert.Enabled = true
	app.Cfg.Alert.TokenHeader = "X-Multena-Alert-Token"
	app.Cfg.Alert.CertURL = "http://localhost:8080/jwks"

	log.Level(2)

	cases := []struct {
		name             string
		setAuthorization bool
		authorization    string
		expectedStatus   int
		expectedBody     string
		URL              string
	}{
		{
			name:           "Missing_headers",
			URL:            "/api/v1/query_range",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "no Authorization header found\n",
		},
		{
			name:             "Malformed_authorization_header:_B",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "B",
			expectedBody:     "invalid Authorization header\n",
		},
		{
			name:             "Malformed_authorization_header:_Bearer",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer ",
			expectedBody:     "error parsing token\nno tenant labels found\n",
		},
		{
			name:             "Malformed_authorization_header:_Bearer_skk",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer skk",
			expectedBody:     "error parsing token\nno tenant labels found\n",
		},
		{
			name:             "Missing_tenant_labels_for_user",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer " + tokens["noTenant"],
			expectedBody:     "no tenant labels found\n",
		},
		{
			name:             "Valid_token_and_headers,_no_query",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups,_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["groupTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "user not allowed with tenant label forbidden_tenant\n",
		},
		{
			name:             "Not_a_User,_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["noTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "no tenant labels found\n",
		},
		{
			name:             "User_belongs_to_no_groups,_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["noGroupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "no tenant labels found\n",
		},
		{
			name:             "User_belongs_to_multiple_groups,_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=\"allowed_group1\"}",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups,_accessing_allowed_tenants",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=~\"allowed_group1|also_allowed_group2\"}",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups,_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query={tenant_id=\"also_allowed_group1\"} != 1337",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User_belongs_to_multiple_groups,_accessing_allowed_tenants",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query={tenant_id=~\"allowed_group1|allowed_group2\"} != 1337",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_query_range,_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["groupsTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/query_range?direction=backward&end=1690463973787000000&limit=1000&query=sum by (level) (count_over_time({tenant_id=\"allowed_group1\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method | printf \"%-4s\"}} {{.path | printf \"%-60s\"}} {{.url | urldecode}}`[1m]))&start=1690377573787000000&step=60000ms",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_index_stats,_accessing_allowed_tenant",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/index/stats?query={tenant_id=\"allowed_user\"}&start=1690377573724000000&end=1690463973724000000",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "Loki_query_range_with_forbidden_tenant",
			authorization:    "Bearer " + tokens["userTenant"],
			setAuthorization: true,
			URL:              "/loki/api/v1/query_range?direction=backward&end=1690463973693000000&limit=10&query={tenant_id=\"forbidden_tenant\"} |= `path` |= `label` | json | line_format `{{.message}}` | json | line_format `{{.request}}` | json | line_format `{{.method}} {{.path}} {{.url | urldecode}}`&start=1690377573693000000&step=86400000ms",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "unauthorized label forbidden_tenant\n",
		},
	}

	app.WithRoutes()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a request
			req, err := http.NewRequest("GET", tc.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			// IMPORTANT: We set the alert token header instead of “Authorization”
			if tc.setAuthorization {
				req.Header.Add(app.Cfg.Alert.TokenHeader, tc.authorization)
			}

			// Prepare the response recorder
			rr := httptest.NewRecorder()

			log.Debug().Str("URL", tc.URL).Str("Authorization", tc.authorization).Msg("Alert-Request")
			// Call the function
			app.e.ServeHTTP(rr, req)

			// Check the status code
			assert.Equal(t, tc.expectedStatus, rr.Code)

			// Check the response body
			if tc.expectedBody != "" {
				assert.Contains(t, rr.Body.String(), tc.expectedBody)
			}
		})
	}
}

func TestIsAdminSkip(t *testing.T) {
	a := assert.New(t)

	app := &App{}
	app.WithConfig()
	app.Cfg.Admin.Bypass = true
	app.Cfg.Admin.Group = "gepardec-run-admins"
	token := &OAuthToken{Groups: []string{"gepardec-run-admins"}}
	a.True(isAdmin(*token, app))

	token.Groups = []string{"user"}
	a.False(isAdmin(*token, app))
}

func TestLogAndWriteError(t *testing.T) {
	a := assert.New(t)

	rw := httptest.NewRecorder()
	logAndWriteError(rw, http.StatusInternalServerError, nil, "test error")
	a.Equal(http.StatusInternalServerError, rw.Code)
	a.Equal("test error\n", rw.Body.String())
}
