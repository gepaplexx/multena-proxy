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

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
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

func setupTestMain() map[string]string {
	// Generate a new private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate private key: %s\n", err)
		return nil
	}

	// Encode the private key to PEM format.
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		fmt.Printf("Failed to marshal private key: %s\n", err)
		return nil
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode the public key to PEM format.
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Printf("Failed to marshal public key: %s\n", err)
		return nil
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
			Email:    "test-email",
			Groups:   []string{},
		},
		{
			name:     "userTenant",
			Username: "user",
			Email:    "test-email",
			Groups:   []string{""},
		},
		{
			name:     "groupTenant",
			Username: "not-a-user",
			Email:    "test-email",
			Groups:   []string{"group1"},
		},
		{
			name:     "groupsTenant",
			Username: "not-a-user",
			Email:    "test-email",
			Groups:   []string{"group1", "group2"},
		},
		{
			name:     "noGroupsTenant",
			Username: "test-user",
			Email:    "test-email",
			Groups:   []string{},
		},
		{
			name:     "userAndGroupTenant",
			Username: "user",
			Email:    "test-email",
			Groups:   []string{"group1", "group2"},
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
	// defer jwksServer.Close()
	Cfg.Web.JwksCertURL = jwksServer.URL
	initJWKS()

	// Set up the upstream server
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintln(w, "Upstream server response")
		if err != nil {
			return
		}
	}))
	// defer upstreamServer.Close()
	Cfg.Thanos.URL = upstreamServer.URL
	Cfg.Loki.URL = upstreamServer.URL
	Cfg.Thanos.TenantLabel = "tenant_id"
	Cfg.Loki.TenantLabel = "tenant_id"

	Cfg.Users["user"] = []string{"allowed_user", "also_allowed_user"}
	Cfg.Groups["group1"] = []string{"allowed_group1", "also_allowed_group1"}
	Cfg.Groups["group2"] = []string{"allowed_group2", "also_allowed_group2"}
	return tokens
}

func Test_reverseProxy(t *testing.T) {
	tokens := setupTestMain()

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
			expectedBody:     "error parsing Keycloak token\n",
		},
		{
			name:             "Malformed_authorization_header:_Bearer_skk",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer " + "skk",
			expectedBody:     "error parsing Keycloak token\n",
		},
		{
			name:             "Missing_tenant_labels_for_user",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer " + tokens["noTenant"],
			expectedBody:     "No tenant labels found\n",
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
			expectedBody:     "user not allowed with namespace forbidden_tenant\n",
		},
		{
			name:             "Not_a_User,_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["noTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "No tenant labels found\n",
		},
		{
			name:             "User_belongs_to_no_groups,_accessing_forbidden_tenant",
			authorization:    "Bearer " + tokens["noGroupsTenant"],
			setAuthorization: true,
			URL:              "/api/v1/query?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "No tenant labels found\n",
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
			expectedBody:     "unauthorized namespace forbidden_tenant\n",
		},
	}

	r, _, err := application()
	if err != nil {
		t.Fatal(err)
	}

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

			Logger.Debug("Request", zap.String("URL", tc.URL), zap.String("Authorization", tc.authorization))

			// Call the function
			r.ServeHTTP(rr, req)

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

	token := &KeycloakToken{Groups: []string{"gepardec-run-admins"}, ApaGroupsOrg: []string{"gepardec-run-admins"}}
	a.True(isAdmin(*token))

	token.Groups = []string{"user"}
	token.ApaGroupsOrg = []string{"org"}
	a.False(isAdmin(*token))
}

func TestLogAndWriteError(t *testing.T) {
	a := assert.New(t)

	rw := httptest.NewRecorder()
	logAndWriteError(rw, http.StatusInternalServerError, nil, "test error")
	a.Equal(http.StatusInternalServerError, rw.Code)
	a.Equal("test error\n", rw.Body.String())
}
