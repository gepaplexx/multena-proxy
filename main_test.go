package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
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
			Groups:   []string{"not-group1", "not-group2"},
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
	//defer jwksServer.Close()
	Cfg.Web.JwksCertURL = jwksServer.URL
	initJWKS()

	// Set up the upstream server
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprintln(w, "Upstream server response")
		if err != nil {
			return
		}
	}))
	//defer upstreamServer.Close()
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
		setPluginID      bool
		pluginID         string
		expectedStatus   int
		expectedBody     string
		URL              string
	}{
		{
			name:           "Missing headers",
			URL:            "/api/v1/query_range",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "No Authorization header found\n",
		},
		{
			name:             "Malformed authorization header: B ",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "B",
			expectedBody:     "No Authorization header found\n",
		},
		{
			name:             "Malformed authorization header: Bearer ",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer ",
			expectedBody:     "No Authorization header found\n",
		},
		{
			name:             "Malformed authorization header: Bearer skk",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer " + "skk",
			expectedBody:     "Error parsing Keycloak token\n",
		},
		{
			name:             "Missing tenant labels for user",
			expectedStatus:   http.StatusForbidden,
			setAuthorization: true,
			setPluginID:      true,
			URL:              "/api/v1/query_range",
			authorization:    "Bearer " + tokens["noTenant"],
			expectedBody:     "No tenant labels found\n",
		},
		{
			name:             "Valid token and headers, no query",
			authorization:    "Bearer " + tokens["userTenant"],
			pluginID:         "thanos",
			setAuthorization: true,
			setPluginID:      true,
			URL:              "/api/v1/query_range",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User belongs to multiple groups, accessing forbidden tenant",
			authorization:    "Bearer " + tokens["groupTenant"],
			pluginID:         "thanos",
			setAuthorization: true,
			setPluginID:      true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "user not allowed with namespace forbidden_tenant\n",
		},
		{
			name:             "User belongs to no groups, accessing forbidden tenant",
			authorization:    "Bearer " + tokens["noTenant"],
			pluginID:         "thanos",
			setAuthorization: true,
			setPluginID:      true,
			URL:              "/api/v1/query_range?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "No tenant labels found\n",
		},
		{
			name:             "User belongs to no groups, accessing forbidden tenant",
			authorization:    "Bearer " + tokens["noGroupsTenant"],
			pluginID:         "thanos",
			setAuthorization: true,
			setPluginID:      true,
			URL:              "/api/v1/query?query=up{tenant_id=\"forbidden_tenant\"}",
			expectedStatus:   http.StatusForbidden,
			expectedBody:     "No tenant labels found\n",
		},
		{
			name:             "User belongs to multiple groups, accessing allowed tenant",
			authorization:    "Bearer " + tokens["groupTenant"],
			pluginID:         "thanos",
			setAuthorization: true,
			setPluginID:      true,
			URL:              "/api/v1/query?query=up{tenant_id=\"allowed_group1\"}",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User belongs to multiple groups, accessing allowed tenants",
			authorization:    "Bearer " + tokens["groupsTenant"],
			pluginID:         "thanos",
			setAuthorization: true,
			setPluginID:      true,
			URL:              "/api/v1/query?query=up{tenant_id=~\"allowed_group1|also_allowed_group2\"}",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User belongs to multiple groups, accessing allowed tenant",
			authorization:    "Bearer " + tokens["groupsTenant"],
			pluginID:         "loki",
			setAuthorization: true,
			setPluginID:      true,
			URL:              "/api/v1/query_range?query={tenant_id=\"also_allowed_group1\"} != 1337",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
		{
			name:             "User belongs to multiple groups, accessing allowed tenants",
			authorization:    "Bearer " + tokens["groupsTenant"],
			pluginID:         "loki",
			setAuthorization: true,
			setPluginID:      true,
			URL:              "/api/v1/query?query={tenant_id=~\"allowed_group1|allowed_group2\"} != 1337",
			expectedStatus:   http.StatusOK,
			expectedBody:     "Upstream server response\n",
		},
	}

	r := application()

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
			if tc.setPluginID {
				req.Header.Add("X-Plugin-Id", "thanos")
			}

			// Prepare the response recorder
			rr := httptest.NewRecorder()

			Logger.Debug("Request", zap.String("URL", tc.URL), zap.String("Authorization", tc.authorization), zap.String("X-Plugin-Id", tc.pluginID))

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

func TestHasAuthorizationHeader(t *testing.T) {
	assert := assert.New(t)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	assert.False(hasAuthorizationHeader(req))

	req.Header.Set("Authorization", "Bearer abc123")
	assert.True(hasAuthorizationHeader(req))
}

func TestGetBearerToken(t *testing.T) {
	assert := assert.New(t)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("Authorization", "Bearer abc123")
	assert.Equal("abc123", getBearerToken(req))
}

func TestIsAdminSkip(t *testing.T) {
	assert := assert.New(t)

	token := &KeycloakToken{Groups: []string{"gepardec-run-admins"}, ApaGroupsOrg: []string{"gepardec-run-admins"}}
	assert.True(isAdminSkip(*token))

	token.Groups = []string{"user"}
	token.ApaGroupsOrg = []string{"org"}
	assert.False(isAdminSkip(*token))
}

func TestLogAndWriteError(t *testing.T) {
	assert := assert.New(t)

	rw := httptest.NewRecorder()
	logAndWriteErrorMsg(rw, "test error", http.StatusInternalServerError, nil)
	assert.Equal(http.StatusInternalServerError, rw.Code)
	assert.Equal("test error\n", rw.Body.String())
}
