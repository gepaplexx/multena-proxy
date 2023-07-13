package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/slok/go-http-metrics/middleware/std"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"
	"strings"
)

// main is the entry point of the application. It initializes necessary components, sets up HTTP routes, and starts the HTTP server.
func main() {
	defer func(Logger *zap.Logger) {
		err := Logger.Sync()

		if err != nil {
			fmt.Printf("{\"level\":\"error\",\"error\":\"%s/\"}", err)
			return
		}
	}(Logger)

	Logger.Info("Starting Proxy")

	mdlw := middleware.New(middleware.Config{
		Recorder: metrics.NewRecorder(metrics.Config{}),
		Service:  "multena",
	})

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/healthz", http.HandlerFunc(healthz))
	mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))

	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", Cfg.Web.Host, Cfg.Web.MetricsPort), mux); err != nil {
			Logger.Panic("Error while serving metrics", zap.Error(err))
		}
	}()
	err := http.ListenAndServe(fmt.Sprintf("%s:%d", Cfg.Web.Host, Cfg.Web.ProxyPort),
		std.Handler("/", mdlw, http.HandlerFunc(reverseProxy)))

	if err != nil {
		Logger.Panic("Error while serving", zap.Error(err))
	}
}

// healthz is an HTTP handler that always returns an HTTP status of 200 and a response body of "Ok". It's commonly used for health checks.
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "Ok")
}

// reverseProxy serves as the primary request handler for the proxy. It evaluates the incoming
// request's authorization and based on the "X-Plugin-Id" header, determines the upstream service.
// For non-admin users, the function fetches user-specific tenant labels and modifies the request
// query accordingly. The updated request is then forwarded to the selected upstream service.
// It handles any encountered error by logging it and returning an appropriate HTTP error response.
// The response from the upstream service is logged and relayed back to the client. After sending
// the response, it ensures the upstream service response body is properly closed.
func reverseProxy(rw http.ResponseWriter, req *http.Request) {
	Logger.Debug("Start reverseProxy")

	var upstreamUrl *url.URL
	var enforceFunc func(string, map[string]bool) (string, error)
	var tenantLabels map[string]bool
	var err error

	urlKey := "query"
	if containsApiV1Labels(req.URL.Path) {
		urlKey = "match[]"
	}
	query := req.URL.Query().Get(urlKey)

	upstreamUrl, err = url.Parse(Cfg.Thanos.URL)
	enforceFunc = promqlEnforcer
	Logger.Debug("Parsed Thanos URL")

	if containsLoki(req.URL.Path) {
		upstreamUrl, err = url.Parse(Cfg.Loki.URL)
		enforceFunc = logqlEnforcer
		Logger.Debug("Parsed Loki URL")
	}

	if err != nil {
		logAndWriteErrorMsg(rw, "Error parsing upstream url", http.StatusInternalServerError, err)
		return
	}

	logRequest(req)

	if !hasAuthorizationHeader(req) {
		logAndWriteErrorMsg(rw, "No Authorization header found", http.StatusForbidden, nil)
		return
	}

	Logger.Debug("Has Authorization header")

	tokenString := getBearerToken(req)
	keycloakToken, token, err := parseJwtToken(tokenString)
	if err != nil && !Cfg.Dev.Enabled {
		logAndWriteErrorMsg(rw, "Error parsing Keycloak token", http.StatusForbidden, err)
		return
	}

	Logger.Debug("Parsed JWT token")

	if !isValidToken(token) {
		logAndWriteErrorMsg(rw, "Invalid token", http.StatusForbidden, nil)
		return
	}

	Logger.Debug("Token is valid")

	if isAdminSkip(keycloakToken) {
		goto DoRequest
	}

	Logger.Debug("Not admin user, enforcing query")

	if Cfg.Dev.Enabled {
		keycloakToken.PreferredUsername = Cfg.Dev.Username
		Logger.Debug("Development mode enabled, set preferred username")
	}

	switch provider := Cfg.TenantProvider; provider {
	case "mysql":
		tenantLabels = GetLabelsFromDB(keycloakToken.Email)
		Logger.Debug("Fetched labels from MySQL")
	case "configmap":
		tenantLabels = GetLabelsCM(keycloakToken.PreferredUsername, keycloakToken.Groups)
		Logger.Debug("Fetched labels from ConfigMap")
	default:
		logAndWriteErrorMsg(rw, "No provider set", http.StatusForbidden, nil)
		return
	}

	Logger.Debug("username", zap.String("username", keycloakToken.PreferredUsername))

	if len(tenantLabels) <= 0 {
		logAndWriteErrorMsg(rw, "No tenant labels found", http.StatusForbidden, nil)
		return
	}
	Logger.Debug("Labels", zap.Any("tenantLabels", tenantLabels))

	query, err = enforceFunc(query, tenantLabels)
	if err != nil {
		logAndWriteError(rw, http.StatusForbidden, err)
		return
	}
	if req.Method == http.MethodPost {
		if err := req.ParseForm(); err != nil {
			logAndWriteErrorMsg(rw, "Error processing Post request", http.StatusForbidden, err)
			return
		}
		Logger.Debug("Parsed form", zap.Any("form", req.PostForm))
		body := req.PostForm
		query, err = enforceFunc(body.Get(urlKey), tenantLabels)
		if err != nil {
			logAndWriteError(rw, http.StatusForbidden, err)
			return
		}
		body.Set(urlKey, query)

		// We are replacing request body, close previous one (ParseForm ensures it is read fully and not nil).
		_ = req.Body.Close()
		newBody := body.Encode()
		req.Body = io.NopCloser(strings.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
	}

	Logger.Debug("Modified query successfully")
	{
		values := req.URL.Query()
		values.Set(urlKey, query)
		req.URL.RawQuery = values.Encode()
		Logger.Debug("Set query")
	}

DoRequest:

	Logger.Debug("Doing request")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ServiceAccountToken))
	Logger.Debug("Set Authorization header")
	logRequest(req)

	proxy := httputil.NewSingleHostReverseProxy(upstreamUrl)
	proxy.ServeHTTP(rw, req)

}

// hasAuthorizationHeader checks whether the given HTTP request contains an "Authorization" header.
func hasAuthorizationHeader(req *http.Request) bool {
	authorization := req.Header.Get("Authorization")
	return authorization != "" && len(authorization) > 7
}

// getBearerToken extracts the JWT token from the "Authorization" header in the given HTTP request.
func getBearerToken(req *http.Request) string {
	return req.Header.Get("Authorization")[7:]
}

// isValidToken checks whether a JWT token is valid or not.
func isValidToken(token *jwt.Token) bool {
	return token.Valid || Cfg.Dev.Enabled
}

// isAdminSkip checks if a user belongs to the admin group. It can bypass some checks for admin users.
func isAdminSkip(token KeycloakToken) bool {
	return (ContainsIgnoreCase(token.Groups, Cfg.Admin.Group) || ContainsIgnoreCase(token.ApaGroupsOrg, Cfg.Admin.Group)) && Cfg.Admin.Bypass
}

func containsApiV1Labels(s string) bool {
	return strings.Contains(s, "/api/v1/label") || strings.Contains(s, "/api/v1/series")
}

func containsLoki(s string) bool {
	return strings.Contains(s, "/loki")
}

// logAndWriteErrorMsg logs an error and sends an error message as the HTTP response.
func logAndWriteErrorMsg(rw http.ResponseWriter, message string, statusCode int, err error) {
	Logger.Error(message, zap.Error(err))
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprint(rw, message+"\n")
}

// logAndWriteError logs an error and sends an error message as the HTTP response.
func logAndWriteError(rw http.ResponseWriter, statusCode int, err error) {
	Logger.Error(err.Error(), zap.Error(err))
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprint(rw, err.Error()+"\n")
}

// logRequest logs the details of an incoming HTTP request.
func logRequest(req *http.Request) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
	}

	// Restore the io.ReadCloser to its original state
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	if !Cfg.Log.LogTokens {
		bodyBytes = []byte("[REDACTED]")
	}

	requestData := struct {
		Method string      `json:"method"`
		URL    string      `json:"url"`
		Header http.Header `json:"header"`
		Body   string      `json:"body"`
	}{
		Method: req.Method,
		URL:    req.URL.String(),
		Header: req.Header,
		Body:   string(bodyBytes),
	}

	if !Cfg.Log.LogTokens {
		copyHeader := make(http.Header)
		for k, v := range requestData.Header {
			copyHeader[k] = v
		}
		copyHeader.Del("Authorization")
		copyHeader.Del("X-Plugin-Id")
		copyHeader.Del("X-Id-Token")
		requestData.Header = copyHeader
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		Logger.Error("Error while marshalling request", zap.Error(err))
		return
	}
	Logger.Debug("Request", zap.String("request", string(jsonData)), zap.String("path", req.URL.Path))
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
