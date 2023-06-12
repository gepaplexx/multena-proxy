package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"
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

	mux := http.NewServeMux()
	mux.Handle("/healthz", http.HandlerFunc(healthz))
	mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	mux.Handle("/", http.HandlerFunc(reverseProxy))
	err := http.ListenAndServe(fmt.Sprintf("%s:%d", Cfg.Proxy.Host, Cfg.Proxy.Port), mux)
	if err != nil {
		Logger.Panic("Error while serving", zap.Error(err))
	}
}

// healthz is an HTTP handler that always returns an HTTP status of 200 and a response body of "Ok". It's commonly used for health checks.
func healthz(w http.ResponseWriter, _ *http.Request) {
	Logger.Debug("Healthz")
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
	var upstreamUrl *url.URL
	var enforceFunc func(string, map[string]bool) (string, error)
	var tenantLabels map[string]bool
	query := req.URL.Query().Get("query")

	logRequest(req)
	Logger.Debug("url request", zap.String("url", req.URL.String()))

	if !hasAuthorizationHeader(req) {
		logAndWriteError(rw, "No Authorization header found", http.StatusForbidden, nil)
		return
	}

	tokenString := getBearerToken(req)
	keycloakToken, token, err := parseJwtToken(tokenString)
	if err != nil && !Cfg.Dev.Enabled {
		logAndWriteError(rw, "Error parsing Keycloak token", http.StatusForbidden, err)
		return
	}

	if !isValidToken(token) {
		logAndWriteError(rw, "Invalid token", http.StatusForbidden, nil)
		return
	}

	if req.Header.Get("X-Plugin-Id") == "" {
		logAndWriteError(rw, "No X-Plugin-Id header found", http.StatusForbidden, nil)
		return
	}

	if req.Header.Get("X-Plugin-Id") == "thanos" {
		upstreamUrl, err = url.Parse(Cfg.Proxy.ThanosUrl)
		enforceFunc = promqlEnforcer
	}

	if req.Header.Get("X-Plugin-Id") == "loki" {
		upstreamUrl, err = url.Parse(Cfg.Proxy.LokiUrl)
		enforceFunc = logqlEnforcer
	}
	if err != nil {
		logAndWriteError(rw, "Error parsing upstream url", http.StatusForbidden, err)
		return
	}

	if isAdminSkip(keycloakToken) {
		goto DoRequest
	}

	if Cfg.Dev.Enabled {
		keycloakToken.PreferredUsername = Cfg.Dev.Username
	}

	switch provider := Cfg.Proxy.Provider; provider {
	case "mysql":
		tenantLabels = GetLabelsFromDB(keycloakToken.Email)
	case "configmap":
		tenantLabels = GetLabelsCM(keycloakToken.PreferredUsername, keycloakToken.Groups)
	default:
		logAndWriteError(rw, "No provider set", http.StatusForbidden, nil)
		return
	}

	Logger.Debug("username", zap.String("username", keycloakToken.PreferredUsername))

	if len(tenantLabels) <= 0 {
		logAndWriteError(rw, "No tenant labels found", http.StatusForbidden, nil)
		return
	}
	Logger.Debug("Labels", zap.Any("tenantLabels", tenantLabels))

	query, err = enforceFunc(query, tenantLabels)
	if err != nil {
		logAndWriteError(rw, "Error modifying query", http.StatusForbidden, err)
		return
	}

DoRequest:

	values := req.URL.Query()
	values.Set("query", query)
	req.URL.RawQuery = values.Encode()

	req.Host = upstreamUrl.Host
	req.URL.Host = upstreamUrl.Host
	req.URL.Path = upstreamUrl.Path + req.URL.Path
	req.URL.Scheme = upstreamUrl.Scheme
	req.Header.Set("Authorization", "Bearer "+ServiceAccountToken)
	req.RequestURI = "" //need to be cleared cuz generated

	originServerResponse, err := http.DefaultClient.Do(req)
	if err != nil {
		logAndWriteError(rw, "Error while calling upstream", http.StatusForbidden, err)
		return
	}
	logResponse(originServerResponse)

	originBody, err := io.ReadAll(originServerResponse.Body)
	if err != nil {
		logAndWriteError(rw, "Error reading origin response", http.StatusForbidden, err)
		return
	}

	// return response to the client
	rw.WriteHeader(http.StatusOK)
	_, err = rw.Write(originBody)
	if err != nil {
		logAndWriteError(rw, "Error writing origin response to client", http.StatusInternalServerError, err)
		return
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logAndWriteError(rw, "Error closing body", http.StatusInternalServerError, err)
			return
		}
	}(originServerResponse.Body)
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
	return ContainsIgnoreCase(token.Groups, Cfg.Proxy.AdminGroup) || ContainsIgnoreCase(token.ApaGroupsOrg, Cfg.Proxy.AdminGroup)
}

// logAndWriteError logs an error and sends an error message as the HTTP response.
func logAndWriteError(rw http.ResponseWriter, message string, statusCode int, err error) {
	Logger.Error(message, zap.Error(err))
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprint(rw, message+"\n")
}

// logRequest logs the details of an incoming HTTP request.
func logRequest(req *http.Request) {
	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		Logger.Error("Error while dumping request", zap.Error(err))
	}
	Logger.Debug("Request", zap.String("request", string(dump)))
}

// logResponse logs the details of an HTTP response received from the upstream server.
func logResponse(res *http.Response) {
	dump, err := httputil.DumpResponse(res, true)
	if err != nil {
		Logger.Error("Error while dumping response", zap.Error(err))
	}
	Logger.Debug("Response", zap.String("response", string(dump)))
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
