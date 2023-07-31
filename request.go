package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type Route struct {
	Url        string
	Datasource string
	MatchWord  string
}

type kkToken struct {
}

func application() *mux.Router {
	lokiUrl, err := url.Parse(Cfg.Loki.URL)
	if err != nil {
		Logger.Panic("Error parsing URL", zap.Error(err))
	}
	thanosUrl, err := url.Parse(Cfg.Thanos.URL)
	if err != nil {
		Logger.Panic("Error parsing URL", zap.Error(err))
	}

	r := mux.NewRouter()
	r.Use(loggingMiddleware)
	r.Use(authMiddleware)

	routes := []Route{
		//loki
		{Url: "/loki/api/v1/query", Datasource: "loki", MatchWord: "query"},
		{Url: "/loki/api/v1/query_range", Datasource: "loki", MatchWord: "query"},
		{Url: "/loki/api/v1/label/{name}/values", Datasource: "loki", MatchWord: "query"},
		{Url: "/loki/api/v1/series", Datasource: "loki", MatchWord: "match[]"},
		{Url: "/loki/api/v1/tail", Datasource: "loki", MatchWord: "query"},
		{Url: "/loki/api/v1/index/stats", Datasource: "loki", MatchWord: "query"},
		// Thanos
		{Url: "/api/v1/query", Datasource: "thanos", MatchWord: "query"},
		{Url: "/api/v1/query_range", Datasource: "thanos", MatchWord: "query"},
		{Url: "/api/v1/format_query", Datasource: "thanos", MatchWord: "query"},
		{Url: "/api/v1/series", Datasource: "thanos", MatchWord: "match[]"},
		{Url: "/api/v1/labels", Datasource: "thanos", MatchWord: "match[]"},
		{Url: "/api/v1/label/{label}/values", Datasource: "thanos", MatchWord: "match[]"},
		{Url: "/api/v1/query_exemplars", Datasource: "thanos", MatchWord: "query"},
		{Url: "/api/v1/status/buildinfo", Datasource: "thanos", MatchWord: "query"},
	}

	for _, route := range routes {
		handleRoute(r, route, thanosUrl, lokiUrl)
	}

	r.HandleFunc("/loki/api/v1/labels", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"status":"success","data":["kubernetes_container_name","kubernetes_host","kubernetes_namespace_name","kubernetes_pod_name"]}`)
	}).Methods("GET")

	r.HandleFunc("/api/v1/status/buildinfo", func(w http.ResponseWriter, r *http.Request) {
		callUpstream(w, r, thanosUrl)
	}).Methods("GET")

	r.SkipClean(true)

	//TODO implement default handler
	return r
}

func handleRoute(r *mux.Router, route Route, thanosUrl *url.URL, lokiUrl *url.URL) {
	var datasourceURL *url.URL
	var enforceFunc func(string, map[string]bool) (string, error)
	if route.Datasource == "thanos" {
		datasourceURL = thanosUrl
		enforceFunc = promqlEnforcer
	}
	if route.Datasource == "loki" {
		datasourceURL = lokiUrl
		enforceFunc = logqlEnforcer
	}
	if datasourceURL == nil {
		Logger.Panic("No datasource URL found")
	}

	r.HandleFunc(route.Url, func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(kkToken{}).(KeycloakToken)
		if !isAdmin(token) {
			labels, err := getTenantLabels(token)
			if err != nil {
				logAndWriteErrorMsg(w, "No tenant labels found", http.StatusForbidden, err)
				return
			}
			err = enforce(r, labels, route.MatchWord, enforceFunc)
			if err != nil {
				logAndWriteError(w, http.StatusForbidden, err)
				return
			}
			if r.Method == "POST" {
				err = enforcePost(r, labels, route.MatchWord, enforceFunc)
				if err != nil {
					logAndWriteError(w, http.StatusForbidden, err)
					return
				}
			}
		}
		callUpstream(w, r, datasourceURL)
	})
}

// -------------------------------  authorize section   ---------------------------------------------

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken, err := getBearerToken(r)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err)
			return
		}

		keycloakToken, token, err := parseJwtToken(authToken)
		if err != nil && !Cfg.Dev.Enabled {
			logAndWriteErrorMsg(w, "error parsing Keycloak token\n", http.StatusForbidden, err)
			return
		}

		if !isValidToken(token) {
			logAndWriteErrorMsg(w, "invalid token", http.StatusForbidden, nil)
		}

		ctx := context.WithValue(r.Context(), kkToken{}, keycloakToken)
		newReq := r.WithContext(ctx)
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

// -------------------------------  end authorize section   ---------------------------------------------
// -------------------------------  getTenantLabels section   ---------------------------------------------
func getTenantLabels(keycloakToken KeycloakToken) (map[string]bool, error) {
	var tenantLabels map[string]bool

	switch provider := Cfg.TenantProvider; provider {
	case "mysql":
		tenantLabels = GetLabelsFromDB(keycloakToken.Email)
		Logger.Debug("Fetched labels from MySQL")
	case "configmap":
		tenantLabels = GetLabelsCM(keycloakToken.PreferredUsername, keycloakToken.Groups)
		Logger.Debug("Fetched labels from ConfigMap")
	default:
		Logger.Error("No provider set")
		return nil, errors.New("no provider set")
	}

	Logger.Debug("username", zap.String("username", keycloakToken.PreferredUsername))
	if len(tenantLabels) <= 0 {
		return nil, errors.New("no tenant labels found")
	}

	Logger.Debug("Labels", zap.Any("tenantLabels", tenantLabels))
	return tenantLabels, nil
}

// -------------------------------  end getTenantLabels section   ---------------------------------------------
// -------------------------------  enforce section   ---------------------------------------------

func enforce(req *http.Request, tenantLabels map[string]bool, urlKey string, enforceFunc func(string, map[string]bool) (string, error)) error {
	query := req.URL.Query().Get(urlKey)
	query, err := enforceFunc(query, tenantLabels)
	if err != nil {
		return err
	}
	values := req.URL.Query()
	values.Set(urlKey, query)
	req.URL.RawQuery = values.Encode()
	Logger.Debug("Set query")
	return nil
}

func enforcePost(req *http.Request, tenantLabels map[string]bool, urlKey string, enforceFunc func(string, map[string]bool) (string, error)) error {
	if err := req.ParseForm(); err != nil {
		return err
	}
	Logger.Debug("Parsed form", zap.Any("form", req.PostForm))
	body := req.PostForm
	query, err := enforceFunc(body.Get(urlKey), tenantLabels)
	if err != nil {
		return err
	}
	body.Set(urlKey, query)

	// We are replacing request body, close previous one (ParseForm ensures it is read fully and not nil).
	_ = req.Body.Close()
	newBody := body.Encode()
	req.Body = io.NopCloser(strings.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
	return nil
}

// -------------------------------  end enforce section   ---------------------------------------------

func callUpstream(rw http.ResponseWriter, req *http.Request, upstream *url.URL) {
	Logger.Debug("Doing request")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ServiceAccountToken))
	Logger.Debug("Set Authorization header")

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ServeHTTP(rw, req)
}

// -------------------------------  log http section   ---------------------------------------------

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
		}

		// Restore the io.ReadCloser to its original state
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if !Cfg.Log.LogTokens {
			bodyBytes = []byte("[REDACTED]")
		}

		requestData := struct {
			Method string      `json:"method"`
			URL    string      `json:"url"`
			Header http.Header `json:"header"`
			Body   string      `json:"body"`
		}{
			Method: r.Method,
			URL:    r.URL.String(),
			Header: r.Header,
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
		Logger.Debug("Request", zap.String("request", string(jsonData)), zap.String("path", r.URL.Path))
		next.ServeHTTP(w, r)
		Logger.Debug("Request", zap.String("complete", "true"))
	})
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

// -------------------------------  end log http section   ---------------------------------------------
