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
	"strings"
)

func main() {
	doInit()
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
	err := http.ListenAndServe(fmt.Sprintf(":%d", C.Proxy.Port), mux)
	if err != nil {
		Logger.Panic("Error while serving", zap.Error(err))
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	Logger.Debug("Healthz")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "Ok")
}

func reverseProxy(rw http.ResponseWriter, req *http.Request) {
	logRequest(req)
	Logger.Debug("url request", zap.String("url", req.URL.String()))

	if !isAuthorized(req) {
		logAndWriteError(rw, "No Authorization header found", http.StatusForbidden, nil)
		return
	}

	tokenString := getBearerToken(req)
	keycloakToken, token, err := parseJwtToken(tokenString)
	if err != nil && !C.Dev.Enabled {
		logAndWriteError(rw, "Error parsing Keycloak token", http.StatusForbidden, err)
		return
	}

	if !isValidToken(token) {
		logAndWriteError(rw, "Invalid token", http.StatusForbidden, nil)
		return
	}

	var upstreamUrl *url.URL
	if ContainsIgnoreCase(keycloakToken.Groups, C.Proxy.AdminGroup) || ContainsIgnoreCase(keycloakToken.ApaGroupsOrg, C.Proxy.AdminGroup) {
		upstreamUrl, err = url.Parse(C.Proxy.ThanosUrl)
		if err != nil {
			logAndWriteError(rw, "Error parsing upstream url", http.StatusForbidden, err)
			return
		}
	} else {
		var tenantLabels []string
		switch provider := C.Proxy.Provider; provider {
		case "mysql":
			tenantLabels = GetLabelsFromDB(keycloakToken.Email)
		case "configmap":
			tenantLabels = GetLabelsCM(keycloakToken.PreferredUsername, keycloakToken.Groups)
		default:
			logAndWriteError(rw, "No provider set", http.StatusForbidden, nil)
			return
		}

		if len(tenantLabels) <= 0 {
			logAndWriteError(rw, "No tenant labels found", http.StatusForbidden, nil)
			return
		}

		Logger.Debug("username", zap.String("username", keycloakToken.PreferredUsername))
		Logger.Debug("Labels", zap.Any("tenantLabels", tenantLabels))

		if req.Header.Get("X-Plugin-Id") == "" {
			logAndWriteError(rw, "No X-Plugin-Id header found", http.StatusForbidden, nil)
			return

		}

		if req.Header.Get("X-Plugin-Id") == "loki" {
			upstreamUrl, err = url.Parse(C.Proxy.LokiUrl)
			if err != nil {
				logAndWriteError(rw, "Error parsing upstream url", http.StatusForbidden, err)
				return
			}
			query := req.URL.Query().Get("query")
			query, err = logqlEnforcer(query, tenantLabels)
			if err != nil {
				logAndWriteError(rw, "Error parsing rewritten query", http.StatusForbidden, err)
				return
			}
			values := req.URL.Query()
			values.Set("query", query)
			req.URL.RawQuery = values.Encode()

		}
		if req.Header.Get("X-Plugin-Id") == "thanos" {
			upstreamUrl, err = url.Parse(C.Proxy.ThanosUrl)
			if err != nil {
				logAndWriteError(rw, "Error parsing upstream url", http.StatusForbidden, err)
				return
			}
			values := req.URL.Query()
			values.Set(C.Proxy.TenantLabel, strings.Join(tenantLabels, ","))
			req.URL.RawQuery = values.Encode()
		}

	}

	req.Host = upstreamUrl.Host
	req.URL.Host = upstreamUrl.Host
	req.URL.Path = upstreamUrl.Path + req.URL.Path
	req.URL.Scheme = upstreamUrl.Scheme
	req.Header.Set("Authorization", "Bearer "+ServiceAccountToken)

	logRequest(req)

	req.RequestURI = ""
	originServerResponse, err := http.DefaultClient.Do(req)
	if err != nil {
		logAndWriteError(rw, "Error while calling upstream", http.StatusForbidden, err)
		return
	}

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

func isAuthorized(req *http.Request) bool {
	return req.Header.Get("Authorization") != ""
}

func getBearerToken(req *http.Request) string {
	return req.Header.Get("Authorization")[7:]
}

func isValidToken(token *jwt.Token) bool {
	return token.Valid || C.Dev.Enabled
}

func logAndWriteError(rw http.ResponseWriter, message string, statusCode int, err error) {
	Logger.Error(message, zap.Error(err))
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprint(rw, message+"\n")
}

func logRequest(req *http.Request) {
	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		Logger.Error("Error while dumping request", zap.Error(err))
	}
	Logger.Debug("Request", zap.String("request", string(dump)))
}

func parseJwtToken(tokenString string) (KeycloakToken, *jwt.Token, error) {
	keycloakToken := KeycloakToken{}
	token, err := jwt.ParseWithClaims(tokenString, &keycloakToken, Jwks.Keyfunc)
	return keycloakToken, token, err
}
