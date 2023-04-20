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
	dump, err := httputil.DumpRequest(req, true)
	if err != nil {
		Logger.Error("Error while dumping request", zap.Error(err))
	}
	Logger.Debug("Request", zap.String("request", string(dump)), zap.Int("line", 50))
	if req.Header.Get("Authorization") == "" {
		Logger.Warn("No Authorization header found", zap.Int("line", 52))
		rw.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(rw, "No Authorization header found\n")
		return
	}

	//parse jwt from request
	if len(req.Header.Get("Authorization")) < 7 {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(rw, "error while parsing token\n")
		return
	}
	tokenString := req.Header.Get("Authorization")[7:]
	keycloakToken := KeycloakToken{}
	token, err := jwt.ParseWithClaims(tokenString, &keycloakToken, Jwks.Keyfunc)
	if err != nil && !C.Dev.Enabled {
		rw.WriteHeader(http.StatusForbidden)
		Logger.Error("Error parsing Keycloak token", zap.Error(err), zap.Int("line", 68))
		_, _ = fmt.Fprint(rw, "Error parsing Keycloak token\n")
		return
	}

	//if token invalid or expired, return 401
	if !token.Valid && !C.Dev.Enabled {
		rw.WriteHeader(http.StatusForbidden)
		Logger.Debug("Invalid token", zap.Any("token", token), zap.Int("line", 76))
		_, _ = fmt.Fprint(rw, "error while parsing token\n")
		return
	}

	//if user in admin group
	var upstreamUrl *url.URL
	if ContainsIgnoreCase(keycloakToken.Groups, C.Proxy.AdminGroup) || ContainsIgnoreCase(keycloakToken.ApaGroupsOrg, C.Proxy.AdminGroup) {
		upstreamUrl, err = url.Parse(C.Proxy.UpstreamBypassURL)
		if err != nil {
			Logger.Error("Error parsing upstream url", zap.Error(err), zap.Int("line", 86))
			_, _ = fmt.Fprint(rw, "Error parsing upstream url\n")
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
			Logger.Error("No provider set", zap.Int("line", 100))
			_, _ = fmt.Fprint(rw, "Internal Server Error\n")
			return
		}

		if len(tenantLabels) <= 0 {
			rw.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(rw, "Forbidden\n")
			return
		}

		Logger.Debug("username", zap.String("username", keycloakToken.PreferredUsername), zap.Int("line", 105))
		Logger.Debug("Labels", zap.Any("tenantLabels", tenantLabels), zap.Int("line", 106))

		if req.Header.Get("X-Plugin-Id") == "loki" || req.URL.Path[:13] == "/loki/api/v1/" {
			upstreamUrl, err = url.Parse(C.Proxy.UpstreamURLLoki)
			if err != nil {
				Logger.Error("Error parsing upstream url", zap.Error(err), zap.Int("line", 111))
				_, _ = fmt.Fprint(rw, "Internal Server Error\n")
				return
			}
			query := req.URL.Query().Get("query")
			query, err = logqlEnforcer(query, tenantLabels)
			if err != nil {
				rw.WriteHeader(http.StatusForbidden)
				Logger.Error("Error parsing rewritten query", zap.Error(err), zap.Int("line", 118))
				_, _ = fmt.Fprint(rw, err)
				return
			}
			values := req.URL.Query()
			values.Set("query", query)
			req.URL.RawQuery = values.Encode()

		}
		if req.Header.Get("X-Plugin-Id") == "thanos" {
			URL := req.URL.String()
			req.URL, err = url.Parse(UrlRewriter(URL, tenantLabels, C.Proxy.TenantLabel))
			if err != nil {
				rw.WriteHeader(http.StatusForbidden)
				Logger.Error("Error parsing rewritten url", zap.Error(err), zap.Int("line", 174))
				_, _ = fmt.Fprint(rw, "Error parsing rewritten url\n")
				return
			}

			//proxy request to origin server
			upstreamUrl, err = url.Parse(C.Proxy.UpstreamURL)
			if err != nil {
				rw.WriteHeader(http.StatusForbidden)
				Logger.Error("Error parsing upstream url", zap.Error(err))
				_, _ = fmt.Fprint(rw, "Error parsing upstream url\n")
				return
			}
		}

	}

	req.Host = upstreamUrl.Host
	req.URL.Host = upstreamUrl.Host
	req.URL.Path = upstreamUrl.Path + req.URL.Path
	req.URL.Scheme = upstreamUrl.Scheme

	req.Header.Set("Authorization", "Bearer "+ServiceAccountToken)

	Logger.Debug("Query", zap.String("query", req.URL.String()), zap.Int("line", 196))

	//clear request URI
	dump, err = httputil.DumpRequest(req, true)
	if err != nil {
		Logger.Error("Error while dumping request", zap.Error(err))
	}
	Logger.Debug("Client request", zap.String("request", string(dump)), zap.Int("line", 159))
	req.RequestURI = ""
	originServerResponse, err := http.DefaultClient.Do(req)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(rw, err)
		if err != nil {
			Logger.Error("Error making request to origin", zap.Error(err), zap.Int("line", 207))
		}
		return
	}

	originBody, err := io.ReadAll(originServerResponse.Body)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		Logger.Error("Error reading origin response", zap.Error(err), zap.Int("line", 214))
		_, _ = fmt.Fprint(rw, "Error reading origin response\n")
		return
	}

	Logger.Debug("Upstream Response", zap.Any("header", originServerResponse.Header), zap.String("body", string(originBody)), zap.Int("line", 220))

	// return response to the client
	rw.WriteHeader(http.StatusOK)
	_, err = rw.Write(originBody)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		Logger.Error("Error writing origin response to client", zap.Error(err), zap.Int("line", 226))
		_, _ = fmt.Fprint(rw, "Error writing origin response to client\n")
		return
	}

	Logger.Debug("Finished Client request", zap.Int("line", 231))
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			Logger.Error("Error closing body", zap.Error(err), zap.Int("line", 235))
			_, _ = fmt.Fprint(rw, "Error closing body\n")
			return
		}
	}(originServerResponse.Body)
}
