package main

import (
	"crypto/tls"
	"fmt"
	logqlv2 "github.com/gepaplexx/multena-proxy/logql/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/prometheus/prometheus/model/labels"
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
			fmt.Println("Error syncing logger", err)
			panic(err)
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
	return
}

func reverseProxy(rw http.ResponseWriter, req *http.Request) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dump, err := httputil.DumpRequest(req, true)
	Logger.Debug("Request", zap.String("request", fmt.Sprintf("%s", dump)))
	if req.Header.Get("Authorization") == "" {
		Logger.Warn("No Authorization header found")
		rw.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(rw, "No Authorization header found")
		return
	}

	//parse jwt from request
	if len(req.Header.Get("Authorization")) < 7 {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(rw, "error while parsing token")
		return
	}
	tokenString := req.Header.Get("Authorization")[7:]
	keycloakToken := KeycloakToken{}
	token, err := jwt.ParseWithClaims(tokenString, &keycloakToken, Jwks.Keyfunc)
	if err != nil {
		Logger.Error("Error parsing Keycloak token", zap.Error(err))
	}

	//if token invalid or expired, return 401
	if !token.Valid && !C.Dev.Enabled {
		rw.WriteHeader(http.StatusForbidden)
		Logger.Debug("Invalid token", zap.Any("token", token))
		_, _ = fmt.Fprint(rw, "error while parsing token")
		return
	}

	//if user in admin group
	var upstreamUrl *url.URL
	if ContainsIgnoreCase(keycloakToken.Groups, C.Proxy.AdminGroup) || ContainsIgnoreCase(keycloakToken.ApaGroupsOrg, C.Proxy.AdminGroup) {
		upstreamUrl, err = url.Parse(C.Proxy.UpstreamBypassURL)
		if err != nil {
			Logger.Error("Error parsing upstream url", zap.Error(err))
		}
	} else {
		var tenantLabels []string
		switch provider := C.Proxy.Provider; provider {
		case "project":
			tenantLabels = GetLabelsFromProject(keycloakToken.PreferredUsername)
		case "mysql":
			tenantLabels = GetLabelsFromDB(keycloakToken.Email)
		case "configmap":
			tenantLabels = GetLabelsCM(keycloakToken.PreferredUsername, keycloakToken.Groups)
		default:
			Logger.Error("No provider set")
		}

		Logger.Debug("username", zap.String("username", keycloakToken.PreferredUsername))
		Logger.Debug("Labels", zap.Any("tenantLabels", tenantLabels))

		if req.Header.Get("X-Plugin-Id") == "loki" {
			upstreamUrl, err = url.Parse(C.Proxy.UpstreamURLLoki)
			if err != nil {
				Logger.Error("Error parsing upstream url", zap.Error(err))
			}
			query := req.URL.Query().Get("query")
			if query == "" {
				query = "{__name__=~\".+\"}"
			}

			Logger.Debug("query", zap.String("query", query))

			expr, err := logqlv2.ParseExpr(query)
			if err != nil {
				Logger.Error("Error parsing query url", zap.Error(err))
			}

			l := []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: strings.Join(tenantLabels, "|"),
				},
			}

			expr.Walk(func(e interface{}) {
				switch ex := e.(type) { //nolint:gocritic
				case *logqlv2.StreamMatcherExpr:
					ex.AppendMatchers(l)
				}
			})

			Logger.Debug("query", zap.String("query", expr.String()))

			query, err = enforceNamespaces(query, tenantLabels)
			if err != nil {
				Logger.Error("Error parsing query url", zap.Error(err))
			}

			q := req.URL.Query()
			q.Set("query", expr.String())
			req.URL.RawQuery = q.Encode()

		} else {
			URL := req.URL.String()
			req.URL, err = url.Parse(UrlRewriter(URL, tenantLabels, C.Proxy.TenantLabel))
			if err != nil {
				Logger.Error("Error parsing rewritten url", zap.Error(err))
			}

			//proxy request to origin server
			upstreamUrl, err = url.Parse(C.Proxy.UpstreamURL)
			if err != nil {
				Logger.Error("Error parsing upstream url", zap.Error(err))
			}
		}

	}

	req.Host = upstreamUrl.Host
	req.URL.Host = upstreamUrl.Host
	req.URL.Scheme = upstreamUrl.Scheme
	req.Header.Set("Authorization", "Bearer "+ServiceAccountToken)

	Logger.Debug("Query", zap.String("query", req.URL.String()))

	//clear request URI
	dump, err = httputil.DumpRequest(req, true)
	Logger.Debug("Client request", zap.String("request", fmt.Sprintf("%s", dump)))
	req.RequestURI = ""
	originServerResponse, err := http.DefaultClient.Do(req)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(rw, err)
		if err != nil {
			Logger.Error("Error making request to origin", zap.Error(err))
		}
		return
	}

	originBody, err := io.ReadAll(originServerResponse.Body)
	if err != nil {
		Logger.Error("Error reading origin response", zap.Error(err))
	}

	//originServerResponseDump, err := httputil.DumpResponse(originServerResponse, true)
	Logger.Debug("Upstream Response", zap.Any("header", originServerResponse.Header), zap.String("body", fmt.Sprintf("%s", originBody)))

	// return response to the client
	rw.WriteHeader(http.StatusOK)
	_, err = rw.Write(originBody)
	if err != nil {
		Logger.Error("Error writing origin response to client", zap.Error(err))
	}

	Logger.Debug("Finished Client request")
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			Logger.Error("Error closing body", zap.Error(err))
		}
	}(originServerResponse.Body)
}
