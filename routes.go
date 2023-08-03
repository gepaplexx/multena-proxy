package main

import (
	"context"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"net/http/pprof"
	"net/url"
)

type Route struct {
	Url       string
	MatchWord string
}

type EnforceFunc func(string, map[string]bool) (string, error)

type Datasource struct {
	UpstreamURL  *url.URL
	EnforceFunc  EnforceFunc
	UseMutualTLS bool
}

type contextKey string

const DatasourceKey contextKey = "datasource"
const KeycloakCtxToken contextKey = "keycloakToken"

// application initializes the application's HTTP router
func application() (*mux.Router, *mux.Router, error) {

	lokiUrl, err := url.Parse(Cfg.Loki.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing Loki URL: %v", err)
	}

	thanosUrl, err := url.Parse(Cfg.Thanos.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing Thanos URL: %v", err)
	}

	i := mux.NewRouter()
	i.HandleFunc("/health", HealthCheckHandler)
	i.HandleFunc("/debug/pprof/", pprof.Index)
	i.Handle("/metrics", promhttp.Handler())

	routes := []Route{
		{Url: "/api/v1/query", MatchWord: "query"},
		{Url: "/api/v1/query_range", MatchWord: "query"},
		{Url: "/api/v1/label/{name}/values", MatchWord: "query"},
		{Url: "/api/v1/series", MatchWord: "match[]"},
		{Url: "/api/v1/tail", MatchWord: "query"},
		{Url: "/api/v1/index/stats", MatchWord: "query"},
		{Url: "/api/v1/format_query", MatchWord: "query"},
		{Url: "/api/v1/labels", MatchWord: "match[]"},
		{Url: "/api/v1/label/{label}/values", MatchWord: "match[]"},
		{Url: "/api/v1/query_exemplars", MatchWord: "query"},
		{Url: "/api/v1/status/buildinfo", MatchWord: "query"},
	}

	e := mux.NewRouter()

	lokiRouter := e.PathPrefix("/loki").Subrouter()
	thanosRouter := e.PathPrefix("").Subrouter()

	lokiRouter.Use(setDatasource(Datasource{
		UpstreamURL:  lokiUrl,
		EnforceFunc:  logqlEnforcer,
		UseMutualTLS: Cfg.Loki.UseMutualTLS,
	}))
	thanosRouter.Use(setDatasource(Datasource{
		UpstreamURL:  thanosUrl,
		EnforceFunc:  promqlEnforcer,
		UseMutualTLS: Cfg.Thanos.UseMutualTLS,
	}))

	e.Use(loggingMiddleware)
	e.Use(authMiddleware)

	for _, route := range routes {
		handleRoute(lokiRouter, route)
		handleRoute(thanosRouter, route)
	}

	e.SkipClean(true)
	return e, i, nil
}

func setDatasource(ds Datasource) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), DatasourceKey, ds)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
