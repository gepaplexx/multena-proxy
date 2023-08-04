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

// Route struct defines a route in the application with a URL and a matching word for label enforcement.
type Route struct {
	Url       string
	MatchWord string
}

// EnforceFunc is a function type that enforces tenant restrictions on a string given a map of tenant labels.
// It returns a string and an error.
type EnforceFunc func(string, map[string]bool) (string, error)

// Datasource struct represents a data source with an upstream URL, an EnforceFunc function, and a UseMutualTLS flag.
type Datasource struct {
	UpstreamURL  *url.URL
	EnforceFunc  EnforceFunc
	UseMutualTLS bool
}

// contextKey is a string type that represents a context key.
type contextKey string

// DatasourceKey and KeycloakCtxToken are the context keys used in the application.
const DatasourceKey contextKey = "datasource"
const KeycloakCtxToken contextKey = "keycloakToken"

// application function initializes the application's HTTP router. It configures routes for the Loki and Thanos APIs,
// and applies middleware for logging, authentication, and setting the data source in the request context.
// It returns an external router, an internal router, and an error.
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

// setDatasource function is a middleware that sets a Datasource in the request context.
// It takes a Datasource and returns a middleware function.
func setDatasource(ds Datasource) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), DatasourceKey, ds)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
