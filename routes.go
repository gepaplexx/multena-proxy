package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http/pprof"
	"net/url"
)

type Route struct {
	Url        string
	Datasource string
	MatchWord  string
}

type kkToken struct{}

// application initializes the application's HTTP router
func application() (*mux.Router, *mux.Router, error) {

	i := mux.NewRouter()
	i.HandleFunc("/health", HealthCheckHandler)
	i.HandleFunc("/debug/pprof/", pprof.Index)
	i.Handle("/metrics", promhttp.Handler())

	e := mux.NewRouter()
	e.Use(loggingMiddleware)
	e.Use(authMiddleware)

	lokiUrl, err := url.Parse(Cfg.Loki.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing Loki URL: %v", err)
	}

	thanosUrl, err := url.Parse(Cfg.Thanos.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing Thanos URL: %v", err)
	}

	routes, err := setupRoutes()
	if err != nil {
		return nil, nil, fmt.Errorf("error setting up routes: %v", err)
	}

	for _, route := range routes {
		if err := handleRoute(e, route, thanosUrl, lokiUrl); err != nil {
			return nil, nil, fmt.Errorf("error handling route: %v", err)
		}
	}

	e.SkipClean(true)
	return e, i, nil
}

// getRouteConfiguration returns the corresponding URL and function for a route
func getRouteConfiguration(route Route, thanosUrl *url.URL, lokiUrl *url.URL) (*url.URL, func(string, map[string]bool) (string, error), error) {
	var datasourceURL *url.URL
	var enforceFunc func(string, map[string]bool) (string, error)

	if route.Datasource == "thanos" {
		datasourceURL = thanosUrl
		enforceFunc = promqlEnforcer
	} else if route.Datasource == "loki" {
		datasourceURL = lokiUrl
		enforceFunc = logqlEnforcer
	} else {
		return nil, nil, fmt.Errorf("unsupported datasource: %s", route.Datasource)
	}

	return datasourceURL, enforceFunc, nil
}

// setupRoutes sets up the application's routes
func setupRoutes() ([]Route, error) {
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
	return routes, nil
}
