package main

import (
	"net/http"
	"net/http/pprof"
	"net/url"

	"github.com/rs/zerolog/log"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Route struct defines a route in the application with a URL and a matching word for label enforcement.
type Route struct {
	Url       string
	MatchWord string
}

// contextKey is a string type that represents a context key.
type contextKey string

// KeycloakCtxToken are the context keys used in the application.
const (
	KeycloakCtxToken contextKey = "keycloakToken"
)

var routes = []Route{
	{Url: "/api/v1/query", MatchWord: "query"},
	{Url: "/api/v1/query_range", MatchWord: "query"},
	{Url: "/api/v1/series", MatchWord: "match[]"},
	{Url: "/api/v1/tail", MatchWord: "query"},
	{Url: "/api/v1/index/stats", MatchWord: "query"},
	{Url: "/api/v1/format_query", MatchWord: "query"},
	{Url: "/api/v1/labels", MatchWord: "match[]"},
	{Url: "/api/v1/label/{label}/values", MatchWord: "match[]"},
	{Url: "/api/v1/query_exemplars", MatchWord: "query"},
	{Url: "/api/v1/status/buildinfo", MatchWord: "query"},
}

func (a *App) WithRoutes() *App {
	e := mux.NewRouter()
	e.Use(a.loggingMiddleware)
	e.Use(a.authMiddleware)
	e.SkipClean(true)
	a.e = e
	return a
}

func (a *App) WithHealthz() *App {
	i := mux.NewRouter()
	a.healthy = true
	i.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if a.healthy {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Ok"))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Not Ok"))
		}
	})
	i.HandleFunc("/debug/pprof/", pprof.Index)
	i.Handle("/metrics", promhttp.Handler())
	a.i = i
	return a
}

func (a *App) WithLoki() *App {
	if a.Cfg.Loki.URL == "" {
		return a
	}
	lokiUrl, err := url.Parse(a.Cfg.Loki.URL)
	if err != nil {
		log.Fatal().Err(err).Msg("Error parsing Loki URL")
	}
	lokiRouter := a.e.PathPrefix("/loki").Subrouter()
	for _, route := range routes {
		log.Trace().Any("route", route).Msg("Loki route")
		lokiRouter.HandleFunc(route.Url, func(w http.ResponseWriter, r *http.Request) {
			req := Request{w, r, LogQLEnforcer{}}
			err := req.enforce(route.MatchWord, a.LabelStore, a.Cfg.Loki.TenantLabel)
			if err != nil {
				return
			}
			req.callUpstream(lokiUrl, a.Cfg.Loki.UseMutualTLS, a.ServiceAccountToken)
		}).Name(route.Url)
	}
	return a
}

func (a *App) WithThanos() *App {
	if a.Cfg.Thanos.URL == "" {
		return a
	}
	thanosUrl, err := url.Parse(a.Cfg.Thanos.URL)
	if err != nil {
		log.Fatal().Err(err).Msg("Error parsing Thanos URL")
	}
	thanosRouter := a.e.PathPrefix("").Subrouter()
	for _, route := range routes {
		log.Trace().Any("route", route).Msg("Thanos route")
		thanosRouter.HandleFunc(route.Url, handler(route.MatchWord, PromQLEnforcer{},
			a.LabelStore,
			a.Cfg.Thanos.TenantLabel,
			thanosUrl,
			a.Cfg.Thanos.UseMutualTLS,
			a.ServiceAccountToken)).Name(route.Url)
	}
	return a
}

func handler(matchWord string, enforcer Enforcer, ls Labelstore, tl string, url *url.URL, tls bool, sat string) func(http.ResponseWriter, *http.Request) {
	fun := func(w http.ResponseWriter, r *http.Request) {
		req := Request{w, r, enforcer}
		err := req.enforce(matchWord, ls, tl)
		if err != nil {
			return
		}
		req.callUpstream(url, tls, sat)
	}
	return fun
}
