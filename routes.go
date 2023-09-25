package main

import (
	"fmt"
	"golang.org/x/exp/maps"
	"net/http"
	"net/http/httputil"
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

func (a *App) WithRoutes() *App {
	e := mux.NewRouter()
	e.Use(a.loggingMiddleware)
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
	routes := []Route{
		{Url: "/api/v1/query", MatchWord: "query"},
		{Url: "/api/v1/query_range", MatchWord: "query"},
		{Url: "/api/v1/series", MatchWord: "match[]"},
		{Url: "/api/v1/tail", MatchWord: "query"},
		{Url: "/api/v1/index/stats", MatchWord: "query"},
		{Url: "/api/v1/format_query", MatchWord: "query"},
		{Url: "/api/v1/labels", MatchWord: "query"},
		{Url: "/api/v1/label/{label}/values", MatchWord: "query"},
		{Url: "/api/v1/query_exemplars", MatchWord: "query"},
		{Url: "/api/v1/status/buildinfo", MatchWord: "query"},
	}
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
		lokiRouter.HandleFunc(route.Url, handler(route.MatchWord,
			LogQLEnforcer(struct{}{}),
			a.Cfg.Loki.TenantLabel,
			lokiUrl,
			a.Cfg.Loki.UseMutualTLS,
			a)).Name(route.Url)
	}
	return a
}

func (a *App) WithThanos() *App {
	routes := []Route{
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
		thanosRouter.HandleFunc(route.Url,
			handler(route.MatchWord,
				PromQLEnforcer(struct{}{}),
				a.Cfg.Thanos.TenantLabel,
				thanosUrl,
				a.Cfg.Thanos.UseMutualTLS,
				a)).Name(route.Url)

	}
	return a
}

func handler(matchWord string, enforcer EnforceQL, tl string, url *url.URL, tls bool, a *App) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var tenantLabels map[string]bool
		var err error
		var skip bool
		authToken, err := getBearerToken(r)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

		keycloakToken, token, err := parseJwtToken(authToken, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "error parsing Keycloak token")
			return
		}
		if !token.Valid {
			logAndWriteError(w, http.StatusForbidden, nil, "invalid token")
			return
		}

		if isAdmin(keycloakToken, a) {
			log.Debug().Str("user", keycloakToken.PreferredUsername).Bool("Admin", true).Msg("Skipping label enforcement")
			goto streamup
		}

		tenantLabels, skip = a.LabelStore.GetLabels(keycloakToken)
		if skip {
			log.Debug().Str("user", keycloakToken.PreferredUsername).Bool("Admin", false).Msg("Skipping label enforcement")
			goto streamup
		}
		log.Debug().Str("user", keycloakToken.PreferredUsername).Strs("labels", maps.Keys(tenantLabels)).Msg("")

		if len(tenantLabels) < 1 {
			logAndWriteError(w, http.StatusForbidden, nil, "No tenant labels found")
			return
		}

		switch r.Method {
		case http.MethodGet:
			err = enforceGet(r, enforcer, tenantLabels, tl, matchWord)
		case http.MethodPost:
			err = enforcePost(r, enforcer, tenantLabels, tl, matchWord)
		default:
			logAndWriteError(w, http.StatusForbidden, nil, "Invalid method")
			return
		}
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

	streamup:

		if !tls {
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.ServiceAccountToken))
		}
		proxy := httputil.NewSingleHostReverseProxy(url)
		proxy.ServeHTTP(w, r)
	}
}
