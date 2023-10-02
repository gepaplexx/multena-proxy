package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"

	"github.com/rs/zerolog/log"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

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
	if a.Cfg.Loki.URL == "" {
		log.Warn().Msg("Loki URL not set, skipping Loki routes")
		return a
	}
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
	lokiRouter := a.e.PathPrefix("/loki").Subrouter()
	for _, route := range routes {
		log.Trace().Any("route", route).Msg("Loki route")
		lokiRouter.HandleFunc(route.Url, handler(route.MatchWord,
			LogQLEnforcer(struct{}{}),
			a.Cfg.Loki.TenantLabel,
			a.Cfg.Loki.URL,
			a.Cfg.Loki.UseMutualTLS,
			a.Cfg.Loki.Header,
			a)).Name(route.Url)
	}
	return a
}

func (a *App) WithThanos() *App {
	if a.Cfg.Thanos.URL == "" {
		log.Warn().Msg("Thanos URL not set, skipping Thanos routes")
		return a
	}
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
	thanosRouter := a.e.PathPrefix("").Subrouter()
	for _, route := range routes {
		log.Trace().Any("route", route).Msg("Thanos route")
		thanosRouter.HandleFunc(route.Url,
			handler(route.MatchWord,
				PromQLEnforcer(struct{}{}),
				a.Cfg.Thanos.TenantLabel,
				a.Cfg.Thanos.URL,
				a.Cfg.Thanos.UseMutualTLS,
				a.Cfg.Thanos.Header,
				a)).Name(route.Url)

	}
	return a
}

func handler(matchWord string, enforcer EnforceQL, tl string, dsURL string, tls bool, header map[string]string, a *App) func(http.ResponseWriter, *http.Request) {
	upstreamURL, err := url.Parse(dsURL)
	if err != nil {
		log.Fatal().Err(err).Str("url", dsURL).Msg("Error parsing URL")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		oauthToken, err := getToken(r, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "") //"error parsing OAuth token")
		}

		labels, skip, err := validateLabels(oauthToken, a)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}
		if skip {
			streamUp(w, r, upstreamURL, tls, header, a)
		}

		err = enforceRequest(r, enforcer, labels, tl, matchWord)
		if err != nil {
			logAndWriteError(w, http.StatusForbidden, err, "")
			return
		}

		streamUp(w, r, upstreamURL, tls, header, a)
	}
}

func streamUp(w http.ResponseWriter, r *http.Request, upstreamURL *url.URL, tls bool, header map[string]string, a *App) {
	setHeader(r, tls, header, a.ServiceAccountToken)
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.ServeHTTP(w, r)
}

func setHeader(r *http.Request, tls bool, header map[string]string, sat string) {
	if !tls {
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sat))
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
}
