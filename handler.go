package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// HealthCheckHandler is an HTTP handler that always returns an HTTP status of 200 and a response body of "Ok".
// It's commonly used for health checks.
func HealthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Ok"))
}

// handleRoute sets up a handler function for a given route
func handleRoute(r *mux.Router, route Route, thanosUrl *url.URL, lokiUrl *url.URL) error {
	datasourceURL, enforceFunc, err := getRouteConfiguration(route, thanosUrl, lokiUrl)
	if err != nil {
		return fmt.Errorf("error getting route configuration: %v", err)
	}

	r.HandleFunc(route.Url, func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value(kkToken{}).(KeycloakToken)
		if !isAdmin(token) {
			labels := GetLabelsFunc(token)
			if len(labels) <= 0 {
				logAndWriteError(w, http.StatusForbidden, err, "No tenant labels found")
			}
			err = enforce(r, labels, route.MatchWord, enforceFunc)
			if err != nil {
				logAndWriteError(w, http.StatusForbidden, err, "")
				return
			}
			if r.Method == "POST" {
				err = enforcePost(r, labels, route.MatchWord, enforceFunc)
				if err != nil {
					logAndWriteError(w, http.StatusForbidden, err, "")
					return
				}
			}
		}
		callUpstream(w, r, datasourceURL)
	})

	return nil
}

func callUpstream(rw http.ResponseWriter, req *http.Request, upstream *url.URL) {
	Logger.Debug("Doing request")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ServiceAccountToken))
	Logger.Debug("Set Authorization header")

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ServeHTTP(rw, req)
}