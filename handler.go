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
func handleRoute(r *mux.Router, route Route) {
	r.HandleFunc(route.Url, func(w http.ResponseWriter, r *http.Request) {
		ds := r.Context().Value(DatasourceKey).(Datasource)
		token := r.Context().Value(KeycloakCtxToken).(KeycloakToken)
		if !isAdmin(token) {
			labels := GetLabelsFunc(token)
			if len(labels) <= 0 {
				logAndWriteError(w, http.StatusForbidden, nil, "No tenant labels found")
				return
			}
			err := enforce(r, labels, route.MatchWord, ds.EnforceFunc)
			if err != nil {
				logAndWriteError(w, http.StatusForbidden, err, "")
				return
			}
			if r.Method == "POST" {
				err = enforcePost(r, labels, route.MatchWord, ds.EnforceFunc)
				if err != nil {
					logAndWriteError(w, http.StatusForbidden, err, "")
					return
				}
			}
		}
		callUpstream(w, r, ds.UpstreamURL)
	})
}

func callUpstream(rw http.ResponseWriter, req *http.Request, upstream *url.URL) {
	Logger.Debug("Doing request")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ServiceAccountToken))
	Logger.Debug("Set Authorization header")

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ServeHTTP(rw, req)
}
