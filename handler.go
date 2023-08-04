package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// HealthCheckHandler is a HTTP handler function that always responds with
// HTTP status code 200 and body "Ok". It is typically used for health check endpoints.
func HealthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Ok"))
}

// handleRoute is a function that handles a specific Route for a mux.Router.
// It registers a handler function to the route URL, which does the following:
// - It retrieves a Datasource and a KeycloakToken from the request context.
// - If the token does not represent an admin user, it does the following:
//   - It retrieves tenant labels using GetLabelsFunc function.
//   - If no tenant labels were found, it returns an HTTP status of 403 and an error message.
//   - Otherwise, it enforces tenant restrictions on the request using the EnforceFunc function of the Datasource.
//   - If an error occurred while enforcing, it returns an HTTP status of 403 and the error message.
//   - If the request method is "POST", it enforces tenant restrictions on the request body.
//   - If an error occurred while enforcing, it returns an HTTP status of 403 and the error message.
//
// - It calls the upstream URL using callUpstream function.
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
		callUpstream(w, r, ds.UpstreamURL, ds.UseMutualTLS)
	})
}

// callUpstream is a function that forwards the HTTP request to an upstream URL using a reverse proxy.
// It takes a ResponseWriter to write the response to, an HTTP request, an upstream URL, and a flag useMutualTLS that
// indicates whether mutual TLS authentication should be used.
// If useMutualTLS is true, it sets an Authorization header in the request.
// It creates a reverse proxy for the upstream URL and serves the request using the proxy.
func callUpstream(rw http.ResponseWriter, req *http.Request, upstream *url.URL, useMutualTLS bool) {
	Logger.Debug("Doing request")
	if useMutualTLS {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ServiceAccountToken))
		Logger.Debug("Set Authorization header")
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ServeHTTP(rw, req)
}
