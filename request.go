package main

import (
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type Enforcer interface {
	EnforceQL(string, map[string]bool) (string, error)
}

type Request struct {
	queryMatch string
	http.ResponseWriter
	*http.Request
	Enforcer
}

func (r *Request) enforce(p Provider) error {
	token := r.Context().Value(KeycloakCtxToken).(KeycloakToken)
	if isAdmin(token) {
		return nil
	}
	tenantLabels := p.GetLabels(token)
	query, err := r.EnforceQL(r.Request.URL.Query().Get(r.queryMatch), tenantLabels)
	if err != nil {
		return err
	}
	if r.Method == http.MethodPost {
		err := r.enforcePost(query)
		if err != nil {
			return err
		}
	}
	r.updateQuery(query)
	return nil
}

func (r *Request) updateQuery(query string) {
	values := r.URL.Query()
	values.Set(r.queryMatch, query)
	r.URL.RawQuery = values.Encode()
}

func (r *Request) enforcePost(query string) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	Logger.Debug("Parsed form", zap.Any("form", r.PostForm))
	_ = r.Body.Close()
	r.PostForm.Set(r.queryMatch, query)
	newBody := r.PostForm.Encode()
	r.Body = io.NopCloser(strings.NewReader(newBody))
	r.ContentLength = int64(len(newBody))
	return nil
}

func (r *Request) callUpstream(upstream *url.URL, useMutualTLS bool) {
	Logger.Debug("Doing request")
	if useMutualTLS {
		r.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ServiceAccountToken))
		Logger.Debug("Set Authorization header")
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ServeHTTP(r.ResponseWriter, r.Request)
}
