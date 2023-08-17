package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

type Enforcer interface {
	EnforceQL(string, map[string]bool, string) (string, error)
}

type Request struct {
	queryMatch string
	http.ResponseWriter
	*http.Request
	Enforcer
}

func (r *Request) enforce(ls Labelstore, labelMatch string) error {
	if r.Context().Value(SkipCtx).(bool) {
		return nil
	}

	token := r.Context().Value(KeycloakCtxToken).(KeycloakToken)
	Logger.Info("Got token", zap.Any("token", token))
	tenantLabels := ls.GetLabels(token)
	if len(tenantLabels) < 1 {
		logAndWriteError(r.ResponseWriter, http.StatusForbidden, nil, "No tenant labels found")
		return fmt.Errorf("no tenant labels found")
	}
	query, err := r.EnforceQL(r.Request.URL.Query().Get(r.queryMatch), tenantLabels, labelMatch)
	if err != nil {
		logAndWriteError(r.ResponseWriter, http.StatusForbidden, err, "")
		return err
	}
	if r.Method == http.MethodPost {
		err = r.enforcePost(query)
		if err != nil {
			logAndWriteError(r.ResponseWriter, http.StatusForbidden, err, "")
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

func (r *Request) callUpstream(upstream *url.URL, useMutualTLS bool, sa string) {
	Logger.Debug("Doing request")
	if useMutualTLS {
		r.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sa))
		Logger.Debug("Set Authorization header")
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ServeHTTP(r.ResponseWriter, r.Request)
}
