package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
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
	log.Trace().Str("match", r.queryMatch).Msg("")
	token := r.Context().Value(KeycloakCtxToken).(KeycloakToken)
	tenantLabels, skip := ls.GetLabels(token)
	log.Trace().Any("token", token).Msg("Got token")
	log.Trace().Any("labels", tenantLabels).Bool("skip", skip).Msg("Got labels")
	if skip {
		log.Debug().Str("user", token.PreferredUsername).Msg("Skipping label enforcement")
		return nil
	}
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
	log.Trace().Str("match", r.queryMatch).Str("query", query).Msg("Updating query")
	values.Set(r.queryMatch, query)
	r.URL.RawQuery = values.Encode()
	log.Trace().Str("url", r.URL.String()).Msg("Updated URL")
}

func (r *Request) enforcePost(query string) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	log.Debug().Interface("form", r.PostForm).Msg("Parsed form")
	_ = r.Body.Close()
	r.PostForm.Set(r.queryMatch, query)
	newBody := r.PostForm.Encode()
	r.Body = io.NopCloser(strings.NewReader(newBody))
	r.ContentLength = int64(len(newBody))
	return nil
}

func (r *Request) callUpstream(upstream *url.URL, useMutualTLS bool, sa string) {
	log.Debug().Msg("Doing request")
	if !useMutualTLS {
		r.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sa))
		log.Debug().Msg("Set Authorization header")
	}

	log.Trace().Any("header", r.Request.Header).Msg("Request")

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ServeHTTP(r.ResponseWriter, r.Request)
}
