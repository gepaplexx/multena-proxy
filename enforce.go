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
	http.ResponseWriter
	*http.Request
	Enforcer
}

func (r *Request) enforce(queryMatch string, ls Labelstore, labelMatch string) error {
	log.Trace().Str("match", queryMatch).Msg("")
	log.Trace().Str("kind", "urlmatch").Str("query", r.Request.URL.Query().Get("query")).Str("match[]", r.Request.URL.Query().Get("match[]")).Msg("")
	token, ok := r.Context().Value(KeycloakCtxToken).(KeycloakToken)
	if !ok {
		logAndWriteError(r.ResponseWriter, http.StatusForbidden, nil, "No token found")
		return fmt.Errorf("no token found")
	}
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

	if r.Method == http.MethodGet {
		query, err := r.EnforceQL(r.Request.URL.Query().Get(queryMatch), tenantLabels, labelMatch)
		if err != nil {
			logAndWriteError(r.ResponseWriter, http.StatusForbidden, err, "")
			return err
		}
		values := r.URL.Query()
		log.Trace().Str("match", queryMatch).Str("query", query).Msg("Updating query")
		values.Set(queryMatch, query)
		r.URL.RawQuery = values.Encode()
		log.Trace().Str("url", r.URL.String()).Msg("Updated URL")
		return nil
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			logAndWriteError(r.ResponseWriter, http.StatusForbidden, err, "")
		}
		log.Trace().Str("kind", "urlmatch").Str("query", r.PostForm.Get("query")).Str("match[]", r.PostForm.Get("match[]")).Msg("")
		query := r.PostForm.Get(queryMatch)
		query, err := r.EnforceQL(query, tenantLabels, labelMatch)
		if err != nil {
			logAndWriteError(r.ResponseWriter, http.StatusForbidden, err, "")
			return err
		}
		_ = r.Body.Close()
		r.PostForm.Set(queryMatch, query)
		newBody := r.PostForm.Encode()
		r.Body = io.NopCloser(strings.NewReader(newBody))
		r.ContentLength = int64(len(newBody))
		return nil
	}
	logAndWriteError(r.ResponseWriter, http.StatusForbidden, nil, "Invalid method")
	return fmt.Errorf("invalid method")
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
