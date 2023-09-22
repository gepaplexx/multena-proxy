package main

import (
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

type EnforceQL interface {
	Enforce(query string, tenantLabels map[string]bool, labelMatch string) (string, error)
}

func enforceGet(r *http.Request, enforce EnforceQL, tenantLabels map[string]bool, labelMatch string, queryMatch string) error {
	log.Trace().Str("kind", "urlmatch").Str("queryMatch", queryMatch).Str("query", r.URL.Query().Get("query")).Str("match[]", r.URL.Query().Get("match[]")).Msg("")

	query, err := enforce.Enforce(r.URL.Query().Get(queryMatch), tenantLabels, labelMatch)
	if err != nil {
		return err
	}

	values := r.URL.Query()
	values.Set(queryMatch, query)
	r.URL.RawQuery = values.Encode()

	r.Body = io.NopCloser(strings.NewReader(""))
	r.ContentLength = 0
	return nil
}

func enforcePost(r *http.Request, enforce EnforceQL, tenantLabels map[string]bool, labelMatch string, queryMatch string) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	log.Trace().Str("kind", "bodymatch").Str("queryMatch", queryMatch).Str("query", r.PostForm.Get("query")).Str("match[]", r.PostForm.Get("match[]")).Msg("")

	query := r.PostForm.Get(queryMatch)
	query, err := enforce.Enforce(query, tenantLabels, labelMatch)
	if err != nil {
		return err
	}

	_ = r.Body.Close()
	r.PostForm.Set(queryMatch, query)
	newBody := r.PostForm.Encode()
	r.Body = io.NopCloser(strings.NewReader(newBody))
	r.ContentLength = int64(len(newBody))
	r.URL.RawQuery = ""
	return nil
}
