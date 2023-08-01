package main

import (
	"go.uber.org/zap"
	"io"
	"net/http"
	"strings"
)

func enforce(req *http.Request, tenantLabels map[string]bool, urlKey string, enforceFunc func(string, map[string]bool) (string, error)) error {
	query, err := enforceFunc(req.URL.Query().Get(urlKey), tenantLabels)
	if err != nil {
		return err
	}
	updateGetQuery(req, urlKey, query)
	Logger.Debug("Set query")
	return nil
}

func updateGetQuery(req *http.Request, urlKey string, query string) {
	values := req.URL.Query()
	values.Set(urlKey, query)
	req.URL.RawQuery = values.Encode()
}

func enforcePost(req *http.Request, tenantLabels map[string]bool, urlKey string, enforceFunc func(string, map[string]bool) (string, error)) error {
	if err := req.ParseForm(); err != nil {
		return err
	}
	Logger.Debug("Parsed form", zap.Any("form", req.PostForm))
	query, err := enforceFunc(req.PostForm.Get(urlKey), tenantLabels)
	if err != nil {
		return err
	}
	updatePostBody(req, urlKey, query)
	return nil
}

func updatePostBody(req *http.Request, urlKey string, query string) {
	// We are replacing request body, close previous one (ParseForm ensures it is read fully and not nil).
	_ = req.Body.Close()
	req.PostForm.Set(urlKey, query)
	newBody := req.PostForm.Encode()
	req.Body = io.NopCloser(strings.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
}
