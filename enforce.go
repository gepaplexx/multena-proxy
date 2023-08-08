package main

import (
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// enforce is a function that enforces tenant restrictions on the provided HTTP request.
// It takes an HTTP request, a map of tenant labels, a url key (which represents the part of the URL
// where the query is located), and a function enforceFunc that is used to enforce restrictions.
// It retrieves the query from the URL using the provided key, enforces the restrictions using enforceFunc,
// and updates the query in the URL with the enforced query.
// It logs the fact that the query was set and returns an error if any occurs during the process.
func enforce(req *http.Request, tenantLabels map[string]bool, urlKey string, enforceFunc func(string, map[string]bool) (string, error)) error {
	query, err := enforceFunc(req.URL.Query().Get(urlKey), tenantLabels)
	if err != nil {
		return err
	}
	updateGetQuery(req, urlKey, query)
	Logger.Debug("Set query")
	return nil
}

// updateGetQuery is a function that updates the query in the URL of the provided HTTP request.
// It takes an HTTP request, a url key (which represents the part of the URL where the query is located),
// and a query. It sets the query in the URL using the provided key and the provided query.
func updateGetQuery(req *http.Request, urlKey string, query string) {
	values := req.URL.Query()
	values.Set(urlKey, query)
	req.URL.RawQuery = values.Encode()
}

// enforcePost is a function that enforces tenant restrictions on the provided HTTP POST request.
// It takes an HTTP POST request, a map of tenant labels, a url key (which represents the part of the URL
// where the query is located), and a function enforceFunc that is used to enforce restrictions.
// It parses the form data from the request, retrieves the query from the form using the provided key,
// enforces the restrictions using enforceFunc, and updates the form data in the body of the request
// with the enforced query. It returns an error if any occurs during the process.
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

// updatePostBody is a function that updates the form data in the body of the provided HTTP POST request.
// It takes an HTTP POST request, a url key (which represents the part of the URL where the query is located),
// and a query. It sets the query in the form data using the provided key and the provided query,
// replaces the body of the request with the updated form data, and sets the ContentLength header
// to the length of the new body.
func updatePostBody(req *http.Request, urlKey string, query string) {
	// We are replacing request body, close previous one (ParseForm ensures it is read fully and not nil).
	_ = req.Body.Close()
	req.PostForm.Set(urlKey, query)
	newBody := req.PostForm.Encode()
	req.Body = io.NopCloser(strings.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
}
