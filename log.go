package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

type requestData struct {
	Method string      `json:"method"`
	URL    string      `json:"url"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

// loggingMiddleware returns a middleware that logs details of incoming HTTP requests and passes control to the next HTTP handler in the chain.
// If configuration allows for logging tokens, the request body is read and logged.
// Otherwise, the body content is redacted.
func (a *App) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyBytes []byte
		if a.Cfg.Log.LogTokens {
			bodyBytes = readBody(r)
		} else {
			bodyBytes = []byte("[REDACTED]")
		}
		// log.Trace().Any("Request", r.Header).Msg("")
		logRequestData(r, bodyBytes, a.Cfg.Log.LogTokens)
		next.ServeHTTP(w, r)
		log.Debug().Str("path", r.URL.Path).Msg("Request complete")
	})
}

// readBody reads and returns the entire request body.
// If an error occurs during reading, it logs the error and returns nil.
// Note that this function also resets the request's Body to ensure it can be read again by subsequent handlers.
func readBody(r *http.Request) []byte {
	var bodyBytes []byte
	var err error
	if r.Body != nil {
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			log.Error().Err(err).Msg("")
			return nil
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	return bodyBytes
}

// logRequestData logs the specified request's details, including method, headers, and optionally, body content.
// If logToken is false, sensitive headers are cleaned before logging.
// If the request data cannot be marshaled to JSON, an error is logged.
func logRequestData(r *http.Request, bodyBytes []byte, logToken bool) {
	rd := requestData{r.Method, r.URL.String(), r.Header, string(bodyBytes)}
	if logToken {
		rd.Header = cleanSensitiveHeaders(rd.Header)
	}
	jsonData, err := json.Marshal(rd)
	if err != nil {
		log.Error().Err(err).Msg("Error while marshalling request")
		return
	}
	log.Debug().Str("verb", r.Method).Str("request", string(jsonData)).Str("path", r.URL.Path).Msg("")
}

// cleanSensitiveHeaders creates and returns a copy of the provided HTTP headers with sensitive headers removed.
// Sensitive headers like "Authorization", "X-Plugin-Id", and "X-Id-Token" are deleted to prevent them from being logged.
func cleanSensitiveHeaders(headers http.Header) http.Header {
	copyHeader := make(http.Header)
	for k, v := range headers {
		copyHeader[k] = v
	}
	copyHeader.Del("Authorization")
	copyHeader.Del("X-Plugin-Id")
	copyHeader.Del("X-Id-Token")
	return copyHeader
}

// logAndWriteError logs the provided error and message at the Trace level and writes them to the ResponseWriter along with the specified status code.
// If the message is an empty string, the error's message is written instead.
func logAndWriteError(rw http.ResponseWriter, statusCode int, err error, message string) {
	if message == "" {
		message = fmt.Sprint(err)
	}
	log.Trace().Err(err).Msg(message)
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprint(rw, message+"\n")
}
