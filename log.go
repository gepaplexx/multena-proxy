package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
)

type requestData struct {
	Method string      `json:"method"`
	URL    string      `json:"url"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyBytes []byte
		if Cfg.Log.LogTokens {
			bodyBytes = readBody(r)
		} else {
			bodyBytes = []byte("[REDACTED]")
		}

		logRequestData(r, bodyBytes)
		next.ServeHTTP(w, r)
		Logger.Debug("Request", zap.String("complete", "true"))
	})
}

// readBody reads and restores the request body.
func readBody(r *http.Request) []byte {
	var bodyBytes []byte
	var err error
	if r.Body != nil {
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			Logger.Error("Error reading body", zap.Error(err))
			return nil
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	return bodyBytes
}

// logRequestData prepares and logs the request data.
func logRequestData(r *http.Request, bodyBytes []byte) {
	rd := requestData{r.Method, r.URL.String(), r.Header, string(bodyBytes)}
	if !Cfg.Log.LogTokens {
		rd.Header = cleanSensitiveHeaders(rd.Header)
	}
	jsonData, err := json.Marshal(rd)
	if err != nil {
		Logger.Error("Error while marshalling request", zap.Error(err))
		return
	}
	Logger.Debug("Request", zap.String("request", string(jsonData)), zap.String("path", r.URL.Path))
}

// cleanSensitiveHeaders removes sensitive headers from the copy of headers.
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

// logAndWriteError logs an error and sends an error message as the HTTP response.
func logAndWriteError(rw http.ResponseWriter, statusCode int, err error, message string) {
	if message == "" {
		message = err.Error()
	}
	Logger.Error(message, zap.Error(err))
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprint(rw, message+"\n")
}
