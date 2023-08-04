package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
)

// requestData structure contains information about a HTTP request.
type requestData struct {
	Method string      `json:"method"`
	URL    string      `json:"url"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

// loggingMiddleware function is like a security camera at the entrance of a building (the server),
// it records the details of everyone (requests) that comes in. It can either record everything or hide sensitive details.
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

// readBody function reads the content of a request, kind of like reading a letter that was sent in the mail.
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

// logRequestData function takes note of what is in the request, like noting down the details of the letter that came in the mail.
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

// cleanSensitiveHeaders function is like removing personal details from the letter before it's recorded or read by someone else.
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

// logAndWriteError function is used when something goes wrong in the server, like an error. It takes note of the error and tells the requester about it.
func logAndWriteError(rw http.ResponseWriter, statusCode int, err error, message string) {
	if message == "" {
		message = err.Error()
	}
	Logger.Error(message, zap.Error(err))
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprint(rw, message+"\n")
}
