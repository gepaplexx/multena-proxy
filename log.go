package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

// requestData structure contains information about a HTTP request.
type requestData struct {
	Method string      `json:"method"`
	URL    string      `json:"url"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

func (a *App) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyBytes []byte
		if a.Cfg.Log.LogTokens {
			bodyBytes = readBody(r)
		} else {
			bodyBytes = []byte("[REDACTED]")
		}

		logRequestData(r, bodyBytes, a.Cfg.Log.LogTokens)
		next.ServeHTTP(w, r)
		log.Debug().Str("path", r.URL.Path).Msg("Request complete")
	})
}

// readBody function reads the content of a request, kind of like reading a letter that was sent in the mail.
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

// logRequestData function takes note of what is in the request, like noting down the details of the letter that came in the mail.
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
		message = fmt.Sprint(err)
	}
	log.Trace().Err(err).Msg(message)
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprint(rw, message+"\n")
}

func (a *App) logConfig() *App {
	log.Debug().Any("config", a.Cfg).Msg("")
	return a
}
