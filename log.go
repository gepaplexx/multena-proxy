package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"

	"go.uber.org/zap/zapcore"

	"go.uber.org/zap"
)

var (
	Logger *zap.Logger
	Level  zap.AtomicLevel
)

func init() {
	Level = zap.NewAtomicLevel()
	Level.SetLevel(getZapLevel("info"))

	rawJSON := []byte(`{
		"level": "info",
		"encoding": "json",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stdout"],
		"encoderConfig": {
		  "messageKey": "msg",
		  "levelKey": "level",
		  "levelEncoder": "lowercase"
		}
	  }`)

	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}
	Logger = zap.Must(cfg.Build())

	Logger.Debug("log construction succeeded")
	Logger.Debug("Go Version", zap.String("version", runtime.Version()))
	Logger.Debug("Go OS/Arch", zap.String("os", runtime.GOOS), zap.String("arch", runtime.GOARCH))
	Logger.Debug("Config", zap.Any("cfg", cfg))
}

// getZapLevel translates a string representation of a logging level into a zapcore.Level.
func getZapLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	default: // unknown level or not set, default to info
		return zapcore.InfoLevel
	}
}

func (a *App) UpdateLogLevel() {
	Level.SetLevel(getZapLevel(strings.ToLower(a.Cfg.Log.Level)))
}

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
func logRequestData(r *http.Request, bodyBytes []byte, logToken bool) {
	rd := requestData{r.Method, r.URL.String(), r.Header, string(bodyBytes)}
	if logToken {
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
	Logger.Debug(message, zap.Error(err))
	rw.WriteHeader(statusCode)
	_, _ = fmt.Fprint(rw, message+"\n")
}
