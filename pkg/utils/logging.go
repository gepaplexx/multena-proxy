package utils

import (
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/json"
	"runtime"
	"strings"
)

var (
	Logger *zap.Logger
)

// InitLogging initializes the logger
// The log level is set in the config file
// The log level can be set to debug, info, warn, error, dpanic, panic, or fatal
func InitLogging() {
	rawJSON := []byte(`{
		"level": "` + strings.ToLower(C.Proxy.LogLevel) + `",
		"encoding": "json",
		"outputPaths": ["stdout"],
		"errorOutputPaths": ["stdout"],
		"encoderConfig": {
		  "messageKey": "message",
		  "levelKey": "level",
		  "levelEncoder": "lowercase"
		}
	  }`)

	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}
	Logger = zap.Must(cfg.Build())

	Logger.Debug("logger construction succeeded")
	Logger.Debug("Go Version", zap.String("version", runtime.Version()))
}

// LogIfPanic logs an error if it is not nil and panics
func LogIfPanic(msg string, err error) {
	if err != nil {
		Logger.Panic(msg, zap.String("error", err.Error()))
	}
}

// LogIfError logs an error if it is not nil and continues execution
func LogIfError(msg string, err error) {
	if err != nil {
		Logger.Error(msg, zap.String("error", err.Error()))
	}
}
