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

func LogIfPanic(msg string, err error) {
	if err != nil {
		Logger.Panic(msg, zap.String("error", err.Error()))
	}
}

func LogIfError(msg string, err error) {
	if err != nil {
		Logger.Error(msg, zap.String("error", err.Error()))
	}
}
