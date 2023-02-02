package utils

import (
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/json"
	"os"
	"strings"
)

var (
	Logger *zap.Logger
)

func initializeLogger() {
	rawJSON := []byte(`{
		"level": "` + strings.ToLower(os.Getenv("LOG_LEVEL")) + `",
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

	Logger.Info("logger construction succeeded")
}

func LogPanic(msg string, err error) {
	if Logger == nil {
		initializeLogger()
	}
	Logger.Panic(msg, zap.String("error", err.Error()))

}

func LogError(msg string, err error) {
	if Logger == nil {
		initializeLogger()
	}

	if err != nil {
		Logger.Error(msg, zap.String("error", err.Error()))
	}
}
