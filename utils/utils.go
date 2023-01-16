package utils

import (
	"go.uber.org/zap"
)

var Logger *zap.Logger

func InitializeLogger() {
	Logger, _ = zap.NewProduction()
	defer Logger.Sync()
}

func LogPanic(msg string, err error) {
	if err != nil {
		Logger.Panic(msg, zap.String("error", err.Error()))
	}
}

func LogError(msg string, err error) {
	if err != nil {
		Logger.Error(msg, zap.String("error", err.Error()))
	}
}
