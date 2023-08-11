package main

import (
	"fmt"
	"net/http"

	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/slok/go-http-metrics/middleware/std"
	"go.uber.org/zap"
)

func main() {
	NewLogger()
	defer func(Logger *zap.Logger) {
		err := Logger.Sync()
		if err != nil {
			fmt.Printf("{\"level\":\"error\",\"error\":\"%s/\"}", err)
			return
		}
	}(Logger)

	app := App{}
	app.NewApp()

	e, i, err := app.NewRoutes()

	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", Cfg.Web.Host, Cfg.Web.MetricsPort), i); err != nil {
			Logger.Panic("Error while serving metrics", zap.Error(err))
		}
	}()

	if err != nil {
		Logger.Panic("Error while initializing application", zap.Error(err))
	}

	mdlw := middleware.New(middleware.Config{
		Recorder: metrics.NewRecorder(metrics.Config{}),
		Service:  "multena",
	})
	err = http.ListenAndServe(fmt.Sprintf("%s:%d", Cfg.Web.Host, Cfg.Web.ProxyPort),
		std.Handler("/", mdlw, e))

	if err != nil {
		Logger.Panic("Error while serving", zap.Error(err))
	}
}
