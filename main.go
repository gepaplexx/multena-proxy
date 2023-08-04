package main

import (
	"fmt"
	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/slok/go-http-metrics/middleware/std"
	"go.uber.org/zap"
	"net/http"
)

// main is the entry point of the program. It is responsible for initializing
// application, setting up http servers for serving metrics and the application
// itself. In the event of any fatal error, it will stop the execution and log
// the error message. At the end, it ensures that any buffered log entries are flushed.
//
// It creates an HTTP server for metrics that listens on the host and port specified
// in the configuration.
//
// It initializes the application (calling the application function), which returns
// an http handler for the application, an http handler for metrics and an error if
// any occurs during initialization. If there is an error during initialization,
// the program will panic and log the error.
//
// Finally, it creates and starts an HTTP server to serve the application. The server
// uses middleware for measuring HTTP metrics and listens on the host and port
// specified in the configuration. If there is an error starting the server, the program
// will panic and log the error.
func main() {
	defer func(Logger *zap.Logger) {
		err := Logger.Sync()
		if err != nil {
			fmt.Printf("{\"level\":\"error\",\"error\":\"%s/\"}", err)
			return
		}
	}(Logger)

	Logger.Info("Starting Proxy")

	e, i, err := application()

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
