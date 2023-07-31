package main

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metrics "github.com/slok/go-http-metrics/metrics/prometheus"
	"github.com/slok/go-http-metrics/middleware"
	"github.com/slok/go-http-metrics/middleware/std"
	"go.uber.org/zap"
	"net/http"
	"net/http/pprof"
)

// main is the entry point. It initializes necessary components, sets up HTTP routes, and starts the HTTP server.
func main() {
	defer func(Logger *zap.Logger) {
		err := Logger.Sync()

		if err != nil {
			fmt.Printf("{\"level\":\"error\",\"error\":\"%s/\"}", err)
			return
		}
	}(Logger)

	Logger.Info("Starting Proxy")

	mdlw := middleware.New(middleware.Config{
		Recorder: metrics.NewRecorder(metrics.Config{}),
		Service:  "multena",
	})
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/healthz", http.HandlerFunc(HealthCheckHandler))
	mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))

	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", Cfg.Web.Host, Cfg.Web.MetricsPort), mux); err != nil {
			Logger.Panic("Error while serving metrics", zap.Error(err))
		}
	}()
	err := http.ListenAndServe(fmt.Sprintf("%s:%d", Cfg.Web.Host, Cfg.Web.ProxyPort),
		std.Handler("/", mdlw, application()))

	if err != nil {
		Logger.Panic("Error while serving", zap.Error(err))
	}
}

// HealthCheckHandler is an HTTP handler that always returns an HTTP status of 200 and a response body of "Ok".
// It's commonly used for health checks.
func HealthCheckHandler(responseWriter http.ResponseWriter, _ *http.Request) {
	responseWriter.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(responseWriter, "%s", "Ok")
}
