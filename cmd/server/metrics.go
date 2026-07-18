package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// metricsAddr is the fail-static metrics endpoint's listen address. It is fixed
// at :2112 to match the edge-control-plane chart, which already declares this
// port in three places and scrapes it: the Deployment's `metrics` containerPort
// (2112), the Service's `metrics` port (values service.metricsPort: 2112), and
// the pod's prometheus.io/scrape:"true" + prometheus.io/port:"2112" annotations.
// Before this wiring nothing bound :2112, so Prometheus scrapes got a connection
// refused; serving here makes the already-configured scrape target real.
const metricsAddr = ":2112"

// newMetricsServer builds the control-plane Prometheus metrics HTTP server,
// serving the given handler (the reconciler's fail-static guard counters) at
// /metrics on addr. Additive and read-only: it exposes counters and never
// touches the reconcile path.
func newMetricsServer(addr string, h http.Handler) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", h)
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// runMetricsServer serves until ctx is cancelled, then drains with a short
// timeout. A clean shutdown surfaces http.ErrServerClosed, reported as nil; a
// bind failure at startup is a real error and propagates so the process fails
// fast (mirrors runHealthServer).
func runMetricsServer(ctx context.Context, srv *http.Server, log *slog.Logger) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Info("metrics server listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
