package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
)

// snapshotSource is the read-only slice of the xDS cache the readiness probe
// needs: it reports whether a snapshot has been published for a node yet. The
// real cachev3.SnapshotCache satisfies it; tests pass a fake.
type snapshotSource interface {
	GetSnapshot(node string) (cachev3.ResourceSnapshot, error)
}

// newHealthServer builds the control-plane health HTTP server.
//
//   - GET /healthz — liveness: 200 as long as the process is up. It must not
//     depend on downstream state, since a failing liveness probe restarts the
//     pod — a momentary lack of xDS data is not a reason to kill the process.
//   - GET /readyz  — readiness: 200 only once the reconciler has published an
//     xDS snapshot for nodeID, else 503. This gates rollout/traffic without
//     restarting the pod, so a replica that has not yet built its first
//     snapshot is held out of service.
//
// This is intentionally additive: it only reads the cache and never touches the
// reconcile path.
func newHealthServer(addr string, snaps snapshotSource, nodeID string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		// GetSnapshot returns an error until the reconciler has seeded a
		// snapshot for this node — that is exactly the "not ready" signal.
		if _, err := snaps.GetSnapshot(nodeID); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("no xDS snapshot for node yet"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// runHealthServer serves until ctx is cancelled, then drains with a short
// timeout. A clean shutdown surfaces http.ErrServerClosed, which is reported as
// nil; a bind failure at startup is a real error and propagates so the process
// fails fast.
func runHealthServer(ctx context.Context, srv *http.Server, log *slog.Logger) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Info("health server listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
