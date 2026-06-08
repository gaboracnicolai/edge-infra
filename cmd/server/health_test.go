package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
)

// fakeCache is a snapshotSource whose GetSnapshot result is fixed per test.
type fakeCache struct {
	snap cachev3.ResourceSnapshot
	err  error
}

func (f fakeCache) GetSnapshot(string) (cachev3.ResourceSnapshot, error) {
	return f.snap, f.err
}

func statusFor(t *testing.T, srv *http.Server, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	srv.Handler.ServeHTTP(rec, req)
	return rec.Code
}

func TestHealthzAlwaysOK(t *testing.T) {
	// Liveness ignores snapshot state: even with no snapshot it stays 200, so a
	// transient lack of xDS data never restarts the pod.
	srv := newHealthServer(":0", fakeCache{err: errors.New("no snapshot")}, "edge-envoy")
	if code := statusFor(t, srv, "/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz = %d, want %d", code, http.StatusOK)
	}
}

func TestReadyzNotReadyBeforeFirstSnapshot(t *testing.T) {
	// GetSnapshot errors until the reconciler seeds a snapshot → 503.
	srv := newHealthServer(":0", fakeCache{err: errors.New("no snapshot found for node")}, "edge-envoy")
	if code := statusFor(t, srv, "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d, want %d", code, http.StatusServiceUnavailable)
	}
}

func TestReadyzReadyOnceSnapshotPresent(t *testing.T) {
	// A nil error means a snapshot exists for the node → ready to serve xDS.
	srv := newHealthServer(":0", fakeCache{err: nil}, "edge-envoy")
	if code := statusFor(t, srv, "/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz = %d, want %d", code, http.StatusOK)
	}
}
