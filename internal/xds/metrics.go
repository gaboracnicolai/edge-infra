package xds

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// blockedCounters is the read-only view of the reconciler's fail-static /
// fail-closed guard counters that the metrics collector exports. *Reconciler
// already satisfies it — the metrics layer only READS these accessors, so wiring
// metrics leaves the reconcile/guard code byte-identical.
type blockedCounters interface {
	EmptySnapshotsBlocked() uint64
	InconsistentSnapshotsBlocked() uint64
	AuthWantedButExtAuthzOff() uint64
}

// reason label values for xds_snapshots_blocked_total.
const (
	reasonEmpty        = "empty"                    // empty-collapse guard: zero listeners/clusters
	reasonInconsistent = "inconsistent"             // consistency guard: dangling reference / blackhole route
	reasonAuthOff      = "auth_wanted_extauthz_off" // CFG-1: a route wants auth but ext_authz is off
)

// snapshotsBlockedDesc describes xds_snapshots_blocked_total{reason}. Its name and
// single categorical label follow the existing repo convention — a
// <subsystem>_<name>_total counter with a small label set, matching
// auth_requests_total{result} (auth-service) and osb_requests_total{operation,status}.
var snapshotsBlockedDesc = prometheus.NewDesc(
	"xds_snapshots_blocked_total",
	"Reconciles where the control-plane withheld a new xDS snapshot from Envoy "+
		"(fail-static / fail-closed guard trip), keeping the last-good config, by reason.",
	[]string{"reason"},
	nil,
)

// reconcilerCollector exports the reconciler's guard counters as Prometheus
// counters. It is a pure READ view over the reconciler's atomic counters: Collect
// snapshots the current values on each scrape and emits them as monotonic
// CounterValue metrics (the underlying atomics only ever increase). It never
// mutates reconciler state.
//
// All three reasons are emitted on every scrape, so each series is present from
// t=0 — an operator can write `increase(xds_snapshots_blocked_total[5m]) > 0`
// (optionally by reason) and have it evaluate against an existing series before
// the first guard ever trips.
type reconcilerCollector struct {
	src blockedCounters
}

func newReconcilerCollector(src blockedCounters) *reconcilerCollector {
	return &reconcilerCollector{src: src}
}

func (c *reconcilerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- snapshotsBlockedDesc
}

func (c *reconcilerCollector) Collect(ch chan<- prometheus.Metric) {
	emit := func(reason string, v uint64) {
		ch <- prometheus.MustNewConstMetric(snapshotsBlockedDesc, prometheus.CounterValue, float64(v), reason)
	}
	emit(reasonEmpty, c.src.EmptySnapshotsBlocked())
	emit(reasonInconsistent, c.src.InconsistentSnapshotsBlocked())
	emit(reasonAuthOff, c.src.AuthWantedButExtAuthzOff())
}

// NewMetricsHandler returns an http.Handler serving the reconciler's fail-static
// guard counters in Prometheus text format. It uses a dedicated registry (not the
// global default) so the exposition is exactly these metrics — matching the
// per-service registries the sibling services use (auth-service, osb).
func NewMetricsHandler(src blockedCounters) http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(newReconcilerCollector(src))
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
