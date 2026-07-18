package xds

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// reconcilerCounters is the read-only view of the reconciler's observability
// counters that the metrics collector exports. *Reconciler already satisfies it —
// the metrics layer only READS these accessors, so wiring metrics leaves the
// reconcile/guard code byte-identical. It covers two DISTINCT families:
//   - *SnapshotsBlocked / AuthWantedButExtAuthzOff: a guard WITHHELD a publish
//     (bad config did NOT reach Envoy) → xds_snapshots_blocked_total.
//   - *FirstBootPublished: a first-boot exemption PUBLISHED bad config (the one
//     path where it reaches Envoy) → xds_snapshots_published_degraded_total.
type reconcilerCounters interface {
	EmptySnapshotsBlocked() uint64
	InconsistentSnapshotsBlocked() uint64
	AuthWantedButExtAuthzOff() uint64
	EmptyFirstBootPublished() uint64
	InconsistentFirstBootPublished() uint64

	// edge_cp_* control-plane gauges (backing the dashboards/alerts #46 removed).
	LastReconcileUnix() int64
	LastReconcileDurationSeconds() float64
	ActiveStreams() int64
	NodesBehind() int
}

// reason label values for xds_snapshots_blocked_total.
const (
	reasonEmpty        = "empty"                    // empty-collapse guard: zero listeners/clusters
	reasonInconsistent = "inconsistent"             // consistency guard: dangling reference / blackhole route
	reasonAuthOff      = "auth_wanted_extauthz_off" // CFG-1: a route wants auth but ext_authz is off
)

// reason label values for xds_snapshots_published_degraded_total.
const (
	reasonEmptyFirstBoot        = "empty_first_boot"        // first boot published an empty snapshot
	reasonInconsistentFirstBoot = "inconsistent_first_boot" // first boot published an inconsistent snapshot
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

// snapshotsPublishedDegradedDesc describes xds_snapshots_published_degraded_total{reason}.
// This is the OTHER side of the guards: on first boot (no last-good) the empty and
// inconsistent guards are exempt and the bad config IS PUBLISHED so a fresh edge can
// come up. Kept as a separate metric — nothing was blocked, so the value must not land
// on xds_snapshots_blocked_total (that would make a "blocked" counter increment on a
// publish and mis-fire the ControlPlaneSnapshotWithheld alert).
var snapshotsPublishedDegradedDesc = prometheus.NewDesc(
	"xds_snapshots_published_degraded_total",
	"First-boot reconciles that PUBLISHED a degraded snapshot (guard exemption, no "+
		"last-good to keep) — the one path where bad config reaches Envoy, by reason.",
	[]string{"reason"},
	nil,
)

// edge_cp_* control-plane gauges. These back the dashboard panels and alert rules
// removed in #46 for lack of an emitter (restored in this same change), plus the new
// delivery-divergence signal.
var (
	lastReconcileDesc = prometheus.NewDesc(
		"edge_cp_last_reconcile_timestamp_seconds",
		"Unix timestamp of the control-plane's last successful reconcile (loop liveness).",
		nil, nil,
	)
	reconcileDurationDesc = prometheus.NewDesc(
		"edge_cp_reconcile_duration_seconds",
		"Duration of the control-plane's last reconcile, in seconds.",
		nil, nil,
	)
	grpcStreamsActiveDesc = prometheus.NewDesc(
		"edge_cp_grpc_streams_active",
		"Currently-open xDS (ADS) gRPC streams from the Envoy fleet.",
		nil, nil,
	)
	nodesBehindDesc = prometheus.NewDesc(
		"edge_cp_nodes_behind",
		"Connected nodes whose last-ACKed xDS version is not the current published "+
			"version (delivery divergence). Unlike xds_snapshots_blocked_total, this "+
			"catches config that was published but whose DELIVERY was withheld.",
		nil, nil,
	)
)

// reconcilerCollector exports the reconciler's guard counters as Prometheus
// counters. It is a pure READ view over the reconciler's atomic counters: Collect
// snapshots the current values on each scrape and emits them as monotonic
// CounterValue metrics (the underlying atomics only ever increase). It never
// mutates reconciler state.
//
// Every reason series (of BOTH metrics) is emitted on every scrape, so each is
// present from t=0 — an operator can write
// `increase(xds_snapshots_published_degraded_total[10m]) > 0` (optionally by reason)
// and have it evaluate against an existing series before the first exemption fires.
type reconcilerCollector struct {
	src reconcilerCounters
}

func newReconcilerCollector(src reconcilerCounters) *reconcilerCollector {
	return &reconcilerCollector{src: src}
}

func (c *reconcilerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- snapshotsBlockedDesc
	ch <- snapshotsPublishedDegradedDesc
	ch <- lastReconcileDesc
	ch <- reconcileDurationDesc
	ch <- grpcStreamsActiveDesc
	ch <- nodesBehindDesc
}

func (c *reconcilerCollector) Collect(ch chan<- prometheus.Metric) {
	emit := func(desc *prometheus.Desc, reason string, v uint64) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(v), reason)
	}
	emit(snapshotsBlockedDesc, reasonEmpty, c.src.EmptySnapshotsBlocked())
	emit(snapshotsBlockedDesc, reasonInconsistent, c.src.InconsistentSnapshotsBlocked())
	emit(snapshotsBlockedDesc, reasonAuthOff, c.src.AuthWantedButExtAuthzOff())
	emit(snapshotsPublishedDegradedDesc, reasonEmptyFirstBoot, c.src.EmptyFirstBootPublished())
	emit(snapshotsPublishedDegradedDesc, reasonInconsistentFirstBoot, c.src.InconsistentFirstBootPublished())

	gauge := func(desc *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v)
	}
	gauge(lastReconcileDesc, float64(c.src.LastReconcileUnix()))
	gauge(reconcileDurationDesc, c.src.LastReconcileDurationSeconds())
	gauge(grpcStreamsActiveDesc, float64(c.src.ActiveStreams()))
	gauge(nodesBehindDesc, float64(c.src.NodesBehind()))
}

// NewMetricsHandler returns an http.Handler serving the reconciler's observability
// counters in Prometheus text format. It uses a dedicated registry (not the global
// default) so the exposition is exactly these metrics — matching the per-service
// registries the sibling services use (auth-service, osb).
func NewMetricsHandler(src reconcilerCounters) http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(newReconcilerCollector(src))
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
