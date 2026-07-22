package xds

import (
	"sort"
	"time"
)

// This file holds the reconciler's read-only observability accessors and the
// per-node ACK tracking behind the delivery-divergence signal. None of it changes
// a guard or publish decision; the metrics collector (metrics.go) reads it.

// LastReconcileUnix returns the unix-seconds timestamp of the last successful
// reconcile (0 before the first one). Backs edge_cp_last_reconcile_timestamp_seconds
// / ControlPlaneReconcileStalled.
func (r *Reconciler) LastReconcileUnix() int64 { return r.lastReconcileUnix.Load() }

// LastReconcileDurationSeconds returns how long the last reconcile took.
// Backs edge_cp_reconcile_duration_seconds / ControlPlaneHighReconcileDuration.
func (r *Reconciler) LastReconcileDurationSeconds() float64 {
	return time.Duration(r.lastReconcileNanos.Load()).Seconds()
}

// ActiveStreams returns the number of currently-open xDS (ADS) gRPC streams.
// Backs edge_cp_grpc_streams_active. Driven by the server OnStreamOpen/OnStreamClosed
// callbacks (balanced per stream by go-control-plane).
func (r *Reconciler) ActiveStreams() int64 { return r.activeStreams.Load() }

// StreamOpened / StreamClosed are called from the xDS server callbacks to track the
// live stream count.
func (r *Reconciler) StreamOpened() { r.activeStreams.Add(1) }
func (r *Reconciler) StreamClosed() { r.activeStreams.Add(-1) }

// RecordNodeAck records the xDS version a connected node last acknowledged (from its
// DiscoveryRequest's version_info). Called from the server callbacks. A node that has
// caught up ACKs the current published version; a node that is stuck keeps ACKing an
// older one — which is exactly what NodesBehind counts.
func (r *Reconciler) RecordNodeAck(node, version string) {
	if node == "" {
		return
	}
	r.ackMu.Lock()
	r.nodeAcks[node] = version
	r.ackMu.Unlock()
}

// ForgetNode drops a node's ACK state when its stream closes, so a disconnected node
// is not counted as behind.
func (r *Reconciler) ForgetNode(node string) {
	r.ackMu.Lock()
	delete(r.nodeAcks, node)
	r.ackMu.Unlock()
}

// PublishedVersion returns the version string of the last published snapshot, or ""
// if nothing has been published yet.
func (r *Reconciler) PublishedVersion() string {
	if p := r.localLast.Load(); p != nil {
		return p.Version
	}
	return ""
}

// NodeStatus is one connected node's delivery state: the xDS version it last
// ACKed and whether that trails the published version. It is the per-node view
// behind /admin/v1/nodes; the aggregate NodesBehind() collapses it to a count.
//
// SCOPE: entries exist only for nodes with OPEN xDS streams (RecordNodeAck /
// ForgetNode). There is no registry of EXPECTED nodes anywhere — absence from
// this list means "not connected", never "healthy".
type NodeStatus struct {
	NodeID       string
	AckedVersion string
	Behind       bool
}

// NodeStatuses returns the per-node ACK view, sorted by node id. Behind is
// computed exactly as NodesBehind counts it: a node trails only once a version
// has been published (before the first publish nothing is "behind").
func (r *Reconciler) NodeStatuses() []NodeStatus {
	published := r.PublishedVersion()
	r.ackMu.Lock()
	out := make([]NodeStatus, 0, len(r.nodeAcks))
	for id, acked := range r.nodeAcks {
		out = append(out, NodeStatus{
			NodeID:       id,
			AckedVersion: acked,
			Behind:       published != "" && acked != published,
		})
	}
	r.ackMu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// NodesBehind returns how many connected nodes have NOT acknowledged the current
// published version — the delivery-divergence signal. It is the regression tripwire
// for the #47 version-collision class: there the control-plane publishes successfully
// (so xds_snapshots_blocked_total stays 0) and only DELIVERY to the node is withheld,
// so the node keeps ACKing the old version while the published version moved on.
//
// NOTE (why not reuse catchUpConnectedNodes's comparison): that compares the server
// CACHE entry (cache.GetSnapshot(node)) to the published version. The cache entry is
// what the server SET, which equals the published version even when Envoy never
// received it — so it is blind to withheld delivery. The ACKed version (what the node
// echoes back on the wire) is the signal that actually catches it.
//
// Returns 0 before the first publish. A node briefly behind right after a config
// change is normal (ACK in flight) — the "stuck" distinction is the alert's `for:`
// window, not this instantaneous count.
func (r *Reconciler) NodesBehind() int {
	published := r.PublishedVersion()
	if published == "" {
		return 0
	}
	r.ackMu.Lock()
	defer r.ackMu.Unlock()
	behind := 0
	for _, acked := range r.nodeAcks {
		if acked != published {
			behind++
		}
	}
	return behind
}
