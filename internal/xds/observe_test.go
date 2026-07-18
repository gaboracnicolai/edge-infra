package xds

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gaugeValue extracts a no-label gauge's value from the Prometheus exposition.
func gaugeValue(t *testing.T, body, name string) float64 {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name+" ") {
			f := strings.Fields(line)
			v, err := strconv.ParseFloat(f[len(f)-1], 64)
			require.NoError(t, err)
			return v
		}
	}
	t.Fatalf("gauge %s not found in exposition", name)
	return 0
}

// edge_cp_last_reconcile_timestamp_seconds / edge_cp_reconcile_duration_seconds must
// be recorded on a successful reconcile (backing ControlPlaneReconcileStalled /
// HighReconcileDuration). Red before the timing hook: both stay 0.
func TestObserve_ReconcileTimestampAndDuration(t *testing.T) {
	r := NewReconciler(newCache(), &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	require.Equal(t, int64(0), r.LastReconcileUnix(), "no reconcile has happened yet")

	before := time.Now().Unix()
	require.NoError(t, r.Reconcile(context.Background()))

	assert.GreaterOrEqual(t, r.LastReconcileUnix(), before,
		"the last-reconcile timestamp must advance on a successful reconcile")
	assert.Greater(t, r.LastReconcileDurationSeconds(), 0.0,
		"the reconcile duration must be recorded")
}

// edge_cp_grpc_streams_active tracks open ADS streams (wired from OnStreamOpen/Closed).
func TestObserve_ActiveStreams(t *testing.T) {
	r := NewReconciler(newCache(), &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	require.Equal(t, int64(0), r.ActiveStreams())
	r.StreamOpened()
	r.StreamOpened()
	assert.Equal(t, int64(2), r.ActiveStreams())
	r.StreamClosed()
	assert.Equal(t, int64(1), r.ActiveStreams())
}

// edge_cp_nodes_behind — the delivery-divergence signal (#47 regression tripwire): a
// node that has NOT acknowledged the current published version registers as behind; a
// node holding the current version does NOT.
func TestObserve_NodesBehind_DivergenceSignal(t *testing.T) {
	r := NewReconciler(newCache(), &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	require.Equal(t, 0, r.NodesBehind(), "nothing published yet → nothing behind")

	require.NoError(t, r.Reconcile(context.Background()))
	published := r.PublishedVersion()
	require.NotEmpty(t, published)

	// A node holding the current published version is NOT behind.
	r.RecordNodeAck("nodeA", published)
	assert.Equal(t, 0, r.NodesBehind(), "a node on the current version is not behind")

	// A node still holding an OLD version IS behind.
	r.RecordNodeAck("nodeB", "stale-old-version")
	assert.Equal(t, 1, r.NodesBehind(), "only the stale node is behind")

	// It clears when the node catches up.
	r.RecordNodeAck("nodeB", published)
	assert.Equal(t, 0, r.NodesBehind())

	// A disconnected node is not counted.
	r.RecordNodeAck("nodeC", "")
	assert.Equal(t, 1, r.NodesBehind())
	r.ForgetNode("nodeC")
	assert.Equal(t, 0, r.NodesBehind(), "a disconnected node must not be counted behind")
}

// The four edge_cp_* gauges must appear in the /metrics exposition with the driven
// values (present from t=0, matching the collector convention).
func TestObserve_EdgeCPMetricsExposed(t *testing.T) {
	r := NewReconciler(newCache(), &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	require.NoError(t, r.Reconcile(context.Background()))
	r.RecordNodeAck("behind-node", "old-version") // 1 behind
	r.StreamOpened()                              // 1 stream

	body := scrapeMetrics(t, NewMetricsHandler(r))
	for _, want := range []string{
		"edge_cp_last_reconcile_timestamp_seconds",
		"edge_cp_reconcile_duration_seconds",
		"edge_cp_grpc_streams_active",
		"# TYPE edge_cp_nodes_behind gauge",
	} {
		require.Contains(t, body, want)
	}
	assert.Equal(t, 1.0, gaugeValue(t, body, "edge_cp_nodes_behind"))
	assert.Equal(t, 1.0, gaugeValue(t, body, "edge_cp_grpc_streams_active"))
}
