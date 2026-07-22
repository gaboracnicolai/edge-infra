package xds

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// /admin/v1/nodes needs the PER-NODE ACK view that the aggregate NodesBehind()
// collapses to a count: which connected node holds which version, and which
// trail the published one. Red before the accessor exists.
func TestNodeStatuses_PerNodeAckView(t *testing.T) {
	r := NewReconciler(newCache(), &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	require.Empty(t, r.NodeStatuses(), "no streams yet — no entries")

	require.NoError(t, r.Reconcile(context.Background()))
	published := r.PublishedVersion()
	require.NotEmpty(t, published)

	// Recorded out of order on purpose: the accessor must sort by node id so
	// the admin response is deterministic.
	r.RecordNodeAck("node-b", "stale-version")
	r.RecordNodeAck("node-a", published)

	got := r.NodeStatuses()
	require.Len(t, got, 2)
	assert.Equal(t, NodeStatus{NodeID: "node-a", AckedVersion: published, Behind: false}, got[0],
		"caught-up node: acked == published, not behind; sorted first")
	assert.Equal(t, NodeStatus{NodeID: "node-b", AckedVersion: "stale-version", Behind: true}, got[1],
		"stale node: trails the published version")

	// The per-node view and the aggregate must agree.
	assert.Equal(t, 1, r.NodesBehind())

	// A disconnected node drops out (ForgetNode), exactly like NodesBehind.
	r.ForgetNode("node-b")
	got = r.NodeStatuses()
	require.Len(t, got, 1)
	assert.Equal(t, "node-a", got[0].NodeID)
}

// Before the first publish nothing is "behind" — mirrors NodesBehind()==0 so
// a fresh control plane never reports divergence it cannot have caused.
func TestNodeStatuses_BeforeFirstPublish_NothingBehind(t *testing.T) {
	r := NewReconciler(newCache(), &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	r.RecordNodeAck("node-a", "") // fresh node: empty version, nothing published

	got := r.NodeStatuses()
	require.Len(t, got, 1)
	assert.False(t, got[0].Behind,
		"no published version yet ⇒ no node is behind (mirrors NodesBehind)")
	assert.Equal(t, 0, r.NodesBehind())
}
