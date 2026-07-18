package xds

import (
	"context"
	"testing"

	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/store"
)

// sampleSnapshotVariant is sampleSnapshot() plus one extra public route, so it is
// valid but has a DIFFERENT config hash — a second, distinct "config".
func sampleSnapshotVariant() *store.Snapshot {
	s := sampleSnapshot()
	s.Routes = append(s.Routes, store.Route{
		ID: "rExtra", Name: "extra", GatewayID: "gw1",
		Hosts: []string{"extra.example.com"}, PathPrefix: "/",
		ClusterName: "api-cluster", AuthPolicy: "none",
	})
	return s
}

// reconcileVersionFresh simulates a control-plane PROCESS: a brand-new reconciler
// (fresh in-process counters) publishes dom into cache and returns the version it
// stamped. Calling it twice models a restart.
func reconcileVersionFresh(t *testing.T, cache cachev3.SnapshotCache, dom *store.Snapshot) string {
	t.Helper()
	r := NewReconciler(cache, &fakeStore{snap: dom}, testNodeID, discardLogger())
	require.NoError(t, r.Reconcile(context.Background()))
	s, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	return s.GetVersion(resourcev3.ClusterType)
}

// The version-collision fix: a CHANGED config published by a restarted control-plane
// must carry a DIFFERENT version string than the config a still-connected Envoy
// already holds — otherwise go-control-plane's SnapshotCache compares the equal
// version strings and withholds the changed CDS/LDS (the live bug).
//
// Red against main's per-process counter: process 1 stamps config A "v1"; the
// restarted process 2 resets its counter and stamps config B "v1" too → equal →
// this assertion fails. With a hash-derived version, hash(A) != hash(B) → differ.
func TestResolveVersion_ChangedConfigAcrossRestartAlwaysDiffers(t *testing.T) {
	cache := newCache()
	vA := reconcileVersionFresh(t, cache, sampleSnapshot())        // process 1: config A
	vB := reconcileVersionFresh(t, cache, sampleSnapshotVariant()) // RESTART, changed config B

	assert.NotEqual(t, vA, vB,
		"a changed config after a restart must carry a NEW version so the SnapshotCache delivers it")
}

// The dual property: an UNCHANGED config, republished by a restarted control-plane,
// must carry the SAME version string — so the cache correctly dedups (no needless
// re-push) instead of the version drifting per process.
//
// Red against main's counter: process 1 publishes config X ("v1") then config A
// ("v2"); the restarted process 2 publishes config A at the reset counter ("v1").
// v2 != v1 → the same config carries two versions → this assertion fails. With a
// hash-derived version, both are hash(A).
func TestResolveVersion_UnchangedConfigAcrossRestartStaysSame(t *testing.T) {
	// process 1: config X, then config A (advances a counter past v1).
	cache1 := newCache()
	fs := &fakeStore{snap: sampleSnapshotVariant()} // config X
	r1 := NewReconciler(cache1, fs, testNodeID, discardLogger())
	require.NoError(t, r1.Reconcile(context.Background()))
	fs.snap = sampleSnapshot() // config A
	require.NoError(t, r1.Reconcile(context.Background()))
	s1, err := cache1.GetSnapshot(testNodeID)
	require.NoError(t, err)
	vA1 := s1.GetVersion(resourcev3.ClusterType)

	// RESTART: a fresh process publishes the SAME config A.
	vA2 := reconcileVersionFresh(t, newCache(), sampleSnapshot())

	assert.Equal(t, vA1, vA2,
		"the same config across a restart must keep the same version (stable dedup)")
}
