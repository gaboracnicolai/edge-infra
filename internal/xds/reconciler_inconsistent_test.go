package xds

import (
	"context"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	streamv3 "github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/store"
)

// danglingRouteSnapshot is a non-empty, otherwise-healthy domain with ONE route
// whose ClusterName has NO matching clusters row. The built snapshot passes
// Envoy's Snapshot.Consistent() (which does not traverse RDS route -> CDS cluster
// references), but Envoy would blackhole that route — a real fail-static case the
// R8 guard must catch. It keeps >=1 listener and >=1 cluster so the empty-collapse
// guard does not fire first.
func danglingRouteSnapshot() *store.Snapshot {
	s := sampleSnapshot()
	s.Routes = append(s.Routes, store.Route{
		ID: "rX", Name: "ghost", GatewayID: "gw1",
		Hosts: []string{"ghost.example.com"}, PathPrefix: "/",
		ClusterName: "ghost-cluster", AuthPolicy: "none",
	})
	return s
}

// R8: after a healthy snapshot exists, a reconcile that builds an inconsistent
// snapshot (a route referencing a nonexistent cluster — a dangling RDS->CDS
// reference) must be REFUSED fail-static: keep the last-good, count the block, and
// publish no new version. Mirrors the empty-collapse guard tests, but for the
// inconsistency the data path can actually produce.
func TestReconcile_DanglingRouteAfterHealthyKeepsLastSnapshot(t *testing.T) {
	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())

	// Healthy fleet published (a last-good now exists).
	require.NoError(t, r.Reconcile(context.Background()))
	v1, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	require.Len(t, v1.GetResources(resourcev3.ClusterType), 2)

	// The source now yields a route pointing at a cluster that isn't in CDS —
	// Envoy would blackhole it. A state-of-the-world push of this must be withheld.
	fs.snap = danglingRouteSnapshot()
	require.NoError(t, r.Reconcile(context.Background()))

	v2, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	assert.Equal(t, v1.GetVersion(resourcev3.ClusterType), v2.GetVersion(resourcev3.ClusterType),
		"an inconsistent (dangling route->cluster) snapshot must NOT be published")
	assert.Equal(t, v1.GetVersion(resourcev3.RouteType), v2.GetVersion(resourcev3.RouteType),
		"the last-good route config must be retained")
	assert.Equal(t, uint64(1), r.InconsistentSnapshotsBlocked(),
		"the suppressed inconsistent publish must be counted")
}

// R8 first-boot exemption: with no last-good to protect, an inconsistent snapshot
// must still publish (with a warning) — a fresh edge must be able to come up.
func TestReconcile_FirstBootDanglingRoutePublishes(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: danglingRouteSnapshot()}, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))

	snap, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err, "first boot must publish even an inconsistent snapshot (nothing to keep)")
	require.NotEmpty(t, snap.GetResources(resourcev3.ClusterType))
	assert.Equal(t, uint64(0), r.InconsistentSnapshotsBlocked(),
		"first boot must not trip the guard")
}

// R8 catch-up invariant: a blocked (inconsistent) reconcile never advances
// lastSnap, so a node connecting AFTER the block receives the healthy last-good
// via the fast-path catch-up — never the withheld inconsistent snapshot.
func TestReconcile_CatchUpFansOutLastGoodNotBlocked(t *testing.T) {
	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background())) // healthy; lastSnap = healthy

	// A dangling reconcile is blocked; lastSnap MUST stay the healthy snapshot.
	fs.snap = danglingRouteSnapshot()
	require.NoError(t, r.Reconcile(context.Background()))
	require.Equal(t, uint64(1), r.InconsistentSnapshotsBlocked())

	// A NEW proxy connects after the block.
	const late = "late-after-block"
	respCh := make(chan cachev3.Response, 1)
	cancel := cache.CreateWatch(
		&cachev3.Request{Node: &corev3.Node{Id: late}, TypeUrl: resourcev3.ClusterType},
		streamv3.NewStreamState(true, nil), respCh)
	defer cancel()

	// Config returns to the healthy set (unchanged hash → fast path → catch-up).
	fs.snap = sampleSnapshot()
	require.NoError(t, r.Reconcile(context.Background()))

	rs, err := cache.GetSnapshot(late)
	require.NoError(t, err, "the late node must receive a snapshot via catch-up")
	snap, ok := rs.(*cachev3.Snapshot)
	require.True(t, ok)
	require.NoError(t, snap.Consistent())
	require.NoError(t, danglingRouteClusterError(snap),
		"catch-up must fan out the healthy last-good, NEVER the withheld inconsistent snapshot")
	require.Len(t, snap.GetResources(resourcev3.ClusterType), 2)
}
