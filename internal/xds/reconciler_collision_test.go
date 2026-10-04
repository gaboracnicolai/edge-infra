package xds

import (
	"context"
	"testing"

	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/store"
)

// A second gateway on a port every node already serves is withheld: nodes keep the
// last-good listeners, a proxy that connects meanwhile is caught up to them, the
// refusal is on xds_snapshots_blocked_total{reason="listener_collision"}, and the
// next config without the collision publishes. (Two gateways sharing a port but
// pinned to different nodes still publish: TestReconcile_EachNodeGetsOnlyItsOwnTenantsKeys.)
func TestReconcile_CollidingListenerKeepsLastGood(t *testing.T) {
	ctx := context.Background()
	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())
	h := NewMetricsHandler(r)
	require.Equal(t, 0.0, blockedCount(t, h, "listener_collision"))

	require.NoError(t, r.Reconcile(ctx))
	lastGood := r.PublishedVersion()

	colliding := sampleSnapshot()
	colliding.Gateways = append(colliding.Gateways,
		store.Gateway{ID: "gw3", Name: "second-https", Port: 8443, Protocol: "HTTP"})
	fs.snap = colliding
	connect(t, cache, "late-node")
	require.NoError(t, r.Reconcile(ctx))

	require.Equal(t, lastGood, r.PublishedVersion(), "a colliding snapshot must not be published")
	require.Equal(t, []string{"edge-http", "edge-https"}, names(t, cache, testNodeID, resourcev3.ListenerType))
	require.Equal(t, []string{"edge-http", "edge-https"}, names(t, cache, "late-node", resourcev3.ListenerType),
		"a proxy that connects during the collision must still get the last-good listeners")
	require.Equal(t, 1.0, blockedCount(t, h, "listener_collision"))

	colliding.Gateways[2].Port = 9443
	require.NoError(t, r.Reconcile(ctx))
	require.NotEqual(t, lastGood, r.PublishedVersion())
	require.Equal(t, []string{"edge-http", "edge-https", "second-https"},
		names(t, cache, testNodeID, resourcev3.ListenerType))
}

// First boot is not exempt: with no last-good there is still no right listener to
// publish, so nothing is.
func TestReconcile_CollidingListenerOnFirstBootPublishesNothing(t *testing.T) {
	cache := newCache()
	colliding := sampleSnapshot()
	colliding.Gateways[1].Port = colliding.Gateways[0].Port
	r := NewReconciler(cache, &fakeStore{snap: colliding}, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))

	_, err := cache.GetSnapshot(testNodeID)
	require.Error(t, err, "no snapshot may be published while two listeners collide")
	require.Equal(t, uint64(1), r.ListenerCollisionsBlocked())
}
