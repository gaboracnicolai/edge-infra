package xds

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds/builders"
)

const testNodeID = "test-node"

type fakeStore struct {
	snap *store.Snapshot
	err  error
}

func (f *fakeStore) LoadSnapshot(_ context.Context) (*store.Snapshot, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.snap, nil
}

func (f *fakeStore) UpsertGateway(_ context.Context, _ store.Gateway) error  { return nil }
func (f *fakeStore) DeleteGateway(_ context.Context, _ string) error         { return nil }
func (f *fakeStore) UpsertRoute(_ context.Context, _ store.Route) error      { return nil }
func (f *fakeStore) DeleteRoute(_ context.Context, _ string, _ string) error { return nil }

func (f *fakeStore) Close() {}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCache() cachev3.SnapshotCache {
	return cachev3.NewSnapshotCache(true, cachev3.IDHash{}, nil)
}

func sampleSnapshot() *store.Snapshot {
	return &store.Snapshot{
		Gateways: []store.Gateway{
			{ID: "gw1", Name: "edge-http", Port: 8080, Protocol: "HTTP"},
			{ID: "gw2", Name: "edge-https", Port: 8443, Protocol: "HTTPS", TLSSecret: "edge-cert"},
		},
		// Explicitly public (auth_policy=none) so the general reconcile-mechanics
		// tests are decoupled from the CFG-1 ext_authz fail-closed guard; the
		// auth-wanting path is exercised via authWantingSnapshot().
		Routes: []store.Route{
			{ID: "r1", Name: "api", GatewayID: "gw1", Hosts: []string{"api.example.com"}, PathPrefix: "/", ClusterName: "api-cluster", AuthPolicy: "none"},
			{ID: "r2", Name: "web", GatewayID: "gw1", Hosts: []string{"www.example.com"}, PathPrefix: "/", ClusterName: "web-cluster", AuthPolicy: "none"},
			{ID: "r3", Name: "tls", GatewayID: "gw2", Hosts: []string{"secure.example.com"}, PathPrefix: "/", ClusterName: "api-cluster", AuthPolicy: "none"},
		},
		Clusters: []store.Cluster{
			{ID: "c1", Name: "api-cluster", ConnectTimeout: 5 * time.Second, LbPolicy: "ROUND_ROBIN"},
			{ID: "c2", Name: "web-cluster", ConnectTimeout: 5 * time.Second, LbPolicy: "LEAST_REQUEST"},
		},
		Endpoints: []store.Endpoint{
			{ID: "e1", ClusterID: "c1", Address: "10.0.0.1", Port: 8080, Weight: 1},
			{ID: "e2", ClusterID: "c1", Address: "10.0.0.2", Port: 8080, Weight: 1},
			{ID: "e3", ClusterID: "c2", Address: "10.0.1.1", Port: 8080, Weight: 1},
		},
		Secrets: []store.Secret{
			{ID: "s1", Name: "edge-cert", CertPEM: "-----CERT-----", KeyPEM: "-----KEY-----"},
		},
	}
}

// authWantingSnapshot is a valid, non-empty snapshot in which one route requests
// per-service auth (auth_policy != "none"). It exercises the CFG-1 fail-closed
// guard: with ext_authz off it must be REFUSED; with ext_authz on it must publish.
func authWantingSnapshot() *store.Snapshot {
	s := sampleSnapshot()
	s.Routes[0].AuthPolicy = "jwt" // one identity-bearing route
	return s
}

func TestReconcile_PopulatesAllResourceTypes(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))

	snap, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)

	assert.Len(t, snap.GetResources(resourcev3.ListenerType), 2, "two gateways → two listeners")
	assert.Len(t, snap.GetResources(resourcev3.RouteType), 2, "two gateways → two route configs")
	assert.Len(t, snap.GetResources(resourcev3.ClusterType), 2)
	assert.Len(t, snap.GetResources(resourcev3.EndpointType), 2, "one CLA per cluster")
	assert.Len(t, snap.GetResources(resourcev3.SecretType), 1)
}

func TestReconcile_ListenerNamesMatchGateways(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	require.NoError(t, r.Reconcile(context.Background()))

	snap, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)

	listeners := snap.GetResources(resourcev3.ListenerType)
	require.Contains(t, listeners, "edge-http")
	require.Contains(t, listeners, "edge-https")

	httpsL := listeners["edge-https"].(*listenerv3.Listener)
	require.Len(t, httpsL.FilterChains, 1)
	require.NotNil(t, httpsL.FilterChains[0].TransportSocket, "HTTPS listener should have TLS transport socket")

	httpL := listeners["edge-http"].(*listenerv3.Listener)
	require.Nil(t, httpL.FilterChains[0].TransportSocket, "HTTP listener should not have TLS")
}

func TestReconcile_HTTPSListenerReferencesSDSSecret(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	require.NoError(t, r.Reconcile(context.Background()))

	snap, _ := cache.GetSnapshot(testNodeID)
	httpsL := snap.GetResources(resourcev3.ListenerType)["edge-https"].(*listenerv3.Listener)

	ts := httpsL.FilterChains[0].TransportSocket
	require.NotNil(t, ts)
	var ctx tlsv3.DownstreamTlsContext
	require.NoError(t, ts.GetTypedConfig().UnmarshalTo(&ctx))
	require.Len(t, ctx.CommonTlsContext.TlsCertificateSdsSecretConfigs, 1)
	assert.Equal(t, "edge-cert", ctx.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].Name)
}

func TestReconcile_ClusterUsesEDS(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	require.NoError(t, r.Reconcile(context.Background()))

	snap, _ := cache.GetSnapshot(testNodeID)
	c := snap.GetResources(resourcev3.ClusterType)["api-cluster"].(*clusterv3.Cluster)
	assert.Equal(t, clusterv3.Cluster_EDS, c.GetType())
	require.NotNil(t, c.EdsClusterConfig)
	require.NotNil(t, c.EdsClusterConfig.EdsConfig)
}

func TestReconcile_EndpointsGroupedByCluster(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	require.NoError(t, r.Reconcile(context.Background()))

	snap, _ := cache.GetSnapshot(testNodeID)
	eps := snap.GetResources(resourcev3.EndpointType)

	api := eps["api-cluster"].(*endpointv3.ClusterLoadAssignment)
	require.Len(t, api.Endpoints, 1)
	assert.Len(t, api.Endpoints[0].LbEndpoints, 2, "api-cluster has two endpoints")

	web := eps["web-cluster"].(*endpointv3.ClusterLoadAssignment)
	assert.Len(t, web.Endpoints[0].LbEndpoints, 1)
}

func TestReconcile_RouteConfigPerGateway(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	require.NoError(t, r.Reconcile(context.Background()))

	snap, _ := cache.GetSnapshot(testNodeID)
	rcs := snap.GetResources(resourcev3.RouteType)

	require.Contains(t, rcs, "edge-http_routes")
	require.Contains(t, rcs, "edge-https_routes")

	httpRC := rcs["edge-http_routes"].(*routev3.RouteConfiguration)
	assert.Len(t, httpRC.VirtualHosts, 2, "two distinct host groups on edge-http")
}

func TestReconcile_StableInputDoesNotBumpVersion(t *testing.T) {
	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))
	v1, _ := cache.GetSnapshot(testNodeID)

	require.NoError(t, r.Reconcile(context.Background()))
	v2, _ := cache.GetSnapshot(testNodeID)

	assert.Equal(t, v1.GetVersion(resourcev3.ClusterType), v2.GetVersion(resourcev3.ClusterType),
		"unchanged input must not push a new snapshot")
}

func TestReconcile_ChangedInputBumpsVersion(t *testing.T) {
	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))
	v1, _ := cache.GetSnapshot(testNodeID)

	fs.snap.Endpoints = append(fs.snap.Endpoints, store.Endpoint{
		ID: "e4", ClusterID: "c2", Address: "10.0.1.2", Port: 8080, Weight: 1,
	})

	require.NoError(t, r.Reconcile(context.Background()))
	v2, _ := cache.GetSnapshot(testNodeID)

	assert.NotEqual(t, v1.GetVersion(resourcev3.EndpointType), v2.GetVersion(resourcev3.EndpointType))
}

func TestReconcile_StoreErrorPropagates(t *testing.T) {
	cache := newCache()
	fs := &fakeStore{err: errors.New("db down")}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())

	err := r.Reconcile(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db down")
}

func TestReconcile_FirstBootEmptySnapshotIsAllowed(t *testing.T) {
	// The empty-collapse guard only engages once a healthy snapshot exists
	// (localLast != nil). On first boot with a legitimately empty store there is
	// no last-good to protect, so an empty snapshot must still publish —
	// otherwise a fresh edge with no talyvor routes could never come up. The
	// condition is `prev != nil && collapsed`, never `collapsed` alone.
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: &store.Snapshot{}}, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))

	snap, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	assert.Empty(t, snap.GetResources(resourcev3.ListenerType))
	assert.Empty(t, snap.GetResources(resourcev3.ClusterType))
	assert.Equal(t, uint64(0), r.EmptySnapshotsBlocked(), "first boot must not trip the guard")
}

func TestReconcile_AllowEmptyEnvPermitsDrainToZero(t *testing.T) {
	// EDGE_ALLOW_EMPTY_SNAPSHOT=true is the intentional decommission / drain
	// escape hatch: an operator tearing the edge down must be able to publish an
	// empty snapshot even after a healthy one. Read once at construction.
	t.Setenv("EDGE_ALLOW_EMPTY_SNAPSHOT", "true")

	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))
	v1, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	require.Len(t, v1.GetResources(resourcev3.ListenerType), 2)

	fs.snap = &store.Snapshot{}
	require.NoError(t, r.Reconcile(context.Background()))

	v2, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	assert.Empty(t, v2.GetResources(resourcev3.ListenerType),
		"drain must publish the empty set when explicitly allowed")
	assert.NotEqual(t, v1.GetVersion(resourcev3.ListenerType), v2.GetVersion(resourcev3.ListenerType),
		"drain must push a new (empty) snapshot")
	assert.Equal(t, uint64(0), r.EmptySnapshotsBlocked(), "the escape hatch must not count as blocked")
}

func TestReconcile_PartialShrinkStillPublishes(t *testing.T) {
	// TALYVOR-SAFETY: the guard must fire ONLY on total collapse. A legitimate
	// partial change — some routes/clusters removed while others remain — is
	// non-zero and must publish normally.
	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))
	v1, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	require.Len(t, v1.GetResources(resourcev3.ClusterType), 2)

	// Drop one gateway, one cluster, its endpoints and routes — but leave the
	// rest. Still a non-empty (listeners>0 AND clusters>0) snapshot.
	shrunk := sampleSnapshot()
	shrunk.Gateways = shrunk.Gateways[:1]           // 1 listener remains
	shrunk.Clusters = shrunk.Clusters[:1]           // 1 cluster remains
	shrunk.Routes = []store.Route{shrunk.Routes[0]} // api → api-cluster
	shrunk.Endpoints = shrunk.Endpoints[:2]         // api-cluster endpoints
	fs.snap = shrunk
	require.NoError(t, r.Reconcile(context.Background()))

	v2, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	assert.Len(t, v2.GetResources(resourcev3.ListenerType), 1, "partial shrink must publish the reduced set")
	assert.Len(t, v2.GetResources(resourcev3.ClusterType), 1)
	assert.NotEqual(t, v1.GetVersion(resourcev3.ClusterType), v2.GetVersion(resourcev3.ClusterType),
		"a legitimate partial change must push a new snapshot")
	assert.Equal(t, uint64(0), r.EmptySnapshotsBlocked(), "partial shrink must not trip the guard")
}

// fakeCoordinator implements ha.Coordinator for tests.
type fakeCoordinator struct {
	hash    string
	version uint64
	callErr error
	calls   atomic.Int32
}

func (f *fakeCoordinator) LoadHash(_ context.Context) (string, uint64, error) {
	f.calls.Add(1)
	return f.hash, f.version, f.callErr
}

func (f *fakeCoordinator) StoreHash(_ context.Context, hash string) (uint64, error) {
	if f.callErr != nil {
		return 0, f.callErr
	}
	f.hash = hash
	f.version++
	return f.version, nil
}

func (f *fakeCoordinator) Heartbeat(_ context.Context) error { return f.callErr }

func TestReconcile_HACoordinator_UsesSharedVersion(t *testing.T) {
	cache := newCache()
	coord := &fakeCoordinator{}
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	r.WithCoordinator(coord)

	require.NoError(t, r.Reconcile(context.Background()))

	snap, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	// StoreHash was called (no prior hash), version incremented to 1.
	assert.Equal(t, "v1", snap.GetVersion(resourcev3.ClusterType))
}

func TestReconcile_HACoordinator_ReuseVersionOnSameHash(t *testing.T) {
	cache := newCache()
	coord := &fakeCoordinator{}
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	r.WithCoordinator(coord)

	// First reconcile — establishes hash + version 1.
	require.NoError(t, r.Reconcile(context.Background()))
	firstSnap, _ := cache.GetSnapshot(testNodeID)

	// Simulate another replica having already stored this hash at version 1.
	// coord.hash and coord.version are already set by the first reconcile.
	// Reset local state so the reconciler re-evaluates.
	r.localLast.Store(nil)

	require.NoError(t, r.Reconcile(context.Background()))
	secondSnap, _ := cache.GetSnapshot(testNodeID)

	// Same config hash → same version, no increment.
	assert.Equal(t,
		firstSnap.GetVersion(resourcev3.ClusterType),
		secondSnap.GetVersion(resourcev3.ClusterType),
		"same config must not bump the shared version counter",
	)
}

func TestReconcile_HACoordinator_ErrorFallsBackToLocal(t *testing.T) {
	cache := newCache()
	coord := &fakeCoordinator{callErr: errors.New("redis down")}
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())
	r.WithCoordinator(coord)

	// Must not return an error — Redis failure is non-fatal.
	require.NoError(t, r.Reconcile(context.Background()))

	snap, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	// Falls back to local version counter, which starts at 1.
	assert.Equal(t, "v1", snap.GetVersion(resourcev3.ClusterType))
}

func TestReconcile_HACoordinator_NilIsLocalMode(t *testing.T) {
	cache := newCache()
	// No WithCoordinator call → nil ha, single-instance mode.
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))
	snap, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	assert.Equal(t, "v1", snap.GetVersion(resourcev3.ClusterType))
}

func TestReconcile_EmptyCollapseAfterHealthyKeepsLastSnapshot(t *testing.T) {
	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())

	// Healthy fleet published.
	require.NoError(t, r.Reconcile(context.Background()))
	v1, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	require.Len(t, v1.GetResources(resourcev3.ListenerType), 2)

	// The source read now succeeds but returns nothing: a truncated table or a
	// failover to an un-seeded replica. A state-of-the-world push of this would
	// remove every listener on every proxy — blackholing all talyvor traffic.
	fs.snap = &store.Snapshot{}
	require.NoError(t, r.Reconcile(context.Background()))

	v2, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	assert.Len(t, v2.GetResources(resourcev3.ListenerType), 2,
		"empty collapse must NOT wipe the last-good listeners")
	assert.Equal(t, v1.GetVersion(resourcev3.ListenerType), v2.GetVersion(resourcev3.ListenerType),
		"no new snapshot may be published on empty collapse")
	assert.Equal(t, uint64(1), r.EmptySnapshotsBlocked(), "the suppressed publish must be counted")
}

func TestReconcile_AllClustersGoneKeepsLastSnapshot(t *testing.T) {
	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))
	v1, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	require.Len(t, v1.GetResources(resourcev3.ClusterType), 2)

	// Listeners survive, but every cluster vanished — routes would all
	// blackhole. This is a collapse too and must not be published.
	partial := sampleSnapshot()
	partial.Clusters = nil
	partial.Endpoints = nil
	fs.snap = partial
	require.NoError(t, r.Reconcile(context.Background()))

	v2, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	assert.Len(t, v2.GetResources(resourcev3.ClusterType), 2,
		"all-clusters-gone is a collapse; must keep last-good clusters")
	assert.Equal(t, v1.GetVersion(resourcev3.ClusterType), v2.GetVersion(resourcev3.ClusterType),
		"no new snapshot may be published when all clusters vanish")
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: sampleSnapshot()}, testNodeID, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, 50*time.Millisecond) }()

	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// CFG-1 (was R4 Stage 3a-ii DETECT+SIGNAL): per-service auth can be enforced ONLY
// when ext_authz is globally configured. When it isn't but a route wants auth, the
// reconciler must FAIL CLOSED — raise the loud signal (counter) AND refuse to
// publish — never warn-and-serve-open, so an identity listener can't run unauthed.
func TestReconcile_AuthWantedButExtAuthzOff_FailsClosed(t *testing.T) {
	cache := newCache()
	// ext_authz NOT configured (default zero value: Enabled=false); a route wants
	// auth (auth_policy=jwt), so an identity-bearing listener is requested.
	r := NewReconciler(cache, &fakeStore{snap: authWantingSnapshot()}, testNodeID, discardLogger())

	// FAIL-CLOSED (CFG-1): Reconcile must REFUSE (error) rather than publish an
	// identity-bearing listener that would serve unauthenticated.
	require.Error(t, r.Reconcile(context.Background()),
		"ext_authz off + routes want auth: Reconcile must refuse (fail-closed), not serve open")
	if r.AuthWantedButExtAuthzOff() == 0 {
		t.Error("the loud signal must still fire (counter > 0)")
	}
	// Nothing published: no snapshot reaches the cache, so the proxy gets no
	// config (fail-closed on first boot) — never an open identity listener.
	if _, err := cache.GetSnapshot(testNodeID); err == nil {
		t.Error("fail-closed: no snapshot must be published when ext_authz is off + auth is wanted")
	}
}

func TestReconcile_ExtAuthzOn_NoAuthOffSignal(t *testing.T) {
	cache := newCache()
	// Same auth-wanting route as the fail-closed test, but ext_authz IS configured:
	// the identity-bearing listener is now backed by a real authz filter, so the
	// reconciler must publish normally and NOT raise the auth-off signal.
	r := NewReconciler(cache, &fakeStore{snap: authWantingSnapshot()}, testNodeID, discardLogger())
	r.WithExtAuthz(builders.ExtAuthzOptions{Enabled: true, Address: "auth-service", Port: 9000})
	require.NoError(t, r.Reconcile(context.Background()))
	if got := r.AuthWantedButExtAuthzOff(); got != 0 {
		t.Fatalf("ext_authz configured: the auth-off signal must NOT fire; got %d", got)
	}
	// A snapshot MUST be published — ext_authz-on is the path that serves auth.
	if _, err := cache.GetSnapshot(testNodeID); err != nil {
		t.Errorf("ext_authz on + auth wanted: a snapshot must be published; got %v", err)
	}
}
