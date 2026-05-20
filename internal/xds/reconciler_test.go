package xds

import (
	"context"
	"errors"
	"io"
	"log/slog"
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

func (f *fakeStore) UpsertGateway(_ context.Context, _ store.Gateway) error      { return nil }
func (f *fakeStore) DeleteGateway(_ context.Context, _ string) error             { return nil }
func (f *fakeStore) UpsertRoute(_ context.Context, _ store.Route) error          { return nil }
func (f *fakeStore) DeleteRoute(_ context.Context, _ string, _ string) error     { return nil }

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
		Routes: []store.Route{
			{ID: "r1", Name: "api", GatewayID: "gw1", Hosts: []string{"api.example.com"}, PathPrefix: "/", ClusterName: "api-cluster"},
			{ID: "r2", Name: "web", GatewayID: "gw1", Hosts: []string{"www.example.com"}, PathPrefix: "/", ClusterName: "web-cluster"},
			{ID: "r3", Name: "tls", GatewayID: "gw2", Hosts: []string{"secure.example.com"}, PathPrefix: "/", ClusterName: "api-cluster"},
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

func TestReconcile_EmptySnapshotProducesEmptyResources(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: &store.Snapshot{}}, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))

	snap, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err)
	assert.Empty(t, snap.GetResources(resourcev3.ListenerType))
	assert.Empty(t, snap.GetResources(resourcev3.ClusterType))
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
