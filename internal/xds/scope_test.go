package xds

import (
	"context"
	"sort"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	streamv3 "github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/store"
)

// twoTenantSnapshot: tenant-a's HTTPS gateway pinned to node-a and tenant-b's to
// node-b, each route presenting its own tenant's cert; a shared HTTP gateway stays
// unpinned.
func twoTenantSnapshot() *store.Snapshot {
	pin := func(node string) map[string]string { return map[string]string{NodeHostnameLabel: node} }
	return &store.Snapshot{
		Gateways: []store.Gateway{
			{ID: "gw-shared", Name: "shared-http", Port: 8080, Protocol: "HTTP"},
			{ID: "gw-a", Name: "tenant-a-https", Port: 8443, Protocol: "HTTPS", NodeSelector: pin("node-a")},
			{ID: "gw-b", Name: "tenant-b-https", Port: 8443, Protocol: "HTTPS", NodeSelector: pin("node-b")},
		},
		Routes: []store.Route{
			{ID: "r-s", Name: "shared", GatewayID: "gw-shared", Hosts: []string{"shared.local"}, PathPrefix: "/", ClusterName: "c-a", AuthPolicy: "none"},
			{ID: "r-a", Name: "tenant-a", GatewayID: "gw-a", Hosts: []string{"tenant-a.local"}, PathPrefix: "/", ClusterName: "c-a", AuthPolicy: "none", TLSSecret: "tenant-a-cert"},
			{ID: "r-b", Name: "tenant-b", GatewayID: "gw-b", Hosts: []string{"tenant-b.local"}, PathPrefix: "/", ClusterName: "c-b", AuthPolicy: "none", TLSSecret: "tenant-b-cert"},
		},
		Clusters: []store.Cluster{
			{ID: "ca", Name: "c-a", ConnectTimeout: time.Second},
			{ID: "cb", Name: "c-b", ConnectTimeout: time.Second},
		},
		Endpoints: []store.Endpoint{
			{ID: "ea", ClusterID: "ca", Address: "10.0.0.1", Port: 5678, Weight: 1},
			{ID: "eb", ClusterID: "cb", Address: "10.0.0.2", Port: 5678, Weight: 1},
		},
		Secrets: []store.Secret{
			{ID: "sa", Name: "tenant-a-cert", CertPEM: "A-CERT", KeyPEM: "A-KEY"},
			{ID: "sb", Name: "tenant-b-cert", CertPEM: "B-CERT", KeyPEM: "B-KEY"},
		},
	}
}

func connect(t *testing.T, cache cachev3.SnapshotCache, node string) {
	t.Helper()
	cancel := cache.CreateWatch(
		&cachev3.Request{Node: &corev3.Node{Id: node}, TypeUrl: resourcev3.ClusterType},
		streamv3.NewStreamState(true, nil), make(chan cachev3.Response, 1))
	t.Cleanup(cancel)
}

func names(t *testing.T, cache cachev3.SnapshotCache, node string, typ resourcev3.Type) []string {
	t.Helper()
	snap, err := cache.GetSnapshot(node)
	require.NoError(t, err, "node %s holds no snapshot", node)
	var out []string
	for n := range snap.GetResources(typ) {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Each node's SDS holds only its own tenant's key — at publish, and through the
// catch-up a node that connects after the publish (a new or reconnected proxy)
// receives.
func TestReconcile_EachNodeGetsOnlyItsOwnTenantsKeys(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: twoTenantSnapshot()}, testNodeID, discardLogger())

	connect(t, cache, "node-a")
	require.NoError(t, r.Reconcile(context.Background()))

	require.Equal(t, []string{"tenant-a-cert"}, names(t, cache, "node-a", resourcev3.SecretType))
	require.Equal(t, []string{"shared-http", "tenant-a-https"}, names(t, cache, "node-a", resourcev3.ListenerType))
	require.Empty(t, names(t, cache, testNodeID, resourcev3.SecretType),
		"a node no tenant gateway selects must hold no tenant key")

	// node-b connects while config is stable: catch-up builds ITS snapshot.
	connect(t, cache, "node-b")
	require.NoError(t, r.Reconcile(context.Background()))

	require.Equal(t, []string{"tenant-b-cert"}, names(t, cache, "node-b", resourcev3.SecretType))
	require.Equal(t, []string{"shared-http", "tenant-b-https"}, names(t, cache, "node-b", resourcev3.ListenerType))
	require.Equal(t, []string{"tenant-a-cert"}, names(t, cache, "node-a", resourcev3.SecretType))
}

// Re-pinning a gateway changes no built resource, so the selectors must be in the
// hash: otherwise the version stays put and the cache never delivers the new scope.
func TestReconcile_RepinningAGatewayBumpsTheVersion(t *testing.T) {
	cache := newCache()
	fs := &fakeStore{snap: twoTenantSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())
	connect(t, cache, "node-c")
	require.NoError(t, r.Reconcile(context.Background()))
	before := r.PublishedVersion()
	require.Empty(t, names(t, cache, "node-c", resourcev3.SecretType))

	repinned := twoTenantSnapshot()
	repinned.Gateways[1].NodeSelector = map[string]string{NodeHostnameLabel: "node-c"}
	fs.snap = repinned
	require.NoError(t, r.Reconcile(context.Background()))

	require.NotEqual(t, before, r.PublishedVersion())
	require.Equal(t, []string{"tenant-a-cert"}, names(t, cache, "node-c", resourcev3.SecretType))
}
