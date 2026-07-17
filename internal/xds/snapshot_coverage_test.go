package xds

import (
	"testing"
	"time"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds/builders"
)

// buildFromDomain mirrors exactly what Reconcile builds, so these coverage checks
// observe the SAME resources the real data path would emit.
func buildFromDomain(t *testing.T, dom *store.Snapshot) *cachev3.Snapshot {
	t.Helper()
	res := map[resourcev3.Type][]types.Resource{
		resourcev3.ListenerType: builders.BuildListeners(dom.Gateways, dom.Routes, builders.RateLimitOptions{}, builders.ExtAuthzOptions{}, builders.RateLimitServiceOptions{}),
		resourcev3.RouteType:    builders.BuildRouteConfigs(dom.Gateways, dom.Routes, builders.RateLimitServiceOptions{}),
		resourcev3.ClusterType:  builders.BuildClusters(dom.Clusters, builders.ExtAuthzOptions{}, builders.RateLimitServiceOptions{}),
		resourcev3.EndpointType: builders.BuildEndpoints(dom.Clusters, dom.Endpoints),
		resourcev3.SecretType:   builders.BuildSecrets(dom.Secrets),
	}
	snap, err := cachev3.NewSnapshot("v1", res)
	require.NoError(t, err)
	return snap
}

// R8 coverage boundary (verified against the ACTUAL builders, not assumed):
//
// A cluster with no endpoints is CONSISTENT — BuildEndpoints emits an (empty) CLA
// per cluster, so there is no dangling CDS->EDS reference. It serves 503 at runtime
// but is not a snapshot inconsistency; the guard neither does nor need block it.
// (This is why the "route to a cluster with no endpoints" example does NOT reduce
// to an EDS-with-no-CLA inconsistency on this data path.)
func TestCoverage_NoEndpointsClusterIsConsistent(t *testing.T) {
	dom := &store.Snapshot{
		Gateways: []store.Gateway{{ID: "gw1", Name: "edge-http", Port: 8080, Protocol: "HTTP"}},
		Routes:   []store.Route{{ID: "r1", Name: "api", GatewayID: "gw1", Hosts: []string{"api.example.com"}, PathPrefix: "/", ClusterName: "api-cluster", AuthPolicy: "none"}},
		Clusters: []store.Cluster{{ID: "c1", Name: "api-cluster", ConnectTimeout: 5 * time.Second, LbPolicy: "ROUND_ROBIN"}},
		// deliberately NO endpoints for api-cluster
	}
	snap := buildFromDomain(t, dom)
	require.NoError(t, snap.Consistent(), "a no-endpoints cluster is consistent (an empty CLA is still emitted)")
	require.NoError(t, danglingRouteClusterError(snap), "the route's target cluster DOES exist in CDS")
}

// The reachable R8 case + the closed gap: a route whose target cluster has no
// clusters row. Envoy's Snapshot.Consistent() does NOT traverse route->cluster
// references, so it misses this real blackhole — but the widened check catches it.
func TestCoverage_RouteToNonexistentClusterCaughtByWidenedCheck(t *testing.T) {
	dom := &store.Snapshot{
		Gateways:  []store.Gateway{{ID: "gw1", Name: "edge-http", Port: 8080, Protocol: "HTTP"}},
		Routes:    []store.Route{{ID: "r1", Name: "api", GatewayID: "gw1", Hosts: []string{"api.example.com"}, PathPrefix: "/", ClusterName: "ghost", AuthPolicy: "none"}},
		Clusters:  []store.Cluster{{ID: "c1", Name: "real-cluster", ConnectTimeout: 5 * time.Second, LbPolicy: "ROUND_ROBIN"}},
		Endpoints: []store.Endpoint{{ID: "e1", ClusterID: "c1", Address: "10.0.0.1", Port: 8080, Weight: 1}},
	}
	snap := buildFromDomain(t, dom)
	require.NoError(t, snap.Consistent(),
		"Consistent() does NOT flag a route forwarding to a cluster absent from CDS")
	require.Error(t, danglingRouteClusterError(snap),
		"the widened R8 check MUST flag a route to a cluster absent from CDS")
}

// A fully healthy domain trips neither check.
func TestCoverage_HealthySnapshotPassesBothChecks(t *testing.T) {
	snap := buildFromDomain(t, sampleSnapshot())
	require.NoError(t, snap.Consistent())
	require.NoError(t, danglingRouteClusterError(snap))
}
