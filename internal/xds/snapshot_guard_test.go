package xds

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

// inconsistentSnapshot: an EDS cluster with NO ClusterLoadAssignment — Envoy's
// Snapshot.Consistent() flags the dangling EDS reference.
func inconsistentSnapshot(t *testing.T) *cachev3.Snapshot {
	t.Helper()
	snap, err := cachev3.NewSnapshot("v1", map[resourcev3.Type][]types.Resource{
		resourcev3.ClusterType: {&clusterv3.Cluster{
			Name:                 "c1",
			ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_EDS},
			EdsClusterConfig: &clusterv3.Cluster_EdsClusterConfig{
				EdsConfig: &corev3.ConfigSource{
					ConfigSourceSpecifier: &corev3.ConfigSource_Ads{Ads: &corev3.AggregatedConfigSource{}},
				},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func consistentSnapshot(t *testing.T) *cachev3.Snapshot {
	t.Helper()
	snap, err := cachev3.NewSnapshot("v1", map[resourcev3.Type][]types.Resource{})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestShouldBlockInconsistent(t *testing.T) {
	inc := inconsistentSnapshot(t)
	if inc.Consistent() == nil {
		t.Fatal("fixture must be inconsistent (EDS cluster with no endpoint assignment)")
	}
	con := consistentSnapshot(t)
	if con.Consistent() != nil {
		t.Fatalf("empty snapshot must be consistent; got %v", con.Consistent())
	}

	// Inconsistent + a last-good already published → block (keep last-good).
	if !shouldBlockInconsistent(inc, true) {
		t.Error("an inconsistent snapshot with a prior good config must be blocked")
	}
	// Inconsistent on first boot → publish (nothing to keep).
	if shouldBlockInconsistent(inc, false) {
		t.Error("a first-boot inconsistent snapshot must not be blocked")
	}
	// Consistent → always publish.
	if shouldBlockInconsistent(con, true) {
		t.Error("a consistent snapshot must publish")
	}
}
