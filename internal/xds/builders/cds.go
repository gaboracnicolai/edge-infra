package builders

import (
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/edge-infra/control-plane/internal/store"
)

func BuildClusters(clusters []store.Cluster) []types.Resource {
	out := make([]types.Resource, 0, len(clusters))
	for _, c := range clusters {
		out = append(out, &clusterv3.Cluster{
			Name:                 c.Name,
			ConnectTimeout:       durationpb.New(c.ConnectTimeout),
			ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_EDS},
			LbPolicy:             lbPolicy(c.LbPolicy),
			EdsClusterConfig: &clusterv3.Cluster_EdsClusterConfig{
				EdsConfig: AdsConfigSource(),
			},
		})
	}
	return out
}

func lbPolicy(s string) clusterv3.Cluster_LbPolicy {
	switch s {
	case "LEAST_REQUEST":
		return clusterv3.Cluster_LEAST_REQUEST
	case "RANDOM":
		return clusterv3.Cluster_RANDOM
	case "RING_HASH":
		return clusterv3.Cluster_RING_HASH
	case "MAGLEV":
		return clusterv3.Cluster_MAGLEV
	default:
		return clusterv3.Cluster_ROUND_ROBIN
	}
}
