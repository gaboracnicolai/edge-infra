package builders

import (
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/edge-infra/control-plane/internal/store"
)

func BuildClusters(clusters []store.Cluster, ea ExtAuthzOptions, rls RateLimitServiceOptions) []types.Resource {
	out := make([]types.Resource, 0, len(clusters)+2)
	for _, c := range clusters {
		cl := &clusterv3.Cluster{
			Name:                 c.Name,
			ConnectTimeout:       durationpb.New(c.ConnectTimeout),
			ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_EDS},
			LbPolicy:             lbPolicy(c.LbPolicy),
			EdsClusterConfig: &clusterv3.Cluster_EdsClusterConfig{
				EdsConfig: AdsConfigSource(),
			},
		}
		if c.HealthCheckPath != "" {
			cl.HealthChecks = []*corev3.HealthCheck{activeHealthCheck(c)}
		}
		out = append(out, cl)
	}
	if ea.Enabled {
		out = append(out, authServiceCluster(ea))
	}
	if rls.Enabled {
		out = append(out, rlsCluster(rls))
	}
	return out
}

// activeHealthCheck builds a per-cluster active HTTP health check that probes
// each EDS endpoint (its own host:port) at the service's health_check path and
// interval. Timeout is capped at the interval so a probe can't outlive its cycle.
func activeHealthCheck(c store.Cluster) *corev3.HealthCheck {
	interval := time.Duration(c.HealthCheckIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	timeout := 5 * time.Second
	if interval < timeout {
		timeout = interval
	}
	return &corev3.HealthCheck{
		Timeout:            durationpb.New(timeout),
		Interval:           durationpb.New(interval),
		HealthyThreshold:   wrapperspb.UInt32(1),
		UnhealthyThreshold: wrapperspb.UInt32(3),
		HealthChecker: &corev3.HealthCheck_HttpHealthCheck_{
			HttpHealthCheck: &corev3.HealthCheck_HttpHealthCheck{
				Path: c.HealthCheckPath,
			},
		},
	}
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
