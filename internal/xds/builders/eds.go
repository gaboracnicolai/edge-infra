package builders

import (
	"net/netip"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/edge-infra/control-plane/internal/store"
)

// BuildEndpoints emits a CLA for every EDS cluster. A STRICT_DNS cluster (one
// with a hostname endpoint) carries its endpoints inline from BuildClusters and
// gets no CLA here — a CLA nothing references makes the snapshot inconsistent.
func BuildEndpoints(clusters []store.Cluster, endpoints []store.Endpoint) []types.Resource {
	byCluster := endpointsByCluster(endpoints)

	out := make([]types.Resource, 0, len(clusters))
	for _, c := range clusters {
		eps := byCluster[c.ID]
		if hasHostname(eps) {
			continue
		}
		out = append(out, loadAssignment(c.Name, eps))
	}
	return out
}

func endpointsByCluster(endpoints []store.Endpoint) map[string][]store.Endpoint {
	byCluster := make(map[string][]store.Endpoint)
	for _, e := range endpoints {
		byCluster[e.ClusterID] = append(byCluster[e.ClusterID], e)
	}
	return byCluster
}

// hasHostname reports whether any endpoint address is a hostname rather than
// an IP literal — such a cluster must be resolved by Envoy (STRICT_DNS).
func hasHostname(eps []store.Endpoint) bool {
	for _, e := range eps {
		if _, err := netip.ParseAddr(e.Address); err != nil {
			return true
		}
	}
	return false
}

func loadAssignment(clusterName string, eps []store.Endpoint) *endpointv3.ClusterLoadAssignment {
	lbEps := make([]*endpointv3.LbEndpoint, 0, len(eps))
	for _, e := range eps {
		lbEps = append(lbEps, &endpointv3.LbEndpoint{
			HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
				Endpoint: &endpointv3.Endpoint{
					Address: socketAddress(e.Address, e.Port),
				},
			},
			LoadBalancingWeight: &wrapperspb.UInt32Value{Value: e.Weight},
		})
	}
	return &endpointv3.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpointv3.LocalityLbEndpoints{{
			LbEndpoints: lbEps,
		}},
	}
}

func socketAddress(addr string, port uint32) *corev3.Address {
	return &corev3.Address{
		Address: &corev3.Address_SocketAddress{
			SocketAddress: &corev3.SocketAddress{
				Protocol:      corev3.SocketAddress_TCP,
				Address:       addr,
				PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port},
			},
		},
	}
}
