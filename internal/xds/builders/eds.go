package builders

import (
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/edge-infra/control-plane/internal/store"
)

func BuildEndpoints(clusters []store.Cluster, endpoints []store.Endpoint) []types.Resource {
	byCluster := make(map[string][]store.Endpoint, len(clusters))
	for _, e := range endpoints {
		byCluster[e.ClusterID] = append(byCluster[e.ClusterID], e)
	}

	out := make([]types.Resource, 0, len(clusters))
	for _, c := range clusters {
		eps := byCluster[c.ID]
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
		out = append(out, &endpointv3.ClusterLoadAssignment{
			ClusterName: c.Name,
			Endpoints: []*endpointv3.LocalityLbEndpoints{{
				LbEndpoints: lbEps,
			}},
		})
	}
	return out
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
