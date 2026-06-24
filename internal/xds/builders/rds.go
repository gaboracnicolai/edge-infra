package builders

import (
	"sort"
	"strings"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"

	"github.com/edge-infra/control-plane/internal/store"
)

func BuildRouteConfigs(gateways []store.Gateway, routes []store.Route, rls RateLimitServiceOptions) []types.Resource {
	byGateway := make(map[string][]store.Route, len(gateways))
	for _, r := range routes {
		byGateway[r.GatewayID] = append(byGateway[r.GatewayID], r)
	}

	out := make([]types.Resource, 0, len(gateways))
	for _, g := range gateways {
		out = append(out, &routev3.RouteConfiguration{
			Name:         RouteConfigName(g.Name),
			VirtualHosts: virtualHostsFor(g, byGateway[g.ID], rls),
		})
	}
	return out
}

func virtualHostsFor(g store.Gateway, routes []store.Route, rls RateLimitServiceOptions) []*routev3.VirtualHost {
	type bucket struct {
		hosts  []string
		routes []store.Route
	}
	byHosts := map[string]*bucket{}
	keys := []string{}

	for _, r := range routes {
		hosts := r.Hosts
		if len(hosts) == 0 {
			hosts = []string{"*"}
		}
		k := strings.Join(hosts, ",")
		if _, ok := byHosts[k]; !ok {
			byHosts[k] = &bucket{hosts: hosts}
			keys = append(keys, k)
		}
		byHosts[k].routes = append(byHosts[k].routes, r)
	}
	sort.Strings(keys)

	if len(keys) == 0 {
		return []*routev3.VirtualHost{{
			Name:    g.Name + "_default",
			Domains: []string{"*"},
		}}
	}

	vhs := make([]*routev3.VirtualHost, 0, len(keys))
	for _, k := range keys {
		b := byHosts[k]
		vhs = append(vhs, &routev3.VirtualHost{
			Name:    g.Name + "_" + k,
			Domains: b.hosts,
			Routes:  routesFor(b.routes),
		})
	}
	return vhs
}

func routesFor(rs []store.Route) []*routev3.Route {
	out := make([]*routev3.Route, 0, len(rs))
	for _, r := range rs {
		prefix := r.PathPrefix
		if prefix == "" {
			prefix = "/"
		}
		out = append(out, &routev3.Route{
			Name: r.Name,
			Match: &routev3.RouteMatch{
				PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: prefix},
			},
			Action: &routev3.Route_Route{
				Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: r.ClusterName},
				},
			},
		})
	}
	return out
}
