package builders

import (
	"sort"
	"strings"
	"time"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	lrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

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
	var rlActions []*routev3.RateLimit
	if rls.Enabled {
		rlActions = rateLimitActions()
	}

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
			Name:       g.Name + "_default",
			Domains:    []string{"*"},
			RateLimits: rlActions,
		}}
	}

	vhs := make([]*routev3.VirtualHost, 0, len(keys))
	for _, k := range keys {
		b := byHosts[k]
		vhs = append(vhs, &routev3.VirtualHost{
			Name:       g.Name + "_" + k,
			Domains:    b.hosts,
			Routes:     routesFor(b.routes),
			RateLimits: rlActions,
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
		rt := &routev3.Route{
			Name: r.Name,
			Match: &routev3.RouteMatch{
				PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: prefix},
			},
			Action: &routev3.Route_Route{
				Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: r.ClusterName},
				},
			},
		}
		// Per-route typed_per_filter_config, built once so rate_limit and auth can
		// coexist without clobbering each other.
		tpfc := map[string]*anypb.Any{}
		// Per-service rate limit → a local_ratelimit override (the base filter is
		// guaranteed present by the LDS presence guard).
		if r.RateLimitPerUnit > 0 {
			tpfc[localRateLimitFilterName] = mustAny(perRouteLocalRateLimit(r))
		}
		// Per-service auth, three ext_authz modes:
		//   none / mtls   → Disabled (opt-out, or the client cert IS the auth).
		//   jwt_or_mtls   → ENABLED + an auth_policy context extension, so auth.rs
		//                    allows a valid client cert OR falls back to the JWT.
		//   jwt / "" / unknown → no override → the global ext_authz applies.
		// Safe default: an unspecified or unrecognized policy never disables auth.
		switch r.AuthPolicy {
		case "none", "mtls":
			tpfc[extAuthzFilterName] = mustAny(&extauthzv3.ExtAuthzPerRoute{
				Override: &extauthzv3.ExtAuthzPerRoute_Disabled{Disabled: true},
			})
		case "jwt_or_mtls":
			tpfc[extAuthzFilterName] = mustAny(&extauthzv3.ExtAuthzPerRoute{
				Override: &extauthzv3.ExtAuthzPerRoute_CheckSettings{
					CheckSettings: &extauthzv3.CheckSettings{
						ContextExtensions: map[string]string{"auth_policy": "jwt_or_mtls"},
					},
				},
			})
		}
		if len(tpfc) > 0 {
			rt.TypedPerFilterConfig = tpfc
		}
		out = append(out, rt)
	}
	return out
}

// perRouteLocalRateLimit renders a service's rate_limit as a per-route
// local_ratelimit override: a bucket of RateLimitPerUnit tokens refilled fully
// each unit, enforced at 100% with a 429.
func perRouteLocalRateLimit(r store.Route) *lrlv3.LocalRateLimit {
	tokens := uint32(r.RateLimitPerUnit)
	return &lrlv3.LocalRateLimit{
		StatPrefix: "http_local_rate_limit",
		Status:     &typev3.HttpStatus{Code: typev3.StatusCode_TooManyRequests},
		TokenBucket: &typev3.TokenBucket{
			MaxTokens:     tokens,
			TokensPerFill: wrapperspb.UInt32(tokens),
			FillInterval:  durationpb.New(rateLimitUnitDuration(r.RateLimitUnit)),
		},
		FilterEnabled:  fullPercent(),
		FilterEnforced: fullPercent(),
	}
}

// rateLimitUnitDuration maps a ServiceSpec rate_limit unit to a fill interval.
// The unit is validated upstream (SECOND/MINUTE/HOUR); default to a second.
func rateLimitUnitDuration(unit string) time.Duration {
	switch unit {
	case "MINUTE":
		return time.Minute
	case "HOUR":
		return time.Hour
	default:
		return time.Second
	}
}
