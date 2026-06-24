package builders

import (
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	"github.com/edge-infra/control-plane/internal/store"
)

// RateLimitOptions configures the per-listener Envoy local_ratelimit filter.
// It is intentionally fail-open: when the limiter is disabled or misconfigured
// the gateway keeps serving traffic. This is the opposite posture from auth.
type RateLimitOptions struct {
	Enabled       bool
	MaxTokens     uint32        // burst size
	TokensPerFill uint32        // tokens added each fill interval
	FillInterval  time.Duration // refill period (must be > 0)
}

func BuildListeners(gateways []store.Gateway, rl RateLimitOptions) []types.Resource {
	out := make([]types.Resource, 0, len(gateways))
	for _, g := range gateways {
		out = append(out, listenerForGateway(g, rl))
	}
	return out
}

func listenerForGateway(g store.Gateway, rl RateLimitOptions) *listenerv3.Listener {
	hcm := &hcmv3.HttpConnectionManager{
		CodecType:  hcmv3.HttpConnectionManager_AUTO,
		StatPrefix: g.Name,
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{
				ConfigSource:    AdsConfigSource(),
				RouteConfigName: RouteConfigName(g.Name),
			},
		},
		HttpFilters: httpFilters(rl),
	}

	filterChain := &listenerv3.FilterChain{
		Filters: []*listenerv3.Filter{{
			Name: wellknown.HTTPConnectionManager,
			ConfigType: &listenerv3.Filter_TypedConfig{
				TypedConfig: mustAny(hcm),
			},
		}},
	}

	if g.Protocol == "HTTPS" && g.TLSSecret != "" {
		filterChain.TransportSocket = downstreamTLS(g.TLSSecret)
	}

	return &listenerv3.Listener{
		Name:         g.Name,
		Address:      socketAddress("0.0.0.0", g.Port),
		FilterChains: []*listenerv3.FilterChain{filterChain},
	}
}

// httpFilters returns the HCM filter chain. The router must always be last.
func httpFilters(rl RateLimitOptions) []*hcmv3.HttpFilter {
	// RED: the local_ratelimit filter is not added yet — only the router.
	return []*hcmv3.HttpFilter{routerFilter()}
}

func routerFilter() *hcmv3.HttpFilter {
	return &hcmv3.HttpFilter{
		Name: wellknown.Router,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: mustAny(&routerv3.Router{}),
		},
	}
}

func downstreamTLS(secretName string) *corev3.TransportSocket {
	ctx := &tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{{
				Name:      secretName,
				SdsConfig: AdsConfigSource(),
			}},
		},
	}
	return &corev3.TransportSocket{
		Name: wellknown.TransportSocketTLS,
		ConfigType: &corev3.TransportSocket_TypedConfig{
			TypedConfig: mustAny(ctx),
		},
	}
}
