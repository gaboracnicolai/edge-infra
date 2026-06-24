package builders

import (
	"math"
	"strconv"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	lrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

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

func BuildListeners(gateways []store.Gateway, rl RateLimitOptions, ea ExtAuthzOptions) []types.Resource {
	out := make([]types.Resource, 0, len(gateways))
	for _, g := range gateways {
		out = append(out, listenerForGateway(g, rl, ea))
	}
	return out
}

func listenerForGateway(g store.Gateway, rl RateLimitOptions, ea ExtAuthzOptions) *listenerv3.Listener {
	hcm := &hcmv3.HttpConnectionManager{
		CodecType:  hcmv3.HttpConnectionManager_AUTO,
		StatPrefix: g.Name,
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{
				ConfigSource:    AdsConfigSource(),
				RouteConfigName: RouteConfigName(g.Name),
			},
		},
		HttpFilters: httpFilters(rl, ea),
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

// httpFilters returns the HCM filter chain in order: local_ratelimit (a coarse
// pre-auth IP throttle that shields the auth-service from unauthenticated
// floods) → ext_authz → router (always last). Phase B's identity-keyed limiter
// will sit after ext_authz, once x-user-id flows.
func httpFilters(rl RateLimitOptions, ea ExtAuthzOptions) []*hcmv3.HttpFilter {
	var filters []*hcmv3.HttpFilter
	if rl.Enabled {
		filters = append(filters, localRateLimitFilter(rl))
	}
	if ea.Enabled {
		filters = append(filters, extAuthzFilter(ea))
	}
	return append(filters, routerFilter())
}

func routerFilter() *hcmv3.HttpFilter {
	return &hcmv3.HttpFilter{
		Name: wellknown.Router,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: mustAny(&routerv3.Router{}),
		},
	}
}

// localRateLimitFilter builds a per-listener Envoy local_ratelimit filter: a
// token bucket that returns 429 + Retry-After when exhausted. It is enforced
// at 100% (not shadow mode). Being an in-Envoy filter it is inherently
// fail-open — it can throttle, but a problem with it cannot 503 the gateway.
func localRateLimitFilter(rl RateLimitOptions) *hcmv3.HttpFilter {
	fill := rl.FillInterval
	if fill <= 0 {
		fill = time.Second
	}
	retryAfter := strconv.Itoa(int(math.Ceil(fill.Seconds())))

	cfg := &lrlv3.LocalRateLimit{
		StatPrefix: "http_local_rate_limit",
		Status:     &typev3.HttpStatus{Code: typev3.StatusCode_TooManyRequests},
		TokenBucket: &typev3.TokenBucket{
			MaxTokens:     rl.MaxTokens,
			TokensPerFill: wrapperspb.UInt32(rl.TokensPerFill),
			FillInterval:  durationpb.New(fill),
		},
		FilterEnabled:  fullPercent(),
		FilterEnforced: fullPercent(),
		ResponseHeadersToAdd: []*corev3.HeaderValueOption{{
			Header: &corev3.HeaderValue{
				Key:   "Retry-After",
				Value: retryAfter,
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}},
	}
	return &hcmv3.HttpFilter{
		Name: "envoy.filters.http.local_ratelimit",
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: mustAny(cfg),
		},
	}
}

// fullPercent is 100% — the filter applies to and enforces every request.
func fullPercent() *corev3.RuntimeFractionalPercent {
	return &corev3.RuntimeFractionalPercent{
		DefaultValue: &typev3.FractionalPercent{
			Numerator:   100,
			Denominator: typev3.FractionalPercent_HUNDRED,
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
