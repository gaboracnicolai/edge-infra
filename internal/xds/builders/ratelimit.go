package builders

import (
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	ratelimitconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/ratelimit/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	ratelimitfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ratelimit/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// rlsClusterName is the internal CDS cluster name for the rate-limit service.
const rlsClusterName = "ratelimit"

// rateLimitFilterName is the Envoy HTTP filter name for the global ratelimit
// filter (distinct from the per-instance local_ratelimit).
const rateLimitFilterName = "envoy.filters.http.ratelimit"

// RateLimitServiceOptions configures the Envoy global ratelimit filter, its RLS
// cluster, and the per-route descriptors.
//
// FAIL-OPEN: the emitted filter sets failure_mode_deny = false, so if the RLS
// is unreachable Envoy ALLOWS the request — the per-instance local_ratelimit
// floor still applies. This is the same posture as the floor, and the opposite
// of ext_authz: a limiter problem must never block traffic.
type RateLimitServiceOptions struct {
	Enabled  bool
	Address  string // RLS DNS name
	Port     uint32
	Domain   string // ratelimit domain (descriptor namespace)
	CAFile   string // upstream TLS trust CA (presence enables TLS)
	CertFile string // upstream mTLS client cert (optional)
	KeyFile  string // upstream mTLS client key (optional)
}

// rateLimitFilter builds the global ratelimit HTTP filter. failure_mode_deny is
// false — the limiter fails OPEN (degrades to the local_ratelimit floor).
func rateLimitFilter(opts RateLimitServiceOptions) *hcmv3.HttpFilter {
	cfg := &ratelimitfilterv3.RateLimit{
		Domain:          opts.Domain,
		FailureModeDeny: false, // FAIL OPEN — never block on a limiter problem
		Timeout:         durationpb.New(50 * time.Millisecond),
		RateLimitService: &ratelimitconfigv3.RateLimitServiceConfig{
			TransportApiVersion: corev3.ApiVersion_V3,
			GrpcService: &corev3.GrpcService{
				TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
						ClusterName: rlsClusterName,
					},
				},
			},
		},
	}
	return &hcmv3.HttpFilter{
		Name: rateLimitFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: mustAny(cfg),
		},
	}
}

// rateLimitActions returns the per-virtual-host rate_limit actions. Each entry
// produces one descriptor the RLS checks against its own bucket:
//   - user_id from x-user-id (present only on authenticated requests)
//   - remote_address (always) — the IP fallback for unauthenticated routes
func rateLimitActions() []*routev3.RateLimit {
	return []*routev3.RateLimit{
		{
			Actions: []*routev3.RateLimit_Action{{
				ActionSpecifier: &routev3.RateLimit_Action_RequestHeaders_{
					RequestHeaders: &routev3.RateLimit_Action_RequestHeaders{
						HeaderName:    "x-user-id",
						DescriptorKey: "user_id",
					},
				},
			}},
		},
		{
			Actions: []*routev3.RateLimit_Action{{
				ActionSpecifier: &routev3.RateLimit_Action_RemoteAddress_{
					RemoteAddress: &routev3.RateLimit_Action_RemoteAddress{},
				},
			}},
		},
	}
}

// rlsCluster builds the static STRICT_DNS, HTTP/2 cluster for the rate-limit
// service, with optional upstream (m)TLS.
func rlsCluster(opts RateLimitServiceOptions) *clusterv3.Cluster {
	c := &clusterv3.Cluster{
		Name:                 rlsClusterName,
		ConnectTimeout:       durationpb.New(2 * time.Second),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS},
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
		TypedExtensionProtocolOptions: map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": mustAny(&httpv3.HttpProtocolOptions{
				UpstreamProtocolOptions: &httpv3.HttpProtocolOptions_ExplicitHttpConfig_{
					ExplicitHttpConfig: &httpv3.HttpProtocolOptions_ExplicitHttpConfig{
						ProtocolConfig: &httpv3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
							Http2ProtocolOptions: &corev3.Http2ProtocolOptions{},
						},
					},
				},
			}),
		},
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: rlsClusterName,
			Endpoints: []*endpointv3.LocalityLbEndpoints{{
				LbEndpoints: []*endpointv3.LbEndpoint{{
					HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
						Endpoint: &endpointv3.Endpoint{
							Address: socketAddress(opts.Address, opts.Port),
						},
					},
				}},
			}},
		},
	}
	if opts.CAFile != "" {
		c.TransportSocket = rlsUpstreamTLS(opts)
	}
	return c
}

func rlsUpstreamTLS(opts RateLimitServiceOptions) *corev3.TransportSocket {
	common := &tlsv3.CommonTlsContext{
		ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{
			ValidationContext: &tlsv3.CertificateValidationContext{
				TrustedCa: fileDataSource(opts.CAFile),
			},
		},
	}
	if opts.CertFile != "" && opts.KeyFile != "" {
		common.TlsCertificates = []*tlsv3.TlsCertificate{{
			CertificateChain: fileDataSource(opts.CertFile),
			PrivateKey:       fileDataSource(opts.KeyFile),
		}}
	}
	return &corev3.TransportSocket{
		Name: wellknown.TransportSocketTLS,
		ConfigType: &corev3.TransportSocket_TypedConfig{
			TypedConfig: mustAny(&tlsv3.UpstreamTlsContext{CommonTlsContext: common}),
		},
	}
}
