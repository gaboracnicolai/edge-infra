package builders

import (
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// authServiceClusterName is the internal CDS cluster name the ext_authz filter
// targets. Not configurable — it is wired end-to-end within the control plane.
const authServiceClusterName = "auth_service"

// extAuthzFilterName is the Envoy HTTP filter name for ext_authz.
const extAuthzFilterName = "envoy.filters.http.ext_authz"

// ExtAuthzOptions configures the Envoy ext_authz HTTP filter and the static
// cluster pointing at the auth-service gRPC API.
//
// FAIL-CLOSED: the emitted filter sets failure_mode_allow = false, so if the
// auth-service is unreachable Envoy DENIES the request. This is the deliberate
// opposite of the rate limiter's fail-open posture — a fail-open ext_authz
// would silently bypass auth for the whole suite.
type ExtAuthzOptions struct {
	Enabled  bool
	Address  string // auth-service DNS name
	Port     uint32
	CAFile   string // upstream TLS trust CA (presence enables TLS)
	CertFile string // upstream mTLS client cert (optional)
	KeyFile  string // upstream mTLS client key (optional)
}

// extAuthzFilter builds the ext_authz HTTP filter. failure_mode_allow is false
// — auth fails CLOSED.
func extAuthzFilter(opts ExtAuthzOptions) *hcmv3.HttpFilter {
	cfg := &extauthzv3.ExtAuthz{
		TransportApiVersion: corev3.ApiVersion_V3,
		// FAIL CLOSED: deny when the auth-service is unreachable. Never flip
		// this to true — a fail-open ext_authz bypasses auth suite-wide.
		FailureModeAllow: false,
		// Forward the verified downstream client cert (source.certificate) to the
		// auth-service so a jwt_or_mtls route can authorize on the cert alone.
		// Harmless for other policies (no cert presented ⇒ field empty).
		IncludePeerCertificate: true,
		Services: &extauthzv3.ExtAuthz_GrpcService{
			GrpcService: &corev3.GrpcService{
				TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
						ClusterName: authServiceClusterName,
					},
				},
			},
		},
	}
	return &hcmv3.HttpFilter{
		Name: extAuthzFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: mustAny(cfg),
		},
	}
}

// authServiceCluster builds the static STRICT_DNS, HTTP/2 cluster the ext_authz
// filter calls over gRPC, with optional upstream (m)TLS.
func authServiceCluster(opts ExtAuthzOptions) *clusterv3.Cluster {
	c := &clusterv3.Cluster{
		Name:                 authServiceClusterName,
		ConnectTimeout:       durationpb.New(2 * time.Second),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STRICT_DNS},
		LbPolicy:             clusterv3.Cluster_ROUND_ROBIN,
		// gRPC requires HTTP/2 to the upstream.
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
			ClusterName: authServiceClusterName,
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
		c.TransportSocket = upstreamTLS(opts)
	}
	return c
}

// upstreamTLS builds the TransportSocket for the auth-service cluster. The CA
// is always trusted; a client cert/key adds mTLS (which the auth-service
// requires when AUTH_TLS_CA is set).
func upstreamTLS(opts ExtAuthzOptions) *corev3.TransportSocket {
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

func fileDataSource(path string) *corev3.DataSource {
	return &corev3.DataSource{
		Specifier: &corev3.DataSource_Filename{Filename: path},
	}
}
