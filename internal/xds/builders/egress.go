package builders

import (
	"strconv"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	grpcalv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	dnscommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/common/dns/v3"
	dnsclusterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dns/v3"
	commonrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	lrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	metadatav3 "github.com/envoyproxy/go-control-plane/envoy/type/metadata/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/edge-infra/control-plane/internal/decisions"
	"github.com/edge-infra/control-plane/internal/store"
)

// The egress gateway (B28.222). edge-egress Envoys serve one listener that agents
// use as their HTTP proxy, and it reaches only the hosts in egress_destinations:
//
//   - a plain-HTTP request for a listed host (http_proxy, or Host: <host>) is sent
//     on over TLS the proxy originates and verifies — SNI is the host, and the
//     server's certificate must name it and chain to the destination's CA;
//   - CONNECT <host>:<port> for a listed host opens a TCP tunnel to it, and the
//     agent's own TLS runs through it end to end (https_proxy);
//   - any other host, CONNECT included, gets 403 from the proxy.
//
// A keyless destination (B28.224) takes no credential from the agent. Its
// plain-HTTP route goes through ext_authz in the auth-service's agent mode: the
// agent's workload token in Proxy-Authorization is verified, every credential
// it sent is removed, and the signed transit assertion is added. CONNECT to it
// is refused, since the agent's own TLS would carry its credentials past the
// gateway unseen. With ext_authz off on the control plane a keyless host is
// closed (503) rather than open.
//
// Each agent has a rate limit of its own (B28.228): a token bucket per agent —
// the ServiceAccount the auth-service verified, which it hands Envoy as ext_authz
// metadata — and per client address, so traffic from an agent that proved no
// identity is limited by the pod it comes from. Over the limit the agent gets
// 429. Every decision is logged with the agent in it, and sent to the control
// plane's hash-chained decision log.

const (
	// EgressListenerName is the edge-egress listener (and its stat prefix).
	EgressListenerName = "egress"
	// EgressRouteConfigName is the route config the egress listener reads.
	EgressRouteConfigName = "egress_routes"

	// DefaultEgressPort is the port agents send proxied requests to.
	DefaultEgressPort = 3128
	// DefaultEgressSystemCAFile is the trust store in the Envoy image, used for a
	// destination that names no CA of its own.
	DefaultEgressSystemCAFile = "/etc/ssl/certs/ca-certificates.crt"

	// egressDeniedBody is what a request for an unlisted host gets, with a 403.
	egressDeniedBody = "edge-egress: destination not allowed\n"

	// egressAgentPolicy is the auth_policy a keyless route sends the auth-service.
	egressAgentPolicy = "agent"

	// defaultEgressConnectTimeout applies to a destination row with none.
	defaultEgressConnectTimeout = 5 * time.Second

	// egressControlPlaneCluster is the edge-egress bootstrap's static cluster to
	// the control plane (deploy/helm/edge-egress/templates/configmap.yaml). The
	// decision log travels over it, on the mTLS connection xDS already uses.
	egressControlPlaneCluster = "xds_cluster"

	// egressAgentRateLimitPrefix is the agent rate limit's stat prefix.
	egressAgentRateLimitPrefix = "egress_agent_rate_limit"

	// maxAgentBuckets is how many agents' buckets (and as many client
	// addresses') one edge-egress Envoy keeps. Past it, the agent seen least
	// recently is forgotten and starts again with a full bucket.
	maxAgentBuckets = 4096
)

// egressLogFields are what the egress access log carries besides
// accessLogFields: the agent the auth-service verified (null when it proved
// none). With response_flags (RL: the agent's rate limit, UAEX: the
// auth-service refused it) and response_code_details, they are the decision.
var egressLogFields = []logField{
	{"agent", "%DYNAMIC_METADATA(" + decisions.AgentMetadataNamespace + ":" + decisions.AgentMetadataKey + ")%"},
}

// EgressOptions configures the edge-egress listener.
type EgressOptions struct {
	Port         uint32 // the agents' proxy port
	SystemCAFile string // trust store for a destination with no CA secret

	// AgentRequestsPerMinute is how many requests each agent may send through
	// one edge-egress Envoy in a minute; 0 is no limit.
	AgentRequestsPerMinute uint32
	// DecisionLog sends every decision to the control plane's decision log.
	DecisionLog bool
}

// EgressClusterName is the cluster that originates TLS to d's host.
func EgressClusterName(d store.EgressDestination) string { return "egress_" + d.Name }

// EgressTunnelClusterName is the raw-TCP cluster CONNECT tunnels to d's host use.
func EgressTunnelClusterName(d store.EgressDestination) string {
	return "egress_" + d.Name + "_tunnel"
}

// BuildEgress renders everything an edge-egress Envoy holds: its listener, the
// allow-list route config, two DNS clusters per destination, the auth-service
// cluster when a destination is keyless, the telemetry cluster when telemetry
// is on, and the CA bundles the destinations name. Only validation_context
// secrets are included — never a private key — so a name that resolves to
// anything else leaves that upstream unverifiable, and closed.
func BuildEgress(dests []store.EgressDestination, secrets []store.Secret, opts EgressOptions, ea ExtAuthzOptions, tel TelemetryOptions) map[resourcev3.Type][]types.Resource {
	authz := false
	clusters := make([]types.Resource, 0, 2*len(dests)+2)
	cas := map[string]bool{}
	for _, d := range dests {
		clusters = append(clusters, egressTLSCluster(d, opts), egressTunnelCluster(d))
		if d.CASecret != "" {
			cas[d.CASecret] = true
		}
		authz = authz || (d.Keyless && ea.Enabled)
	}
	if authz {
		clusters = append(clusters, authServiceCluster(ea))
	}
	clusters = append(clusters, TelemetryClusters(tel)...)

	var bundles []store.Secret
	for _, s := range secrets {
		if cas[s.Name] && s.Kind == "validation_context" {
			bundles = append(bundles, s)
		}
	}

	return map[resourcev3.Type][]types.Resource{
		resourcev3.ListenerType: {egressListener(opts, authz, ea, tel)},
		resourcev3.RouteType:    {egressRouteConfig(dests, ea.Enabled, authz)},
		resourcev3.ClusterType:  clusters,
		resourcev3.SecretType:   BuildSecrets(bundles),
	}
}

func egressListener(opts EgressOptions, authz bool, ea ExtAuthzOptions, tel TelemetryOptions) *listenerv3.Listener {
	var filters []*hcmv3.HttpFilter
	if authz {
		// Only keyless routes enable it; every other route turns it off.
		filters = append(filters, extAuthzFilter(ea))
	}
	if opts.AgentRequestsPerMinute > 0 {
		// After ext_authz, which names the agent.
		filters = append(filters, agentRateLimitFilter(opts.AgentRequestsPerMinute))
	}
	filters = append(filters, &hcmv3.HttpFilter{
		Name: wellknown.Router,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			// No x-envoy-* headers on requests that leave the cluster.
			TypedConfig: mustAny(&routerv3.Router{SuppressEnvoyHeaders: true}),
		},
	})
	hcm := &hcmv3.HttpConnectionManager{
		CodecType:  hcmv3.HttpConnectionManager_AUTO,
		StatPrefix: EgressListenerName,
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{ConfigSource: AdsConfigSource(), RouteConfigName: EgressRouteConfigName},
		},
		// Envoy answers CONNECT with 403 unless it is enabled here; the routes then
		// decide which CONNECTs are tunnelled.
		UpgradeConfigs:        []*hcmv3.HttpConnectionManager_UpgradeConfig{{UpgradeType: "CONNECT"}},
		Http2ProtocolOptions:  &corev3.Http2ProtocolOptions{AllowConnect: true},
		RequestHeadersTimeout: durationpb.New(requestHeadersTimeout),
		StreamIdleTimeout:     durationpb.New(streamIdleTimeout),
		CommonHttpProtocolOptions: &corev3.HttpProtocolOptions{
			IdleTimeout: durationpb.New(connectionIdleTimeout),
		},
		// The client is the address the connection comes from, never one the
		// agent claims in X-Forwarded-For: the rate limit keys on it and the
		// logs record it. Nothing is appended to X-Forwarded-For on the way out.
		UseRemoteAddress: wrapperspb.Bool(true),
		SkipXffAppend:    true,
		HttpFilters:      filters,
	}
	observeConnectionManager(hcm, EgressListenerName, tel, egressLogFields...)
	if opts.DecisionLog {
		hcm.AccessLog = append(hcm.AccessLog, decisionLogger())
	}
	return &listenerv3.Listener{
		Name:    EgressListenerName,
		Address: socketAddress("0.0.0.0", opts.Port),
		FilterChains: []*listenerv3.FilterChain{{
			Filters: []*listenerv3.Filter{{
				Name:       wellknown.HTTPConnectionManager,
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: mustAny(hcm)},
			}},
		}},
	}
}

// agentRateLimitFilter gives every agent a bucket of perMinute requests,
// refilled each minute. A request is counted against its agent (the
// ServiceAccount in the auth-service's metadata, when it proved one) and its
// client address; when either bucket is empty it gets 429, with Retry-After and
// the X-RateLimit headers.
func agentRateLimitFilter(perMinute uint32) *hcmv3.HttpFilter {
	bucket := &typev3.TokenBucket{
		MaxTokens:     perMinute,
		TokensPerFill: wrapperspb.UInt32(perMinute),
		FillInterval:  durationpb.New(time.Minute),
	}
	wildcard := func(key string) *commonrlv3.LocalRateLimitDescriptor {
		// No value: a bucket for each value seen.
		return &commonrlv3.LocalRateLimitDescriptor{
			Entries:     []*commonrlv3.RateLimitDescriptor_Entry{{Key: key}},
			TokenBucket: bucket,
		}
	}
	cfg := &lrlv3.LocalRateLimit{
		StatPrefix:     egressAgentRateLimitPrefix,
		Status:         &typev3.HttpStatus{Code: typev3.StatusCode_TooManyRequests},
		TokenBucket:    bucket,
		FilterEnabled:  fullPercent(),
		FilterEnforced: fullPercent(),
		RateLimits: []*routev3.RateLimit{
			{Actions: []*routev3.RateLimit_Action{{
				ActionSpecifier: &routev3.RateLimit_Action_Metadata{Metadata: &routev3.RateLimit_Action_MetaData{
					DescriptorKey: "agent",
					MetadataKey: &metadatav3.MetadataKey{
						Key:  decisions.AgentMetadataNamespace,
						Path: []*metadatav3.MetadataKey_PathSegment{{Segment: &metadatav3.MetadataKey_PathSegment_Key{Key: decisions.AgentMetadataKey}}},
					},
					Source: routev3.RateLimit_Action_MetaData_DYNAMIC,
				}},
			}}},
			{Actions: []*routev3.RateLimit_Action{{
				ActionSpecifier: &routev3.RateLimit_Action_RemoteAddress_{RemoteAddress: &routev3.RateLimit_Action_RemoteAddress{}},
			}}},
		},
		Descriptors: []*commonrlv3.LocalRateLimitDescriptor{wildcard("agent"), wildcard("remote_address")},
		// Every request has a client address, so a descriptor always matches
		// and the filter-wide bucket is never the one counted.
		AlwaysConsumeDefaultTokenBucket: wrapperspb.Bool(false),
		MaxDynamicDescriptors:           wrapperspb.UInt32(maxAgentBuckets),
		EnableXRatelimitHeaders:         commonrlv3.XRateLimitHeadersRFCVersion_DRAFT_VERSION_03,
		ResponseHeadersToAdd: []*corev3.HeaderValueOption{{
			Header:       &corev3.HeaderValue{Key: "Retry-After", Value: "60"},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		}},
	}
	return &hcmv3.HttpFilter{
		Name:       localRateLimitFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(cfg)},
	}
}

// decisionLogger sends every egress access-log entry to the control plane's
// decision log (decisions.Service) over the xDS connection, a batch a second.
// Like every access log it is fail-open: entries an unreachable control plane
// cannot take are dropped, never a request.
func decisionLogger() *accesslogv3.AccessLog {
	return &accesslogv3.AccessLog{
		Name: "envoy.access_loggers.http_grpc",
		ConfigType: &accesslogv3.AccessLog_TypedConfig{
			TypedConfig: mustAny(&grpcalv3.HttpGrpcAccessLogConfig{
				CommonConfig: &grpcalv3.CommonGrpcAccessLogConfig{
					LogName: decisions.LogName,
					GrpcService: &corev3.GrpcService{
						TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
							EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{ClusterName: egressControlPlaneCluster},
						},
					},
					TransportApiVersion: corev3.ApiVersion_V3,
					BufferFlushInterval: durationpb.New(time.Second),
				},
			}),
		},
	}
}

// egressRouteConfig has one virtual host per destination — its bare host for
// proxied HTTP, host:port for CONNECT — and a catch-all that refuses the rest.
// A CONNECT request matches only a connect_matcher route, so each host carries
// one of each. With the ext_authz filter on the listener (authz), only a keyless
// host's plain-HTTP route runs it; every other route switches it off.
func egressRouteConfig(dests []store.EgressDestination, extAuthzEnabled, authz bool) *routev3.RouteConfiguration {
	vhs := make([]*routev3.VirtualHost, 0, len(dests)+1)
	for _, d := range dests {
		connect := &routev3.Route{
			Name:  d.Name + "_connect",
			Match: connectMatch(),
			Action: &routev3.Route_Route{Route: &routev3.RouteAction{
				ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: EgressTunnelClusterName(d)},
				Timeout:          durationpb.New(0),
				// connect_config terminates the CONNECT here: the tunnel's bytes
				// go to the cluster as plain TCP.
				UpgradeConfigs: []*routev3.RouteAction_UpgradeConfig{{
					UpgradeType:   "CONNECT",
					ConnectConfig: &routev3.RouteAction_UpgradeConfig_ConnectConfig{},
				}},
			}},
		}
		plain := &routev3.Route{
			Name:  d.Name,
			Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
			Action: &routev3.Route_Route{Route: &routev3.RouteAction{
				ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: EgressClusterName(d)},
				// Model calls stream for minutes; the stream idle timeout still
				// reaps one that stalls.
				Timeout: durationpb.New(0),
			}},
		}
		if d.Keyless {
			connect.Action = directResponse(403, "edge-egress: "+d.Host+" is keyless: send plain http:// through the proxy, not CONNECT\n")
			if extAuthzEnabled {
				plain.TypedPerFilterConfig = map[string]*anypb.Any{extAuthzFilterName: mustAny(&extauthzv3.ExtAuthzPerRoute{
					Override: &extauthzv3.ExtAuthzPerRoute_CheckSettings{CheckSettings: &extauthzv3.CheckSettings{
						ContextExtensions: map[string]string{"auth_policy": egressAgentPolicy},
					}},
				})}
			} else {
				// Nothing could remove the agent's credentials: closed, not open.
				plain.Action = directResponse(503, "edge-egress: "+d.Host+" is keyless and ext_authz is off\n")
			}
		}
		vhs = append(vhs, &routev3.VirtualHost{
			Name:    "egress_" + d.Name,
			Domains: []string{d.Host, d.Host + ":" + strconv.FormatUint(uint64(d.Port), 10)},
			Routes:  []*routev3.Route{connect, plain},
		})
	}
	deny := directResponse(403, egressDeniedBody)
	vhs = append(vhs, &routev3.VirtualHost{
		Name:    "egress_denied",
		Domains: []string{"*"},
		Routes: []*routev3.Route{
			{Name: "denied_connect", Match: connectMatch(), Action: deny},
			{Name: "denied", Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}}, Action: deny},
		},
	})
	if authz {
		for _, vh := range vhs {
			for _, rt := range vh.GetRoutes() {
				if rt.TypedPerFilterConfig == nil {
					rt.TypedPerFilterConfig = map[string]*anypb.Any{extAuthzFilterName: mustAny(&extauthzv3.ExtAuthzPerRoute{
						Override: &extauthzv3.ExtAuthzPerRoute_Disabled{Disabled: true},
					})}
				}
			}
		}
	}
	return &routev3.RouteConfiguration{
		Name:         EgressRouteConfigName,
		VirtualHosts: vhs,
		// What use_remote_address makes Envoy add about the agent stays here.
		RequestHeadersToRemove: []string{"x-envoy-external-address", "x-envoy-internal"},
	}
}

func directResponse(status uint32, body string) *routev3.Route_DirectResponse {
	return &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{
		Status: status,
		Body:   &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: body}},
	}}
}

func connectMatch() *routev3.RouteMatch {
	return &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_ConnectMatcher_{
		ConnectMatcher: &routev3.RouteMatch_ConnectMatcher{},
	}}
}

// egressDNSCluster resolves d's host by DNS (IPv4 first, every address one
// endpoint — logical DNS), on d's port.
func egressDNSCluster(name string, d store.EgressDestination) *clusterv3.Cluster {
	timeout := d.ConnectTimeout
	if timeout <= 0 {
		timeout = defaultEgressConnectTimeout
	}
	return &clusterv3.Cluster{
		Name:           name,
		ConnectTimeout: durationpb.New(timeout),
		ClusterDiscoveryType: &clusterv3.Cluster_ClusterType{ClusterType: &clusterv3.Cluster_CustomClusterType{
			Name: "envoy.cluster.dns",
			TypedConfig: mustAny(&dnsclusterv3.DnsCluster{
				DnsLookupFamily:              dnscommonv3.DnsLookupFamily_V4_PREFERRED,
				AllAddressesInSingleEndpoint: true,
			}),
		}},
		LoadAssignment: loadAssignment(name, []store.Endpoint{{Address: d.Host, Port: d.Port, Weight: 1}}),
	}
}

func egressTunnelCluster(d store.EgressDestination) *clusterv3.Cluster {
	return egressDNSCluster(EgressTunnelClusterName(d), d)
}

// egressTLSCluster originates TLS to d: SNI is the host, and the server's
// certificate must name the host and chain to d's CA bundle (over SDS) or, when d
// names none, to the system trust store.
func egressTLSCluster(d store.EgressDestination, opts EgressOptions) *clusterv3.Cluster {
	verify := &tlsv3.CertificateValidationContext{
		MatchTypedSubjectAltNames: []*tlsv3.SubjectAltNameMatcher{{
			SanType: tlsv3.SubjectAltNameMatcher_DNS,
			Matcher: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: d.Host}},
		}},
	}
	common := &tlsv3.CommonTlsContext{}
	if d.CASecret != "" {
		common.ValidationContextType = &tlsv3.CommonTlsContext_CombinedValidationContext{
			CombinedValidationContext: &tlsv3.CommonTlsContext_CombinedCertificateValidationContext{
				DefaultValidationContext: verify,
				ValidationContextSdsSecretConfig: &tlsv3.SdsSecretConfig{
					Name:      d.CASecret,
					SdsConfig: AdsConfigSource(),
				},
			},
		}
	} else {
		verify.TrustedCa = &corev3.DataSource{Specifier: &corev3.DataSource_Filename{Filename: opts.SystemCAFile}}
		common.ValidationContextType = &tlsv3.CommonTlsContext_ValidationContext{ValidationContext: verify}
	}
	cl := egressDNSCluster(EgressClusterName(d), d)
	cl.TransportSocket = &corev3.TransportSocket{
		Name: wellknown.TransportSocketTLS,
		ConfigType: &corev3.TransportSocket_TypedConfig{
			TypedConfig: mustAny(&tlsv3.UpstreamTlsContext{Sni: d.Host, CommonTlsContext: common}),
		},
	}
	return cl
}
