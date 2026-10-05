package builders

import (
	"strconv"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	dnscommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/common/dns/v3"
	dnsclusterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dns/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/durationpb"

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

	// defaultEgressConnectTimeout applies to a destination row with none.
	defaultEgressConnectTimeout = 5 * time.Second
)

// EgressOptions configures the edge-egress listener.
type EgressOptions struct {
	Port         uint32 // the agents' proxy port
	SystemCAFile string // trust store for a destination with no CA secret
}

// EgressClusterName is the cluster that originates TLS to d's host.
func EgressClusterName(d store.EgressDestination) string { return "egress_" + d.Name }

// EgressTunnelClusterName is the raw-TCP cluster CONNECT tunnels to d's host use.
func EgressTunnelClusterName(d store.EgressDestination) string {
	return "egress_" + d.Name + "_tunnel"
}

// BuildEgress renders everything an edge-egress Envoy holds: its listener, the
// allow-list route config, two DNS clusters per destination, the telemetry
// cluster when telemetry is on, and the CA bundles the destinations name. Only
// validation_context secrets are included — never a private key — so a name
// that resolves to anything else leaves that upstream unverifiable, and closed.
func BuildEgress(dests []store.EgressDestination, secrets []store.Secret, opts EgressOptions, tel TelemetryOptions) map[resourcev3.Type][]types.Resource {
	clusters := make([]types.Resource, 0, 2*len(dests)+1)
	cas := map[string]bool{}
	for _, d := range dests {
		clusters = append(clusters, egressTLSCluster(d, opts), egressTunnelCluster(d))
		if d.CASecret != "" {
			cas[d.CASecret] = true
		}
	}
	clusters = append(clusters, TelemetryClusters(tel)...)

	var bundles []store.Secret
	for _, s := range secrets {
		if cas[s.Name] && s.Kind == "validation_context" {
			bundles = append(bundles, s)
		}
	}

	return map[resourcev3.Type][]types.Resource{
		resourcev3.ListenerType: {egressListener(opts, tel)},
		resourcev3.RouteType:    {egressRouteConfig(dests)},
		resourcev3.ClusterType:  clusters,
		resourcev3.SecretType:   BuildSecrets(bundles),
	}
}

func egressListener(opts EgressOptions, tel TelemetryOptions) *listenerv3.Listener {
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
		HttpFilters: []*hcmv3.HttpFilter{{
			Name: wellknown.Router,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{
				// No x-envoy-* headers on requests that leave the cluster.
				TypedConfig: mustAny(&routerv3.Router{SuppressEnvoyHeaders: true}),
			},
		}},
	}
	observeConnectionManager(hcm, EgressListenerName, tel)
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

// egressRouteConfig has one virtual host per destination — its bare host for
// proxied HTTP, host:port for CONNECT — and a catch-all that refuses the rest.
// A CONNECT request matches only a connect_matcher route, so each host carries
// one of each.
func egressRouteConfig(dests []store.EgressDestination) *routev3.RouteConfiguration {
	vhs := make([]*routev3.VirtualHost, 0, len(dests)+1)
	for _, d := range dests {
		vhs = append(vhs, &routev3.VirtualHost{
			Name:    "egress_" + d.Name,
			Domains: []string{d.Host, d.Host + ":" + strconv.FormatUint(uint64(d.Port), 10)},
			Routes: []*routev3.Route{
				{
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
				},
				{
					Name:  d.Name,
					Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
					Action: &routev3.Route_Route{Route: &routev3.RouteAction{
						ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: EgressClusterName(d)},
						// Model calls stream for minutes; the stream idle timeout still
						// reaps one that stalls.
						Timeout: durationpb.New(0),
					}},
				},
			},
		})
	}
	deny := &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{
		Status: 403,
		Body:   &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: egressDeniedBody}},
	}}
	vhs = append(vhs, &routev3.VirtualHost{
		Name:    "egress_denied",
		Domains: []string{"*"},
		Routes: []*routev3.Route{
			{Name: "denied_connect", Match: connectMatch(), Action: deny},
			{Name: "denied", Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}}, Action: deny},
		},
	})
	return &routev3.RouteConfiguration{Name: EgressRouteConfigName, VirtualHosts: vhs}
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
