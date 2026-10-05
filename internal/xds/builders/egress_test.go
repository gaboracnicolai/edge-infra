package builders

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	grpcalv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	streamv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	lrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/store"
)

var mockLLM = store.EgressDestination{ID: "d1", Name: "mock-llm", Host: "llm.mock.test", Port: 443, CASecret: "mock-ca"}

// A listed host is reachable two ways — proxied HTTP onto the TLS cluster, and
// CONNECT host:port onto the tunnel — and every other host gets 403.
func TestBuildEgress_OnlyListedHostsAreRouted(t *testing.T) {
	res := BuildEgress([]store.EgressDestination{mockLLM}, nil, EgressOptions{Port: 3128}, ExtAuthzOptions{}, TelemetryOptions{})
	rc := res[resourcev3.RouteType][0].(*routev3.RouteConfiguration)
	require.Len(t, rc.GetVirtualHosts(), 2)

	vh := rc.GetVirtualHosts()[0]
	assert.Equal(t, []string{"llm.mock.test", "llm.mock.test:443"}, vh.GetDomains())
	connect, plain := vh.GetRoutes()[0], vh.GetRoutes()[1]
	require.NotNil(t, connect.GetMatch().GetConnectMatcher())
	assert.Equal(t, "egress_mock-llm_tunnel", connect.GetRoute().GetCluster())
	require.Len(t, connect.GetRoute().GetUpgradeConfigs(), 1)
	assert.NotNil(t, connect.GetRoute().GetUpgradeConfigs()[0].GetConnectConfig(), "the CONNECT is terminated here")
	assert.Equal(t, "egress_mock-llm", plain.GetRoute().GetCluster())

	deny := rc.GetVirtualHosts()[1]
	assert.Equal(t, []string{"*"}, deny.GetDomains())
	require.Len(t, deny.GetRoutes(), 2)
	assert.NotNil(t, deny.GetRoutes()[0].GetMatch().GetConnectMatcher(), "an unlisted CONNECT is refused too")
	for _, r := range deny.GetRoutes() {
		assert.EqualValues(t, 403, r.GetDirectResponse().GetStatus())
	}
}

// The TLS cluster verifies the host's certificate (SNI and SAN are the host, the
// CA comes over SDS); the tunnel carries the agent's own TLS untouched; and the
// egress proxy is sent the CA bundle but never a private key.
func TestBuildEgress_UpstreamTLSVerifiesTheHost(t *testing.T) {
	secrets := []store.Secret{
		{Name: "mock-ca", Kind: "validation_context", CertPEM: "CA"},
		{Name: "gateway-cert", Kind: "tls_certificate", CertPEM: "C", KeyPEM: "KEY"},
	}
	res := BuildEgress([]store.EgressDestination{mockLLM}, secrets, EgressOptions{Port: 3128}, ExtAuthzOptions{}, TelemetryOptions{})
	require.Len(t, res[resourcev3.ClusterType], 2)

	tlsCl := res[resourcev3.ClusterType][0].(*clusterv3.Cluster)
	require.Equal(t, "egress_mock-llm", tlsCl.GetName())
	up := &tlsv3.UpstreamTlsContext{}
	require.NoError(t, tlsCl.GetTransportSocket().GetTypedConfig().UnmarshalTo(up))
	assert.Equal(t, "llm.mock.test", up.GetSni())
	combined := up.GetCommonTlsContext().GetCombinedValidationContext()
	require.NotNil(t, combined)
	assert.Equal(t, "mock-ca", combined.GetValidationContextSdsSecretConfig().GetName())
	sans := combined.GetDefaultValidationContext().GetMatchTypedSubjectAltNames()
	require.Len(t, sans, 1)
	assert.Equal(t, "llm.mock.test", sans[0].GetMatcher().GetExact())

	tunnel := res[resourcev3.ClusterType][1].(*clusterv3.Cluster)
	assert.Equal(t, "egress_mock-llm_tunnel", tunnel.GetName())
	assert.Nil(t, tunnel.GetTransportSocket())

	require.Len(t, res[resourcev3.SecretType], 1)
	assert.Equal(t, "mock-ca", res[resourcev3.SecretType][0].(*tlsv3.Secret).GetName())
}

// A keyless host (B28.224): its plain-HTTP route asks the auth-service in agent
// mode, its CONNECT is refused, and every other route skips ext_authz. With
// ext_authz off on the control plane the keyless host is closed, not open.
func TestBuildEgress_KeylessHostGoesThroughAgentAuthz(t *testing.T) {
	keyless := mockLLM
	keyless.Keyless = true
	other := store.EgressDestination{ID: "d2", Name: "other", Host: "other.test", Port: 443}
	ea := ExtAuthzOptions{Enabled: true, Address: "auth-service.infra.svc.cluster.local", Port: 50051}

	res := BuildEgress([]store.EgressDestination{keyless, other}, nil, EgressOptions{Port: 3128}, ea, TelemetryOptions{})
	l := res[resourcev3.ListenerType][0].(*listenerv3.Listener)
	hcm := &hcmv3.HttpConnectionManager{}
	require.NoError(t, l.GetFilterChains()[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(hcm))
	require.Len(t, hcm.GetHttpFilters(), 2)
	assert.Equal(t, extAuthzFilterName, hcm.GetHttpFilters()[0].GetName(), "ext_authz runs before the router")
	assert.Contains(t, clusterNames(res), authServiceClusterName)

	perRoute := func(r *routev3.Route) *extauthzv3.ExtAuthzPerRoute {
		pr := &extauthzv3.ExtAuthzPerRoute{}
		require.NoError(t, r.GetTypedPerFilterConfig()[extAuthzFilterName].UnmarshalTo(pr), r.GetName())
		return pr
	}
	rc := res[resourcev3.RouteType][0].(*routev3.RouteConfiguration)
	connect, plain := rc.GetVirtualHosts()[0].GetRoutes()[0], rc.GetVirtualHosts()[0].GetRoutes()[1]
	assert.EqualValues(t, 403, connect.GetDirectResponse().GetStatus(), "a tunnel would carry the agent's own key")
	assert.Equal(t, "egress_mock-llm", plain.GetRoute().GetCluster())
	assert.Equal(t, map[string]string{"auth_policy": "agent"}, perRoute(plain).GetCheckSettings().GetContextExtensions())
	for _, vh := range rc.GetVirtualHosts()[1:] {
		for _, r := range vh.GetRoutes() {
			assert.True(t, perRoute(r).GetDisabled(), "%s must not call the auth-service", r.GetName())
		}
	}

	closed := BuildEgress([]store.EgressDestination{keyless}, nil, EgressOptions{Port: 3128}, ExtAuthzOptions{}, TelemetryOptions{})
	rc = closed[resourcev3.RouteType][0].(*routev3.RouteConfiguration)
	assert.EqualValues(t, 503, rc.GetVirtualHosts()[0].GetRoutes()[1].GetDirectResponse().GetStatus())
	assert.NotContains(t, clusterNames(closed), authServiceClusterName)
}

// B28.228: each agent gets its own bucket — keyed on the ServiceAccount the
// auth-service put in ext_authz metadata, and on the client address — counted
// after ext_authz names the agent; the access log carries the agent; and every
// decision goes to the control plane's decision log over the xDS cluster.
func TestBuildEgress_AgentRateLimitAndDecisionLog(t *testing.T) {
	keyless := mockLLM
	keyless.Keyless = true
	ea := ExtAuthzOptions{Enabled: true, Address: "auth-service.infra.svc.cluster.local", Port: 50051}
	listenerHCM := func(opts EgressOptions) *hcmv3.HttpConnectionManager {
		res := BuildEgress([]store.EgressDestination{keyless}, nil, opts, ea, TelemetryOptions{})
		hcm := &hcmv3.HttpConnectionManager{}
		require.NoError(t, res[resourcev3.ListenerType][0].(*listenerv3.Listener).
			GetFilterChains()[0].GetFilters()[0].GetTypedConfig().UnmarshalTo(hcm))
		return hcm
	}

	hcm := listenerHCM(EgressOptions{Port: 3128, AgentRequestsPerMinute: 5, DecisionLog: true})
	var names []string
	for _, f := range hcm.GetHttpFilters() {
		names = append(names, f.GetName())
	}
	assert.Equal(t, []string{extAuthzFilterName, localRateLimitFilterName, "envoy.filters.http.router"}, names,
		"the limit is counted after ext_authz names the agent")
	assert.True(t, hcm.GetUseRemoteAddress().GetValue(), "the client is the connection's peer, not X-Forwarded-For")
	assert.True(t, hcm.GetSkipXffAppend(), "nothing about the agent is added on the way out")

	rl := &lrlv3.LocalRateLimit{}
	require.NoError(t, hcm.GetHttpFilters()[1].GetTypedConfig().UnmarshalTo(rl))
	assert.EqualValues(t, 429, rl.GetStatus().GetCode())
	assert.EqualValues(t, 5, rl.GetTokenBucket().GetMaxTokens())
	assert.Equal(t, int64(60), rl.GetTokenBucket().GetFillInterval().GetSeconds())
	agent := rl.GetRateLimits()[0].GetActions()[0].GetMetadata()
	assert.Equal(t, "agent", agent.GetDescriptorKey())
	assert.Equal(t, "envoy.filters.http.ext_authz", agent.GetMetadataKey().GetKey())
	assert.Equal(t, "agent", agent.GetMetadataKey().GetPath()[0].GetKey())
	assert.NotNil(t, rl.GetRateLimits()[1].GetActions()[0].GetRemoteAddress())
	require.Len(t, rl.GetDescriptors(), 2)
	for i, key := range []string{"agent", "remote_address"} {
		e := rl.GetDescriptors()[i].GetEntries()
		require.Len(t, e, 1)
		assert.Equal(t, key, e[0].GetKey())
		assert.Empty(t, e[0].GetValue(), "no value: a bucket for every %s", key)
		assert.EqualValues(t, 5, rl.GetDescriptors()[i].GetTokenBucket().GetMaxTokens())
	}

	require.Len(t, hcm.GetAccessLog(), 2)
	stdout := &streamv3.StdoutAccessLog{}
	require.NoError(t, hcm.GetAccessLog()[0].GetTypedConfig().UnmarshalTo(stdout))
	assert.Equal(t, "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:agent)%",
		stdout.GetLogFormat().GetJsonFormat().GetFields()["agent"].GetStringValue())
	als := &grpcalv3.HttpGrpcAccessLogConfig{}
	require.NoError(t, hcm.GetAccessLog()[1].GetTypedConfig().UnmarshalTo(als))
	assert.Equal(t, "edge-decisions", als.GetCommonConfig().GetLogName())
	assert.Equal(t, "xds_cluster", als.GetCommonConfig().GetGrpcService().GetEnvoyGrpc().GetClusterName())

	off := listenerHCM(EgressOptions{Port: 3128})
	assert.Len(t, off.GetHttpFilters(), 2, "no limit unless one is set")
	assert.Len(t, off.GetAccessLog(), 1, "no decision log unless it is on")
}

func clusterNames(res map[resourcev3.Type][]types.Resource) []string {
	var out []string
	for _, c := range res[resourcev3.ClusterType] {
		out = append(out, c.(*clusterv3.Cluster).GetName())
	}
	return out
}
