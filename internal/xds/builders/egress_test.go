package builders

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/store"
)

var mockLLM = store.EgressDestination{ID: "d1", Name: "mock-llm", Host: "llm.mock.test", Port: 443, CASecret: "mock-ca"}

// A listed host is reachable two ways — proxied HTTP onto the TLS cluster, and
// CONNECT host:port onto the tunnel — and every other host gets 403.
func TestBuildEgress_OnlyListedHostsAreRouted(t *testing.T) {
	res := BuildEgress([]store.EgressDestination{mockLLM}, nil, EgressOptions{Port: 3128}, TelemetryOptions{})
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
	res := BuildEgress([]store.EgressDestination{mockLLM}, secrets, EgressOptions{Port: 3128}, TelemetryOptions{})
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
