package builders

import (
	"slices"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	"github.com/edge-infra/control-plane/internal/store"
)

func TestBuildListeners_ExtAuthz_FailClosedAndOrdered(t *testing.T) {
	rl := RateLimitOptions{Enabled: true, MaxTokens: 10, TokensPerFill: 10, FillInterval: time.Second}
	ea := ExtAuthzOptions{Enabled: true, Address: "auth-service.infra.svc.cluster.local", Port: 50051}
	hcm := hcmFromListener(t, BuildListeners([]store.Gateway{sampleGateway()}, nil, rl, ea, RateLimitServiceOptions{})[0])

	// Order: local_ratelimit (pre-auth IP throttle) → ext_authz → router.
	got := filterNames(hcm)
	want := []string{localRateLimitFilterName, extAuthzFilterName, wellknown.Router}
	if !slices.Equal(got, want) {
		t.Fatalf("filters = %v; want %v", got, want)
	}

	var cfg extauthzv3.ExtAuthz
	if err := hcm.HttpFilters[1].GetTypedConfig().UnmarshalTo(&cfg); err != nil {
		t.Fatalf("unmarshal ext_authz: %v", err)
	}
	// THE non-negotiable: auth fails CLOSED. If the auth-service is unreachable
	// Envoy must deny, never allow.
	if cfg.GetFailureModeAllow() {
		t.Error("failure_mode_allow must be false (fail closed)")
	}
	if got := cfg.GetGrpcService().GetEnvoyGrpc().GetClusterName(); got != authServiceClusterName {
		t.Errorf("ext_authz grpc cluster = %q; want %q", got, authServiceClusterName)
	}
	if cfg.GetTransportApiVersion() != corev3.ApiVersion_V3 {
		t.Errorf("transport_api_version = %v; want V3", cfg.GetTransportApiVersion())
	}
}

func TestBuildListeners_ExtAuthzDisabled_NoFilter(t *testing.T) {
	hcm := hcmFromListener(t, BuildListeners([]store.Gateway{sampleGateway()}, nil, RateLimitOptions{}, ExtAuthzOptions{Enabled: false}, RateLimitServiceOptions{})[0])
	if slices.Contains(filterNames(hcm), extAuthzFilterName) {
		t.Fatal("ext_authz filter must not be emitted when disabled")
	}
}

func TestBuildClusters_ExtAuthz_AuthServiceClusterEmitted(t *testing.T) {
	ea := ExtAuthzOptions{Enabled: true, Address: "auth-service.infra.svc.cluster.local", Port: 50051}
	var found *clusterv3.Cluster
	for _, r := range BuildClusters(nil, ea, RateLimitServiceOptions{}) {
		if c, ok := r.(*clusterv3.Cluster); ok && c.Name == authServiceClusterName {
			found = c
		}
	}
	if found == nil {
		t.Fatal("auth_service cluster must be emitted when ext_authz is enabled")
	}
	// gRPC requires HTTP/2 upstream.
	if _, ok := found.GetTypedExtensionProtocolOptions()["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]; !ok {
		t.Error("auth_service cluster missing HTTP/2 protocol options (required for gRPC)")
	}
}

func TestBuildClusters_ExtAuthzDisabled_NoAuthServiceCluster(t *testing.T) {
	for _, r := range BuildClusters(nil, ExtAuthzOptions{Enabled: false}, RateLimitServiceOptions{}) {
		if c, ok := r.(*clusterv3.Cluster); ok && c.Name == authServiceClusterName {
			t.Fatal("auth_service cluster must not be emitted when disabled")
		}
	}
}

func authServiceClusterFrom(t *testing.T, ea ExtAuthzOptions) *clusterv3.Cluster {
	t.Helper()
	for _, r := range BuildClusters(nil, ea, RateLimitServiceOptions{}) {
		if c, ok := r.(*clusterv3.Cluster); ok && c.Name == authServiceClusterName {
			return c
		}
	}
	t.Fatal("auth_service cluster not emitted")
	return nil
}

// The ext_authz cutover: with the upstream CA + client cert/key set (mTLS to the
// auth-service, which requires client-cert verification), the auth_service cluster
// must carry a TLS transport socket that presents the client cert AND trusts the
// CA. This is what lets the gateway serve WITH authentication rather than fail the
// handshake (plaintext → deny-all).
func TestBuildClusters_ExtAuthz_MTLSTransportWhenCertsSet(t *testing.T) {
	ea := ExtAuthzOptions{
		Enabled:  true,
		Address:  "auth-service.infra.svc.cluster.local",
		Port:     50051,
		CAFile:   "/etc/authz-client-tls/ca.crt",
		CertFile: "/etc/authz-client-tls/tls.crt",
		KeyFile:  "/etc/authz-client-tls/tls.key",
	}
	c := authServiceClusterFrom(t, ea)
	if c.GetTransportSocket() == nil {
		t.Fatal("mTLS configured: auth_service cluster must have a TLS transport socket (else Envoy talks plaintext to a TLS auth-service and every request is denied)")
	}
	var ctx tlsv3.UpstreamTlsContext
	if err := c.GetTransportSocket().GetTypedConfig().UnmarshalTo(&ctx); err != nil {
		t.Fatalf("transport socket is not an UpstreamTlsContext: %v", err)
	}
	if ctx.GetCommonTlsContext().GetValidationContext().GetTrustedCa() == nil {
		t.Error("upstream TLS must trust the CA (verify the auth-service server cert)")
	}
	if len(ctx.GetCommonTlsContext().GetTlsCertificates()) == 0 {
		t.Error("mTLS: upstream must present a client certificate (auth-service requires client-cert verification)")
	}
}

// Adversarial: with no CA file the cluster stays PLAINTEXT (no transport socket).
// This is the pre-cutover state that would deny-all against a TLS auth-service —
// the reason enabling ext_authz without wiring the certs is unsafe.
func TestBuildClusters_ExtAuthz_PlaintextWhenNoCA(t *testing.T) {
	ea := ExtAuthzOptions{Enabled: true, Address: "auth-service.infra.svc.cluster.local", Port: 50051}
	c := authServiceClusterFrom(t, ea)
	if c.GetTransportSocket() != nil {
		t.Error("no CA file: cluster must be plaintext (no transport socket) — TLS only when CAFile is set")
	}
}
