package builders

import (
	"slices"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	"github.com/edge-infra/control-plane/internal/store"
)

func TestBuildListeners_ExtAuthz_FailClosedAndOrdered(t *testing.T) {
	rl := RateLimitOptions{Enabled: true, MaxTokens: 10, TokensPerFill: 10, FillInterval: time.Second}
	ea := ExtAuthzOptions{Enabled: true, Address: "auth-service.infra.svc.cluster.local", Port: 50051}
	hcm := hcmFromListener(t, BuildListeners([]store.Gateway{sampleGateway()}, rl, ea)[0])

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
	hcm := hcmFromListener(t, BuildListeners([]store.Gateway{sampleGateway()}, RateLimitOptions{}, ExtAuthzOptions{Enabled: false})[0])
	if slices.Contains(filterNames(hcm), extAuthzFilterName) {
		t.Fatal("ext_authz filter must not be emitted when disabled")
	}
}

func TestBuildClusters_ExtAuthz_AuthServiceClusterEmitted(t *testing.T) {
	ea := ExtAuthzOptions{Enabled: true, Address: "auth-service.infra.svc.cluster.local", Port: 50051}
	var found *clusterv3.Cluster
	for _, r := range BuildClusters(nil, ea) {
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
	for _, r := range BuildClusters(nil, ExtAuthzOptions{Enabled: false}) {
		if c, ok := r.(*clusterv3.Cluster); ok && c.Name == authServiceClusterName {
			t.Fatal("auth_service cluster must not be emitted when disabled")
		}
	}
}
