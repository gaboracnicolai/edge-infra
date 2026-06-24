package builders

import (
	"slices"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	ratelimitfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ratelimit/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	"github.com/edge-infra/control-plane/internal/store"
)

func enabledRLS() RateLimitServiceOptions {
	return RateLimitServiceOptions{Enabled: true, Address: "ratelimit.infra.svc.cluster.local", Port: 8082, Domain: "edge"}
}

func TestBuildListeners_RateLimitService_FailOpenAndOrdered(t *testing.T) {
	rl := RateLimitOptions{Enabled: true, MaxTokens: 10, TokensPerFill: 10, FillInterval: time.Second}
	ea := ExtAuthzOptions{Enabled: true, Address: "auth-service", Port: 50051}
	hcm := hcmFromListener(t, BuildListeners([]store.Gateway{sampleGateway()}, rl, ea, enabledRLS())[0])

	// Order: local_ratelimit → ext_authz → ratelimit → router.
	got := filterNames(hcm)
	want := []string{localRateLimitFilterName, extAuthzFilterName, rateLimitFilterName, wellknown.Router}
	if !slices.Equal(got, want) {
		t.Fatalf("filters = %v; want %v", got, want)
	}

	var cfg ratelimitfilterv3.RateLimit
	if err := hcm.HttpFilters[2].GetTypedConfig().UnmarshalTo(&cfg); err != nil {
		t.Fatalf("unmarshal ratelimit: %v", err)
	}
	// FAIL-OPEN: a limiter problem must never block traffic.
	if cfg.GetFailureModeDeny() {
		t.Error("failure_mode_deny must be false (fail open) for the rate limiter")
	}
	if cfg.GetDomain() != "edge" {
		t.Errorf("domain = %q; want edge", cfg.GetDomain())
	}
	if got := cfg.GetRateLimitService().GetGrpcService().GetEnvoyGrpc().GetClusterName(); got != rlsClusterName {
		t.Errorf("ratelimit grpc cluster = %q; want %q", got, rlsClusterName)
	}
}

func TestBuildListeners_RateLimitServiceDisabled_NoFilter(t *testing.T) {
	hcm := hcmFromListener(t, BuildListeners([]store.Gateway{sampleGateway()}, RateLimitOptions{}, ExtAuthzOptions{}, RateLimitServiceOptions{Enabled: false})[0])
	if slices.Contains(filterNames(hcm), rateLimitFilterName) {
		t.Fatal("global ratelimit filter must not be emitted when disabled")
	}
}

func TestBuildClusters_RateLimitService_ClusterEmitted(t *testing.T) {
	var found *clusterv3.Cluster
	for _, r := range BuildClusters(nil, ExtAuthzOptions{}, enabledRLS()) {
		if c, ok := r.(*clusterv3.Cluster); ok && c.Name == rlsClusterName {
			found = c
		}
	}
	if found == nil {
		t.Fatal("ratelimit cluster must be emitted when the RLS is enabled")
	}
	if _, ok := found.GetTypedExtensionProtocolOptions()["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"]; !ok {
		t.Error("ratelimit cluster missing HTTP/2 protocol options (required for gRPC)")
	}
}

func TestBuildRouteConfigs_RateLimitService_DescriptorsOnVHost(t *testing.T) {
	res := BuildRouteConfigs([]store.Gateway{sampleGateway()}, nil, enabledRLS())
	rc, ok := res[0].(*routev3.RouteConfiguration)
	if !ok || len(rc.GetVirtualHosts()) == 0 {
		t.Fatalf("expected a route configuration with a virtual host")
	}
	if len(rc.GetVirtualHosts()[0].GetRateLimits()) == 0 {
		t.Fatal("virtual host must carry rate_limit descriptors (x-user-id / remote_address) when the RLS is enabled")
	}
}
