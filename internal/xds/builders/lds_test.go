package builders

import (
	"slices"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	lrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	"github.com/edge-infra/control-plane/internal/store"
)

func hcmFromListener(t *testing.T, res any) *hcmv3.HttpConnectionManager {
	t.Helper()
	l, ok := res.(*listenerv3.Listener)
	if !ok {
		t.Fatalf("resource is not a Listener: %T", res)
	}
	if len(l.FilterChains) != 1 || len(l.FilterChains[0].Filters) != 1 {
		t.Fatalf("unexpected filter chain shape: %+v", l.FilterChains)
	}
	var hcm hcmv3.HttpConnectionManager
	if err := l.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(&hcm); err != nil {
		t.Fatalf("unmarshal hcm: %v", err)
	}
	return &hcm
}

func filterNames(hcm *hcmv3.HttpConnectionManager) []string {
	names := make([]string, 0, len(hcm.HttpFilters))
	for _, f := range hcm.HttpFilters {
		names = append(names, f.Name)
	}
	return names
}

func sampleGateway() store.Gateway {
	return store.Gateway{Name: "gw", Port: 80, Protocol: "HTTP"}
}

func TestBuildListeners_RateLimitDisabled_RouterOnly(t *testing.T) {
	res := BuildListeners([]store.Gateway{sampleGateway()}, nil, RateLimitOptions{Enabled: false}, ExtAuthzOptions{}, RateLimitServiceOptions{})
	got := filterNames(hcmFromListener(t, res[0]))
	if len(got) != 1 || got[0] != wellknown.Router {
		t.Fatalf("filters = %v; want [%s]", got, wellknown.Router)
	}
}

func TestBuildListeners_RateLimitEnabled_FilterPresentAndOrdered(t *testing.T) {
	rl := RateLimitOptions{Enabled: true, MaxTokens: 200, TokensPerFill: 100, FillInterval: time.Second}
	hcm := hcmFromListener(t, BuildListeners([]store.Gateway{sampleGateway()}, nil, rl, ExtAuthzOptions{}, RateLimitServiceOptions{})[0])

	// local_ratelimit must precede the router (router is always last).
	got := filterNames(hcm)
	if len(got) != 2 || got[0] != localRateLimitFilterName || got[len(got)-1] != wellknown.Router {
		t.Fatalf("filters = %v; want [%s, %s]", got, localRateLimitFilterName, wellknown.Router)
	}

	var cfg lrlv3.LocalRateLimit
	if err := hcm.HttpFilters[0].GetTypedConfig().UnmarshalTo(&cfg); err != nil {
		t.Fatalf("unmarshal local_ratelimit: %v", err)
	}
	if cfg.GetTokenBucket().GetMaxTokens() != 200 {
		t.Errorf("max_tokens = %d; want 200", cfg.GetTokenBucket().GetMaxTokens())
	}
	if cfg.GetTokenBucket().GetTokensPerFill().GetValue() != 100 {
		t.Errorf("tokens_per_fill = %d; want 100", cfg.GetTokenBucket().GetTokensPerFill().GetValue())
	}
	if cfg.GetStatus().GetCode() != typev3.StatusCode_TooManyRequests {
		t.Errorf("status = %v; want TooManyRequests (429)", cfg.GetStatus().GetCode())
	}
	// Enforced at 100% so it actually blocks, not shadow mode.
	if cfg.GetFilterEnforced().GetDefaultValue().GetNumerator() != 100 {
		t.Errorf("filter_enforced numerator = %d; want 100", cfg.GetFilterEnforced().GetDefaultValue().GetNumerator())
	}
	hasRetryAfter := false
	for _, h := range cfg.GetResponseHeadersToAdd() {
		if h.GetHeader().GetKey() == "Retry-After" {
			hasRetryAfter = true
		}
	}
	if !hasRetryAfter {
		t.Error("missing Retry-After response header")
	}
}

func rateLimitedRoute() store.Route {
	return store.Route{
		Name: "osb-team-svc", GatewayID: "shared", ClusterName: "osb-team-svc",
		PathPrefix: "/", RateLimitPerUnit: 100, RateLimitUnit: "SECOND",
	}
}

// THE PRESENCE GUARD: with the global throttle OFF, a route that carries a
// per-service rate_limit must STILL get the base local_ratelimit filter in the
// HCM chain — otherwise the per-route override is inert and the limit silently
// no-ops.
func TestBuildListeners_PerServiceRateLimit_PresenceGuard(t *testing.T) {
	gw := sharedGateway()
	hcm := hcmFromListener(t, BuildListeners(
		[]store.Gateway{gw}, []store.Route{rateLimitedRoute()},
		RateLimitOptions{Enabled: false}, ExtAuthzOptions{}, RateLimitServiceOptions{},
	)[0])
	if !slices.Contains(filterNames(hcm), localRateLimitFilterName) {
		t.Fatalf("rl.Enabled=false but a route needs a per-service limit: base local_ratelimit "+
			"filter MUST be emitted so the override applies; filters = %v", filterNames(hcm))
	}
}

// The inverse: no per-service limits + global throttle off → no needless filter.
func TestBuildListeners_NoPerServiceRateLimit_Disabled_NoFilter(t *testing.T) {
	gw := sharedGateway()
	plain := store.Route{Name: "plain", GatewayID: "shared", ClusterName: "c", PathPrefix: "/"}
	hcm := hcmFromListener(t, BuildListeners(
		[]store.Gateway{gw}, []store.Route{plain},
		RateLimitOptions{Enabled: false}, ExtAuthzOptions{}, RateLimitServiceOptions{},
	)[0])
	if slices.Contains(filterNames(hcm), localRateLimitFilterName) {
		t.Errorf("no per-service limits + rl disabled: local_ratelimit filter should be absent; filters = %v", filterNames(hcm))
	}
}
