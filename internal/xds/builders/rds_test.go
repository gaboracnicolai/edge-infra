package builders

import (
	"testing"
	"time"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	lrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/edge-infra/control-plane/internal/store"
)

func sharedGateway() store.Gateway {
	return store.Gateway{ID: "shared", Name: "osb-shared-http", Port: 80, Protocol: "HTTP"}
}

func findRoute(t *testing.T, res any, name string) *routev3.Route {
	t.Helper()
	rc, ok := res.(*routev3.RouteConfiguration)
	if !ok {
		t.Fatalf("resource is not a RouteConfiguration: %T", res)
	}
	for _, vh := range rc.GetVirtualHosts() {
		for _, r := range vh.GetRoutes() {
			if r.GetName() == name {
				return r
			}
		}
	}
	t.Fatalf("route %q not found in %s", name, rc.GetName())
	return nil
}

// A per-service rate_limit renders as a per-route local_ratelimit override with
// a token bucket derived from (requests_per_unit, unit).
func TestBuildRouteConfigs_PerServiceRateLimit_Override(t *testing.T) {
	gw := sharedGateway()
	route := store.Route{
		Name: "osb-team-svc", GatewayID: "shared", ClusterName: "osb-team-svc",
		Hosts: []string{"svc.example"}, PathPrefix: "/",
		RateLimitPerUnit: 100, RateLimitUnit: "SECOND",
	}
	res := BuildRouteConfigs([]store.Gateway{gw}, []store.Route{route}, RateLimitServiceOptions{})
	r := findRoute(t, res[0], "osb-team-svc")

	tpfc := r.GetTypedPerFilterConfig()[localRateLimitFilterName]
	if tpfc == nil {
		t.Fatal("expected per-route local_ratelimit typed_per_filter_config; got none")
	}
	var cfg lrlv3.LocalRateLimit
	if err := tpfc.UnmarshalTo(&cfg); err != nil {
		t.Fatalf("unmarshal per-route local_ratelimit: %v", err)
	}
	if got := cfg.GetTokenBucket().GetMaxTokens(); got != 100 {
		t.Errorf("max_tokens = %d; want 100", got)
	}
	if got := cfg.GetTokenBucket().GetTokensPerFill().GetValue(); got != 100 {
		t.Errorf("tokens_per_fill = %d; want 100", got)
	}
	if got := cfg.GetTokenBucket().GetFillInterval().AsDuration(); got != time.Second {
		t.Errorf("fill_interval = %s; want 1s", got)
	}
	if got := cfg.GetStatus().GetCode(); got != typev3.StatusCode_TooManyRequests {
		t.Errorf("status = %v; want 429", got)
	}
	if got := cfg.GetFilterEnabled().GetDefaultValue().GetNumerator(); got != 100 {
		t.Errorf("filter_enabled numerator = %d; want 100", got)
	}
	if got := cfg.GetFilterEnforced().GetDefaultValue().GetNumerator(); got != 100 {
		t.Errorf("filter_enforced numerator = %d; want 100", got)
	}
}

// unit=MINUTE → a 60s fill interval.
func TestBuildRouteConfigs_RateLimitUnitMinute(t *testing.T) {
	gw := sharedGateway()
	route := store.Route{
		Name: "osb-team-min", GatewayID: "shared", ClusterName: "osb-team-min",
		PathPrefix: "/", RateLimitPerUnit: 30, RateLimitUnit: "MINUTE",
	}
	res := BuildRouteConfigs([]store.Gateway{gw}, []store.Route{route}, RateLimitServiceOptions{})
	r := findRoute(t, res[0], "osb-team-min")
	var cfg lrlv3.LocalRateLimit
	if err := r.GetTypedPerFilterConfig()[localRateLimitFilterName].UnmarshalTo(&cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := cfg.GetTokenBucket().GetFillInterval().AsDuration(); got != time.Minute {
		t.Errorf("fill_interval = %s; want 1m", got)
	}
	if got := cfg.GetTokenBucket().GetMaxTokens(); got != 30 {
		t.Errorf("max_tokens = %d; want 30", got)
	}
}

// A route with no per-service limit carries no override (controller rows render unchanged).
func TestBuildRouteConfigs_NoRateLimit_NoOverride(t *testing.T) {
	gw := sharedGateway()
	route := store.Route{
		Name: "plain", GatewayID: "shared", ClusterName: "c", PathPrefix: "/",
	}
	res := BuildRouteConfigs([]store.Gateway{gw}, []store.Route{route}, RateLimitServiceOptions{})
	r := findRoute(t, res[0], "plain")
	if r.GetTypedPerFilterConfig()[localRateLimitFilterName] != nil {
		t.Error("route without a per-service limit must not carry a local_ratelimit override")
	}
}
