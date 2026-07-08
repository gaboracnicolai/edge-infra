package builders

import (
	"testing"
	"time"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	lrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/edge-infra/control-plane/internal/store"
)

const extAuthzFilterNameForTest = "envoy.filters.http.ext_authz"

// extAuthzPerRoute returns the per-route ext_authz override on a built route, if
// present (present == the route opted OUT of auth via auth_policy=none).
func extAuthzPerRoute(t *testing.T, r *routev3.Route) (*extauthzv3.ExtAuthzPerRoute, bool) {
	t.Helper()
	cfg, ok := r.GetTypedPerFilterConfig()[extAuthzFilterNameForTest]
	if !ok {
		return nil, false
	}
	var pr extauthzv3.ExtAuthzPerRoute
	if err := cfg.UnmarshalTo(&pr); err != nil {
		t.Fatalf("unmarshal ExtAuthzPerRoute: %v", err)
	}
	return &pr, true
}

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

// ---- R4 Stage 3a-ii: per-service auth_policy (jwt/none) --------------------

// THE SAFETY TEST (lead): an unspecified/default/unknown auth_policy must NEVER
// disable auth — only the exact literal "none" opts a route out. jwt, "", and a
// typo all leave ext_authz to apply (authenticated under ea.Enabled).
func TestBuildRouteConfigs_DefaultAuthenticated(t *testing.T) {
	gw := sharedGateway()
	for _, ap := range []string{"jwt", "", "bogus"} {
		route := store.Route{
			Name: "r-" + ap, GatewayID: "shared", ClusterName: "c", PathPrefix: "/", AuthPolicy: ap,
		}
		res := BuildRouteConfigs([]store.Gateway{gw}, []store.Route{route}, RateLimitServiceOptions{})
		if _, optedOut := extAuthzPerRoute(t, findRoute(t, res[0], "r-"+ap)); optedOut {
			t.Errorf("auth_policy=%q must NOT add an ext_authz override (stays authenticated)", ap)
		}
	}
	// Only "none" opts out.
	route := store.Route{Name: "r-none", GatewayID: "shared", ClusterName: "c", PathPrefix: "/", AuthPolicy: "none"}
	res := BuildRouteConfigs([]store.Gateway{gw}, []store.Route{route}, RateLimitServiceOptions{})
	if _, optedOut := extAuthzPerRoute(t, findRoute(t, res[0], "r-none")); !optedOut {
		t.Error("auth_policy=none must add an ext_authz disable override")
	}
}

// auth_policy=none renders as the EXACT ExtAuthzPerRoute{Disabled:true} (not an
// encoding Envoy would silently ignore).
func TestBuildRouteConfigs_AuthNone_DisablesExtAuthz(t *testing.T) {
	gw := sharedGateway()
	route := store.Route{Name: "public", GatewayID: "shared", ClusterName: "c", PathPrefix: "/", AuthPolicy: "none"}
	res := BuildRouteConfigs([]store.Gateway{gw}, []store.Route{route}, RateLimitServiceOptions{})
	pr, ok := extAuthzPerRoute(t, findRoute(t, res[0], "public"))
	if !ok {
		t.Fatal("expected an ext_authz per-route override for auth_policy=none")
	}
	if !pr.GetDisabled() {
		t.Error("ExtAuthzPerRoute.Disabled must be true for auth_policy=none")
	}
}

// A route with BOTH a rate_limit and auth_policy=none carries both overrides —
// the TypedPerFilterConfig map is never clobbered.
func TestBuildRouteConfigs_RateLimitAndAuthCoexist(t *testing.T) {
	gw := sharedGateway()
	route := store.Route{
		Name: "both", GatewayID: "shared", ClusterName: "c", PathPrefix: "/",
		RateLimitPerUnit: 100, RateLimitUnit: "SECOND", AuthPolicy: "none",
	}
	res := BuildRouteConfigs([]store.Gateway{gw}, []store.Route{route}, RateLimitServiceOptions{})
	tpfc := findRoute(t, res[0], "both").GetTypedPerFilterConfig()
	if _, ok := tpfc[localRateLimitFilterName]; !ok {
		t.Error("rate_limit override missing — map clobbered")
	}
	if _, ok := tpfc[extAuthzFilterNameForTest]; !ok {
		t.Error("ext_authz disable missing — map clobbered")
	}
}

// ---- R4 Stage 3b-mtls Slice 2: mtls composition ---------------------------

// COMPOSITION: an mtls route disables ext_authz (the client cert is the auth;
// don't also demand a JWT), reusing the 3a-ii mechanism.
func TestBuildRouteConfigs_MTLS_DisablesExtAuthz(t *testing.T) {
	gw := sharedGateway()
	route := store.Route{Name: "osb-mtls", GatewayID: "shared", ClusterName: "c", PathPrefix: "/", AuthPolicy: "mtls"}
	res := BuildRouteConfigs([]store.Gateway{gw}, []store.Route{route}, RateLimitServiceOptions{})
	pr, ok := extAuthzPerRoute(t, findRoute(t, res[0], "osb-mtls"))
	if !ok {
		t.Fatal("mtls route must disable ext_authz (client cert is the auth)")
	}
	if !pr.GetDisabled() {
		t.Error("ExtAuthzPerRoute.Disabled must be true for mtls")
	}
}

// mtls + rate_limit on one route → BOTH overrides render (map not clobbered).
func TestBuildRouteConfigs_MTLSAndRateLimit_Coexist(t *testing.T) {
	gw := sharedGateway()
	route := store.Route{
		Name: "osb-both", GatewayID: "shared", ClusterName: "c", PathPrefix: "/",
		AuthPolicy: "mtls", RateLimitPerUnit: 50, RateLimitUnit: "SECOND",
	}
	res := BuildRouteConfigs([]store.Gateway{gw}, []store.Route{route}, RateLimitServiceOptions{})
	tpfc := findRoute(t, res[0], "osb-both").GetTypedPerFilterConfig()
	if _, ok := tpfc[localRateLimitFilterName]; !ok {
		t.Error("rate_limit override missing — map clobbered")
	}
	if _, ok := tpfc[extAuthzFilterNameForTest]; !ok {
		t.Error("ext_authz disable missing for mtls — map clobbered")
	}
}

// ---- R4 Stage 3b-mtls: jwt_or_mtls ext_authz composition ------------------

// jwt_or_mtls keeps ext_authz ENABLED (the JWT fallback runs there) and carries
// an auth_policy context extension so auth.rs can allow a valid client cert.
func TestBuildRouteConfigs_JwtOrMtls_ExtAuthzEnabledWithContext(t *testing.T) {
	gw := sharedGateway()
	route := store.Route{Name: "osb-j", GatewayID: "shared", ClusterName: "c", PathPrefix: "/", AuthPolicy: "jwt_or_mtls"}
	res := BuildRouteConfigs([]store.Gateway{gw}, []store.Route{route}, RateLimitServiceOptions{})
	pr, ok := extAuthzPerRoute(t, findRoute(t, res[0], "osb-j"))
	if !ok {
		t.Fatal("jwt_or_mtls must set an ext_authz per-route CheckSettings override")
	}
	if pr.GetDisabled() {
		t.Error("jwt_or_mtls must NOT disable ext_authz (the JWT fallback runs there)")
	}
	if got := pr.GetCheckSettings().GetContextExtensions()["auth_policy"]; got != "jwt_or_mtls" {
		t.Errorf("context_extensions[auth_policy] = %q; want jwt_or_mtls", got)
	}
}
