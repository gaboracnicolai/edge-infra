package builders

import (
	"slices"
	"testing"
	"time"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	lrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	"github.com/edge-infra/control-plane/internal/store"
)

// chainCertName returns the SDS secret name the filter chain's downstream TLS
// references (empty when the chain has no TLS transport socket).
func chainCertName(t *testing.T, fc *listenerv3.FilterChain) string {
	t.Helper()
	if fc.GetTransportSocket() == nil {
		return ""
	}
	var ctx tlsv3.DownstreamTlsContext
	if err := fc.GetTransportSocket().GetTypedConfig().UnmarshalTo(&ctx); err != nil {
		t.Fatalf("unmarshal DownstreamTlsContext: %v", err)
	}
	sds := ctx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs()
	if len(sds) == 0 {
		return ""
	}
	return sds[0].GetName()
}

func listenerFrom(t *testing.T, res any) *listenerv3.Listener {
	t.Helper()
	l, ok := res.(*listenerv3.Listener)
	if !ok {
		t.Fatalf("resource is not a Listener: %T", res)
	}
	return l
}

// chainMTLS reports whether the chain's downstream TLS requires a client cert,
// and the SDS name of the validation_context (client-CA) it verifies against.
func chainMTLS(t *testing.T, fc *listenerv3.FilterChain) (requireClientCert bool, clientCAName string) {
	t.Helper()
	if fc.GetTransportSocket() == nil {
		return false, ""
	}
	var ctx tlsv3.DownstreamTlsContext
	if err := fc.GetTransportSocket().GetTypedConfig().UnmarshalTo(&ctx); err != nil {
		t.Fatalf("unmarshal DownstreamTlsContext: %v", err)
	}
	if sds := ctx.GetCommonTlsContext().GetValidationContextSdsSecretConfig(); sds != nil {
		clientCAName = sds.GetName()
	}
	return ctx.GetRequireClientCertificate().GetValue(), clientCAName
}

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

// ---- R4 Stage 3b-i: per-SNI HTTPS rendering --------------------------------

// THE LOAD-BEARING TEST: the shared HTTPS gateway presents the RIGHT cert per
// SNI host — two services get two filter chains, each matching its own host and
// referencing its own secret (certs never cross hosts).
func TestBuildListeners_PerSNI_CertPerHost(t *testing.T) {
	gw := store.Gateway{ID: "https", Name: "osb-shared-https", Port: 443, Protocol: "HTTPS"}
	routes := []store.Route{
		{Name: "osb-t-a", GatewayID: "https", ClusterName: "osb-t-a", Hosts: []string{"a.example.com"}, PathPrefix: "/", TLSSecret: "sec-a"},
		{Name: "osb-t-b", GatewayID: "https", ClusterName: "osb-t-b", Hosts: []string{"b.example.com"}, PathPrefix: "/", TLSSecret: "sec-b"},
	}
	l := listenerFrom(t, BuildListeners([]store.Gateway{gw}, routes, RateLimitOptions{}, ExtAuthzOptions{}, RateLimitServiceOptions{})[0])
	if len(l.FilterChains) != 2 {
		t.Fatalf("per-SNI: want 2 filter chains; got %d", len(l.FilterChains))
	}
	got := map[string]string{}
	for _, fc := range l.FilterChains {
		sn := fc.GetFilterChainMatch().GetServerNames()
		if len(sn) != 1 {
			t.Fatalf("each SNI chain must match exactly one host; got %v", sn)
		}
		got[sn[0]] = chainCertName(t, fc)
	}
	if got["a.example.com"] != "sec-a" {
		t.Errorf("host a.example.com cert = %q; want sec-a", got["a.example.com"])
	}
	if got["b.example.com"] != "sec-b" {
		t.Errorf("host b.example.com cert = %q; want sec-b", got["b.example.com"])
	}
}

// BACKWARD-COMPAT: a single-cert HTTPS gateway (g.TLSSecret set, no per-route
// secrets) renders exactly one filter chain with that cert and no SNI match.
func TestBuildListeners_SingleCertHTTPS_BackwardCompat(t *testing.T) {
	gw := store.Gateway{ID: "g", Name: "edge-https", Port: 8443, Protocol: "HTTPS", TLSSecret: "edge-cert"}
	routes := []store.Route{{Name: "r", GatewayID: "g", ClusterName: "c", Hosts: []string{"h"}, PathPrefix: "/"}}
	l := listenerFrom(t, BuildListeners([]store.Gateway{gw}, routes, RateLimitOptions{}, ExtAuthzOptions{}, RateLimitServiceOptions{})[0])
	if len(l.FilterChains) != 1 {
		t.Fatalf("single-cert HTTPS: want 1 chain; got %d", len(l.FilterChains))
	}
	if got := chainCertName(t, l.FilterChains[0]); got != "edge-cert" {
		t.Errorf("single-cert chain = %q; want edge-cert", got)
	}
	if fcm := l.FilterChains[0].GetFilterChainMatch(); fcm != nil && len(fcm.GetServerNames()) != 0 {
		t.Error("single-cert chain must not carry an SNI match (it serves all)")
	}
}

// HTTP gateway is unchanged: one plaintext chain, no TLS transport socket.
func TestBuildListeners_HTTP_NoTLS(t *testing.T) {
	gw := store.Gateway{ID: "g", Name: "osb-shared-http", Port: 80, Protocol: "HTTP"}
	routes := []store.Route{{Name: "r", GatewayID: "g", ClusterName: "c", Hosts: []string{"h"}, PathPrefix: "/"}}
	l := listenerFrom(t, BuildListeners([]store.Gateway{gw}, routes, RateLimitOptions{}, ExtAuthzOptions{}, RateLimitServiceOptions{})[0])
	if len(l.FilterChains) != 1 {
		t.Fatalf("HTTP: want 1 chain; got %d", len(l.FilterChains))
	}
	if l.FilterChains[0].GetTransportSocket() != nil {
		t.Error("HTTP chain must have no TLS transport socket")
	}
}

// ADVERSARIAL: two services declare the SAME SNI host with DIFFERENT certs (a
// misconfiguration). Resolution must be DETERMINISTIC — the smallest route name
// wins regardless of input order — one host → one chain → one cert.
func TestBuildListeners_PerSNI_SameHostConflict_Deterministic(t *testing.T) {
	gw := store.Gateway{ID: "https", Name: "osb-shared-https", Port: 443, Protocol: "HTTPS"}
	// Passed in REVERSE name order to prove the choice isn't iteration/chain order.
	routes := []store.Route{
		{Name: "osb-z", GatewayID: "https", ClusterName: "osb-z", Hosts: []string{"dup.example.com"}, PathPrefix: "/", TLSSecret: "cert-z"},
		{Name: "osb-a", GatewayID: "https", ClusterName: "osb-a", Hosts: []string{"dup.example.com"}, PathPrefix: "/", TLSSecret: "cert-a"},
	}
	l := listenerFrom(t, BuildListeners([]store.Gateway{gw}, routes, RateLimitOptions{}, ExtAuthzOptions{}, RateLimitServiceOptions{})[0])
	if len(l.FilterChains) != 1 {
		t.Fatalf("same host must collapse to one filter chain; got %d", len(l.FilterChains))
	}
	if got := chainCertName(t, l.FilterChains[0]); got != "cert-a" {
		t.Errorf("same-host conflict must deterministically pick smallest route name (cert-a); got %q", got)
	}
}

// ---- R4 Stage 3b-mtls Slice 2: per-service downstream mTLS ----------------

func mtlsGateway() store.Gateway {
	return store.Gateway{ID: "https", Name: "osb-shared-https", Port: 443, Protocol: "HTTPS"}
}

// THE HANDSHAKE TEST (load-bearing): a per-SNI chain for a route WITH a client_ca
// requires a client cert AND references that CA's validation_context via SDS — so
// Envoy fails the TLS handshake for a caller with no/invalid client cert.
func TestBuildListeners_MTLS_RequiresClientCert(t *testing.T) {
	route := store.Route{
		Name: "osb-a", GatewayID: "https", ClusterName: "osb-a", Hosts: []string{"a.example"},
		PathPrefix: "/", TLSSecret: "sec-a", ClientCASecret: "ca-a", AuthPolicy: "mtls",
	}
	l := listenerFrom(t, BuildListeners([]store.Gateway{mtlsGateway()}, []store.Route{route},
		RateLimitOptions{}, ExtAuthzOptions{}, RateLimitServiceOptions{})[0])
	req, caName := chainMTLS(t, l.FilterChains[0])
	if !req {
		t.Error("mtls route: require_client_certificate must be true")
	}
	if caName != "ca-a" {
		t.Errorf("validation_context SDS ref = %q; want ca-a", caName)
	}
	if chainCertName(t, l.FilterChains[0]) != "sec-a" {
		t.Error("the server cert must still be served alongside the client-CA")
	}
}

// A plain HTTPS route (no client_ca) is server-only — no client cert required.
func TestBuildListeners_NoMTLS_ServerOnly(t *testing.T) {
	route := store.Route{
		Name: "osb-b", GatewayID: "https", ClusterName: "osb-b", Hosts: []string{"b.example"},
		PathPrefix: "/", TLSSecret: "sec-b",
	}
	l := listenerFrom(t, BuildListeners([]store.Gateway{mtlsGateway()}, []store.Route{route},
		RateLimitOptions{}, ExtAuthzOptions{}, RateLimitServiceOptions{})[0])
	req, caName := chainMTLS(t, l.FilterChains[0])
	if req || caName != "" {
		t.Error("plain HTTPS route must NOT require a client cert or reference a client-CA")
	}
}

// PER-SNI ISOLATION: one service's mTLS requirement never leaks onto another
// service's SNI on the shared HTTPS listener.
func TestBuildListeners_MTLS_PerSNIIsolation(t *testing.T) {
	routes := []store.Route{
		{Name: "osb-a", GatewayID: "https", ClusterName: "osb-a", Hosts: []string{"a.example"}, PathPrefix: "/", TLSSecret: "sec-a", ClientCASecret: "ca-a", AuthPolicy: "mtls"},
		{Name: "osb-b", GatewayID: "https", ClusterName: "osb-b", Hosts: []string{"b.example"}, PathPrefix: "/", TLSSecret: "sec-b"},
	}
	l := listenerFrom(t, BuildListeners([]store.Gateway{mtlsGateway()}, routes,
		RateLimitOptions{}, ExtAuthzOptions{}, RateLimitServiceOptions{})[0])
	if len(l.FilterChains) != 2 {
		t.Fatalf("want 2 SNI chains; got %d", len(l.FilterChains))
	}
	requires := map[string]bool{}
	for _, fc := range l.FilterChains {
		req, _ := chainMTLS(t, fc)
		requires[fc.GetFilterChainMatch().GetServerNames()[0]] = req
	}
	if !requires["a.example"] {
		t.Error("service A (mtls) must require a client cert on its SNI")
	}
	if requires["b.example"] {
		t.Error("service B (plain HTTPS) must NOT require a client cert — no mtls leak across SNIs")
	}
}
