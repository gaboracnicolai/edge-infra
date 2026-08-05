package builders

import (
	"testing"

	"github.com/edge-infra/control-plane/internal/store"
)

// mtls_null_ca_test.go — an mtls route with no client CA must be UNRENDERABLE.
//
// THE HOLE. auth_policy='mtls' means "the client cert IS the auth", so rds.go
// sets ExtAuthzPerRoute{Disabled} — no JWT check, no auth-service call. The
// matching cert requirement is emitted by lds.go ONLY when the client-CA name is
// non-empty (downstreamTLS: `if clientCAName != ""`). A route carrying
// auth_policy='mtls' with a NULL/empty client_ca_secret_name therefore renders a
// listener with NO client-cert verification AND no ext_authz: an open route.
//
// Migration 0007 asserted the opposite — "a missing CA renders an unresolved SDS
// ref, so that SNI's mTLS handshake fails closed (never a bypass)". That is true
// when the NAME IS PRESENT and does not resolve to a secret. It is false when the
// name is absent, because then there is no SDS reference at all to be unresolved.
// The NULLABLE column is what creates exactly that case.
//
// NOT REACHABLE TODAY, verified rather than inherited: OSB rejects None, "" and
// whitespace for mtls (models.py `_transport_auth_requires_https` plus
// validate_secret_name), and the Go writer in internal/store/postgres.go never
// sets auth_policy or client_ca_secret_name at all, so its rows take the schema
// default 'jwt'. There is no third writer.
//
// A latent hole guarded only by "no current writer does that" is one new writer
// away from live, so this is closed in the renderer — the last line, which holds
// however the row got there — and at the schema (migration 0008).

func mtlsRoute(clientCA string) store.Route {
	return store.Route{
		Name: "svc-mtls", GatewayID: "gw", ClusterName: "c", PathPrefix: "/",
		TLSSecret: "tls-secret", ClientCASecret: clientCA, AuthPolicy: "mtls",
	}
}

// The predicate the reconciler gates on. Empty client CA on an mtls route is the
// unrenderable combination.
func TestAnyMTLSRouteMissingClientCA(t *testing.T) {
	cases := []struct {
		name  string
		route store.Route
		want  bool
	}{
		{"mtls with NULL/empty client CA is the hole", mtlsRoute(""), true},
		{"mtls with a client CA is fine", mtlsRoute("client-ca-secret"), false},
		{
			// The SDS ref is present but may not resolve — that IS the case migration
			// 0007's comment correctly describes, and it genuinely fails closed at the
			// handshake. Not our business to refuse it here.
			"mtls naming a CA that may not resolve is NOT this defect",
			mtlsRoute("ca-that-might-not-exist"), false,
		},
		{
			// jwt_or_mtls with no CA is SAFE and must not be refused: rds.go keeps
			// ext_authz ENABLED for it, so a cert-less caller simply falls through to
			// the JWT path. Refusing it would break a working configuration.
			"jwt_or_mtls with no client CA falls through to JWT — must NOT be refused",
			store.Route{Name: "j", GatewayID: "gw", ClusterName: "c", PathPrefix: "/",
				TLSSecret: "t", AuthPolicy: "jwt_or_mtls"},
			false,
		},
		{
			"a plain jwt route with no client CA is untouched",
			store.Route{Name: "p", GatewayID: "gw", ClusterName: "c", PathPrefix: "/", AuthPolicy: "jwt"},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AnyMTLSRouteMissingClientCA([]store.Route{tc.route}); got != tc.want {
				t.Errorf("AnyMTLSRouteMissingClientCA = %v, want %v", got, tc.want)
			}
		})
	}
}

// Whitespace is not a client CA. `validate_secret_name` rejects it upstream, but
// the renderer must not depend on an upstream in another language: a name of
// spaces would pass a naive `!= ""` check and then render an SDS ref that can
// never resolve, which is a different failure from the one the operator asked for.
func TestAnyMTLSRouteMissingClientCA_WhitespaceIsNotACA(t *testing.T) {
	if !AnyMTLSRouteMissingClientCA([]store.Route{mtlsRoute("   ")}) {
		t.Error("a whitespace-only client CA must count as missing")
	}
}

// The mixed-fleet case: one bad route poisons the snapshot rather than being
// silently dropped. Publishing the other routes and quietly omitting this one
// would be the same silent-degradation this whole change exists to stop.
func TestAnyMTLSRouteMissingClientCA_OneBadRouteInAFleet(t *testing.T) {
	routes := []store.Route{
		{Name: "ok1", GatewayID: "gw", ClusterName: "c", PathPrefix: "/a", AuthPolicy: "none"},
		{Name: "ok2", GatewayID: "gw", ClusterName: "c", PathPrefix: "/b", AuthPolicy: "jwt"},
		mtlsRoute(""),
	}
	if !AnyMTLSRouteMissingClientCA(routes) {
		t.Error("one mtls route with no client CA must be detected among healthy routes")
	}
}
