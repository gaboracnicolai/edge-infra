package xds

import (
	"context"
	"strings"
	"testing"

	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds/builders"
)

// extAuthzOn isolates the NEW guard from the pre-existing CFG-1 one. Without it
// AnyRouteWantsAuth fires first (an mtls route is != "none", so it counts as
// wanting auth) and the test would pass on the wrong refusal — green for a
// reason that has nothing to do with the client CA.
func extAuthzOn(r *Reconciler) *Reconciler {
	r.WithExtAuthz(builders.ExtAuthzOptions{Enabled: true, Address: "auth-service", Port: 9000})
	return r
}

// The reconciler must REFUSE a snapshot containing an mtls route with no client
// CA, exactly as it refuses when a route wants auth while ext_authz is off
// (reconciler.go:261). Fail-static: last-good stays, nothing open is published.
//
// This is the LAST LINE. Migration 0008 makes the row unrepresentable at rest,
// but the renderer must hold regardless of how a row arrived — a pre-constraint
// row, a restored dump, or a writer that does not exist yet.
func TestReconcile_RefusesMTLSRouteWithNoClientCA(t *testing.T) {
	snap := sampleSnapshot()
	snap.Routes = append(snap.Routes, store.Route{
		Name: "open-mtls", GatewayID: snap.Gateways[0].ID, ClusterName: snap.Clusters[0].Name,
		PathPrefix: "/x", TLSSecret: "tls-s", AuthPolicy: "mtls", // ClientCASecret deliberately empty
	})

	r := extAuthzOn(NewReconciler(newCache(), &fakeStore{snap: snap}, testNodeID, discardLogger()))
	err := r.Reconcile(context.Background())
	if err == nil {
		t.Fatal("reconcile ACCEPTED an mtls route with no client CA — that renders a listener " +
			"with no cert verification (lds.go emits none without a CA name) and no ext_authz " +
			"(rds.go disables it for mtls): an open route reaching a proxy")
	}
	low := strings.ToLower(err.Error())
	for _, want := range []string{"mtls", "client"} {
		if !strings.Contains(low, want) {
			t.Errorf("the refusal must say WHICH defect it caught; %q missing %q", err.Error(), want)
		}
	}
}

// The refusal must not fire on the safe shapes, or it is an outage rather than a
// guard. A correctly-configured mtls route still publishes.
func TestReconcile_AcceptsMTLSRouteWithAClientCA(t *testing.T) {
	snap := sampleSnapshot()
	snap.Routes = append(snap.Routes, store.Route{
		Name: "good-mtls", GatewayID: snap.Gateways[0].ID, ClusterName: snap.Clusters[0].Name,
		PathPrefix: "/y", TLSSecret: "tls-s", ClientCASecret: "client-ca", AuthPolicy: "mtls",
	})
	r := extAuthzOn(NewReconciler(newCache(), &fakeStore{snap: snap}, testNodeID, discardLogger()))
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("a correctly-configured mtls route must publish: %v", err)
	}
}
