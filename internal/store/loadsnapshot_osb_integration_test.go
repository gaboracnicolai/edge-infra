//go:build integration

// Cross-language end-to-end test for the OSB -> data-plane translator (R4
// Stage 1). It drives the REAL Python translator (via osb/tools/provision.py,
// through worker.process_message) to provision an HTTP service, then asserts the
// Go reconciler's LoadSnapshot serves it as gateway + cluster + endpoint + route
// — and drops the route after deprovision. Skipped unless both env vars are set;
// the integration harness (make test-integration) supplies them.
//
//	TEST_DATABASE_URL — DSN of the shared Postgres (both schemas applied)
//	OSB_PROVISION     — command that runs provision.py, e.g. "/venv/bin/python /repo/osb/tools/provision.py"
package store_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"

	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds/builders"
)

func osbProvision(t *testing.T, dsn, provisionCmd, action, arg string) {
	t.Helper()
	fields := strings.Fields(provisionCmd)
	args := append(fields[1:], action, arg)
	cmd := exec.Command(fields[0], args...)
	cmd.Env = append(os.Environ(), "DATABASE_URL="+dsn)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("provision %s %q failed: %v\n%s", action, arg, err, out)
	}
}

func loadForTest(t *testing.T, dsn string) *store.Snapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := store.NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	snap, err := s.LoadSnapshot(ctx)
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	return snap
}

func hasGateway(s *store.Snapshot, name string) bool {
	for _, g := range s.Gateways {
		if g.Name == name {
			return true
		}
	}
	return false
}

func hasCluster(s *store.Snapshot, name string) bool {
	for _, c := range s.Clusters {
		if c.Name == name {
			return true
		}
	}
	return false
}

func hasRoute(s *store.Snapshot, name string) bool {
	for _, r := range s.Routes {
		if r.Name == name {
			return true
		}
	}
	return false
}

func endpointAddr(s *store.Snapshot, clusterID, addr string, port uint32) bool {
	for _, e := range s.Endpoints {
		if e.ClusterID == clusterID && e.Address == addr && e.Port == port {
			return true
		}
	}
	return false
}

func builtRouteHasLocalRateLimit(res []cachetypes.Resource, name string) bool {
	for _, r := range res {
		rc, ok := r.(*routev3.RouteConfiguration)
		if !ok {
			continue
		}
		for _, vh := range rc.GetVirtualHosts() {
			for _, rt := range vh.GetRoutes() {
				if rt.GetName() == name {
					_, has := rt.GetTypedPerFilterConfig()["envoy.filters.http.local_ratelimit"]
					return has
				}
			}
		}
	}
	return false
}

func builtClusterHasHealthCheck(res []cachetypes.Resource, name, path string) bool {
	for _, r := range res {
		c, ok := r.(*clusterv3.Cluster)
		if !ok || c.GetName() != name {
			continue
		}
		for _, hc := range c.GetHealthChecks() {
			if hc.GetHttpHealthCheck().GetPath() == path {
				return true
			}
		}
	}
	return false
}

// builtRouteExtAuthzDisabled reports whether the built route carries an
// ExtAuthzPerRoute{Disabled:true} override (i.e. auth_policy=none opted it out).
func builtRouteExtAuthzDisabled(res []cachetypes.Resource, name string) bool {
	for _, r := range res {
		rc, ok := r.(*routev3.RouteConfiguration)
		if !ok {
			continue
		}
		for _, vh := range rc.GetVirtualHosts() {
			for _, rt := range vh.GetRoutes() {
				if rt.GetName() != name {
					continue
				}
				cfg, has := rt.GetTypedPerFilterConfig()["envoy.filters.http.ext_authz"]
				if !has {
					return false
				}
				var pr extauthzv3.ExtAuthzPerRoute
				if cfg.UnmarshalTo(&pr) != nil {
					return false
				}
				return pr.GetDisabled()
			}
		}
	}
	return false
}

func TestLoadSnapshot_OSBEndToEnd(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	prov := os.Getenv("OSB_PROVISION")
	if dsn == "" || prov == "" {
		t.Skip("TEST_DATABASE_URL and OSB_PROVISION required (integration)")
	}

	const (
		specA    = `{"name":"e2esvc","team":"e2eteam","host":"10.9.9.9","port":8080,"protocol":"HTTP"}`
		specB    = `{"name":"e2esvc","team":"e2eteam2","host":"10.9.9.10","port":8080,"protocol":"HTTP"}`
		clusterA = "osb-e2eteam-e2esvc"
		clusterB = "osb-e2eteam2-e2esvc"
	)

	// Two teams register the SAME service name — both must surface as distinct
	// derived clusters/routes (R4 Stage 2 per-tenant isolation).
	osbProvision(t, dsn, prov, "create", specA)
	osbProvision(t, dsn, prov, "create", specB)
	snap := loadForTest(t, dsn)
	if !hasGateway(snap, "osb-shared-http") {
		t.Error("LoadSnapshot missing shared gateway osb-shared-http")
	}
	for _, c := range []string{clusterA, clusterB} {
		if !hasCluster(snap, c) {
			t.Errorf("LoadSnapshot missing derived cluster %s", c)
		}
		if !hasRoute(snap, c) {
			t.Errorf("LoadSnapshot missing derived route %s", c)
		}
	}
	if !endpointAddr(snap, clusterA, "10.9.9.9", 8080) {
		t.Errorf("LoadSnapshot missing endpoint for %s", clusterA)
	}
	if !endpointAddr(snap, clusterB, "10.9.9.10", 8080) {
		t.Errorf("LoadSnapshot missing endpoint for %s", clusterB)
	}

	// DELETE team A's service (team-threaded). B's identically-named service must
	// remain served — a tenant can only unwind its own rows.
	osbProvision(t, dsn, prov, "delete", `{"team":"e2eteam","name":"e2esvc"}`)
	snap2 := loadForTest(t, dsn)
	if hasRoute(snap2, clusterA) || hasCluster(snap2, clusterA) {
		t.Errorf("team A's %s still served after its own deprovision", clusterA)
	}
	if !hasRoute(snap2, clusterB) || !hasCluster(snap2, clusterB) {
		t.Errorf("team B's %s must remain served after team A deletes its own", clusterB)
	}
	if !hasGateway(snap2, "osb-shared-http") {
		t.Error("shared gateway must persist")
	}
}

// R4 Stage 3a-i: a service's rate_limit + health_check survive the Python write,
// load into the Go Snapshot's Route/Cluster, and render through the builders as a
// per-route local_ratelimit override + a per-cluster active HTTP health check.
func TestLoadSnapshot_OSBPerServicePolicy(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	prov := os.Getenv("OSB_PROVISION")
	if dsn == "" || prov == "" {
		t.Skip("TEST_DATABASE_URL and OSB_PROVISION required (integration)")
	}

	const spec = `{"name":"policed","team":"e2epol","host":"10.9.9.20","port":8080,"protocol":"HTTP",` +
		`"rate_limit":{"requests_per_unit":100,"unit":"SECOND"},` +
		`"health_check":{"path":"/healthz","interval_seconds":5}}`
	const derived = "osb-e2epol-policed"

	osbProvision(t, dsn, prov, "create", spec)
	snap := loadForTest(t, dsn)

	// (a) The loaded domain snapshot carries the policy fields.
	var route *store.Route
	for i := range snap.Routes {
		if snap.Routes[i].Name == derived {
			route = &snap.Routes[i]
		}
	}
	if route == nil {
		t.Fatalf("route %s not in snapshot", derived)
	}
	if route.RateLimitPerUnit != 100 || route.RateLimitUnit != "SECOND" {
		t.Errorf("route policy = (%d,%q); want (100, SECOND)", route.RateLimitPerUnit, route.RateLimitUnit)
	}
	var cluster *store.Cluster
	for i := range snap.Clusters {
		if snap.Clusters[i].Name == derived {
			cluster = &snap.Clusters[i]
		}
	}
	if cluster == nil {
		t.Fatalf("cluster %s not in snapshot", derived)
	}
	if cluster.HealthCheckPath != "/healthz" || cluster.HealthCheckIntervalSeconds != 5 {
		t.Errorf("cluster health check = (%q,%d); want (/healthz, 5)", cluster.HealthCheckPath, cluster.HealthCheckIntervalSeconds)
	}

	// (b) The builders render them onto the derived route + cluster.
	routeCfgs := builders.BuildRouteConfigs(snap.Gateways, snap.Routes, builders.RateLimitServiceOptions{})
	if !builtRouteHasLocalRateLimit(routeCfgs, derived) {
		t.Errorf("built route %s missing local_ratelimit typed_per_filter_config", derived)
	}
	clusters := builders.BuildClusters(snap.Clusters, builders.ExtAuthzOptions{}, builders.RateLimitServiceOptions{})
	if !builtClusterHasHealthCheck(clusters, derived, "/healthz") {
		t.Errorf("built cluster %s missing HTTP health check for /healthz", derived)
	}
}

// R4 Stage 3a-ii: auth_policy=none opts a derived route out of ext_authz
// (ExtAuthzPerRoute{Disabled}); the default (jwt) leaves the route authenticated
// (no override). Python write -> Go load -> builder render.
func TestLoadSnapshot_OSBAuthPolicy(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	prov := os.Getenv("OSB_PROVISION")
	if dsn == "" || prov == "" {
		t.Skip("TEST_DATABASE_URL and OSB_PROVISION required (integration)")
	}

	const specPublic = `{"name":"pub","team":"e2eauth","host":"10.9.9.30","port":8080,"protocol":"HTTP","auth_policy":"none"}`
	const specDefault = `{"name":"priv","team":"e2eauth","host":"10.9.9.31","port":8080,"protocol":"HTTP"}`

	osbProvision(t, dsn, prov, "create", specPublic)
	osbProvision(t, dsn, prov, "create", specDefault)
	snap := loadForTest(t, dsn)

	routeCfgs := builders.BuildRouteConfigs(snap.Gateways, snap.Routes, builders.RateLimitServiceOptions{})
	if !builtRouteExtAuthzDisabled(routeCfgs, "osb-e2eauth-pub") {
		t.Error("auth_policy=none route must carry an ext_authz disable override")
	}
	if builtRouteExtAuthzDisabled(routeCfgs, "osb-e2eauth-priv") {
		t.Error("default (jwt) route must NOT carry an ext_authz disable — stays authenticated")
	}
}
