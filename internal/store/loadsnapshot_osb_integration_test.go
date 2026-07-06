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

	"github.com/edge-infra/control-plane/internal/store"
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
