package builders

import (
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"

	"github.com/edge-infra/control-plane/internal/store"
)

func clusterFrom(t *testing.T, res any) *clusterv3.Cluster {
	t.Helper()
	c, ok := res.(*clusterv3.Cluster)
	if !ok {
		t.Fatalf("resource is not a Cluster: %T", res)
	}
	return c
}

// A per-service health_check renders as an active HTTP health check on the cluster.
func TestBuildClusters_HealthCheck(t *testing.T) {
	sc := store.Cluster{
		Name: "osb-team-svc", ConnectTimeout: 5 * time.Second, LbPolicy: "ROUND_ROBIN",
		HealthCheckPath: "/healthz", HealthCheckIntervalSeconds: 5,
	}
	res := BuildClusters([]store.Cluster{sc}, ExtAuthzOptions{}, RateLimitServiceOptions{})
	c := clusterFrom(t, res[0])

	if len(c.GetHealthChecks()) != 1 {
		t.Fatalf("health checks = %d; want 1", len(c.GetHealthChecks()))
	}
	hc := c.GetHealthChecks()[0]
	if got := hc.GetHttpHealthCheck().GetPath(); got != "/healthz" {
		t.Errorf("health check path = %q; want /healthz", got)
	}
	if got := hc.GetInterval().AsDuration(); got != 5*time.Second {
		t.Errorf("health check interval = %s; want 5s", got)
	}
	if hc.GetTimeout().AsDuration() <= 0 {
		t.Error("health check timeout must be set (> 0)")
	}
}

// A cluster with no health_check renders none (controller clusters unchanged).
func TestBuildClusters_NoHealthCheck(t *testing.T) {
	sc := store.Cluster{Name: "plain", ConnectTimeout: 5 * time.Second, LbPolicy: "ROUND_ROBIN"}
	res := BuildClusters([]store.Cluster{sc}, ExtAuthzOptions{}, RateLimitServiceOptions{})
	c := clusterFrom(t, res[0])
	if len(c.GetHealthChecks()) != 0 {
		t.Errorf("cluster without health_check must have no health checks; got %d", len(c.GetHealthChecks()))
	}
}
