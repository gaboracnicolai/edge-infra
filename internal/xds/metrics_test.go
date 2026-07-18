package xds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/store"
)

// scrapeMetrics renders the Prometheus text exposition from a metrics handler.
func scrapeMetrics(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Body.String()
}

// blockedCount returns the current value of the
// xds_snapshots_blocked_total{reason="<reason>"} series in the scraped
// exposition. It fails if the series is absent: every reason must be present
// from t=0 (before any guard trips) so an alert can be written against a series
// that already exists.
func blockedCount(t *testing.T, h http.Handler, reason string) float64 {
	t.Helper()
	prefix := `xds_snapshots_blocked_total{reason="` + reason + `"}`
	for _, line := range strings.Split(scrapeMetrics(t, h), "\n") {
		if strings.HasPrefix(line, prefix) {
			fields := strings.Fields(line)
			v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
			require.NoError(t, err)
			return v
		}
	}
	t.Fatalf("metric series %s not found in exposition", prefix)
	return 0
}

// The three fail-static / fail-closed guard counters must be exported as
// xds_snapshots_blocked_total{reason=...} so prod can ALERT on withheld
// snapshots. Red-first: NewMetricsHandler does not exist yet (this file will not
// compile against origin/main), and once wired the per-reason counts must track
// each guard trip EXACTLY — a collector that did not read the live counters
// would leave them at 0 and fail the increment assertions below.
func TestFailStaticMetrics_ExportGuardTripCounts(t *testing.T) {
	ctx := context.Background()
	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())
	h := NewMetricsHandler(r)

	// Baseline: every reason present and zero before any guard has tripped.
	require.Equal(t, 0.0, blockedCount(t, h, "empty"))
	require.Equal(t, 0.0, blockedCount(t, h, "inconsistent"))
	require.Equal(t, 0.0, blockedCount(t, h, "auth_wanted_extauthz_off"))

	// Publish a healthy last-good so the fail-static guards are armed (they are
	// exempt on first boot).
	require.NoError(t, r.Reconcile(ctx))

	// Trip the inconsistent guard: a route forwarding to a cluster absent from
	// CDS. The publish is withheld and the counter increments.
	fs.snap = danglingRouteSnapshot()
	require.NoError(t, r.Reconcile(ctx))
	require.Equal(t, 1.0, blockedCount(t, h, "inconsistent"), "inconsistent block must be counted")
	require.Equal(t, 0.0, blockedCount(t, h, "empty"), "an inconsistent block must not move the empty series")

	// Trip the empty-collapse guard: the source read succeeds but returns nothing.
	fs.snap = &store.Snapshot{}
	require.NoError(t, r.Reconcile(ctx))
	require.Equal(t, 1.0, blockedCount(t, h, "empty"), "empty-collapse block must be counted")

	// Trip CFG-1: a route wants per-service auth while ext_authz is globally off,
	// so the reconciler refuses to build the snapshot (fail-closed).
	fs.snap = authWantingSnapshot()
	require.Error(t, r.Reconcile(ctx))
	require.Equal(t, 1.0, blockedCount(t, h, "auth_wanted_extauthz_off"), "CFG-1 fail-closed must be counted")

	// The exposition follows the repo convention: a <subsystem>_<name>_total
	// counter (cf. auth_requests_total, osb_requests_total).
	body := scrapeMetrics(t, h)
	require.Contains(t, body, "# TYPE xds_snapshots_blocked_total counter")
}
