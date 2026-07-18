package xds

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/store"
)

// degradedCount returns the current value of
// xds_snapshots_published_degraded_total{reason="<reason>"} in the scraped
// exposition (mirrors blockedCount in metrics_test.go). Fails if the series is
// absent — every reason must be present from t=0.
func degradedCount(t *testing.T, h http.Handler, reason string) float64 {
	t.Helper()
	prefix := `xds_snapshots_published_degraded_total{reason="` + reason + `"}`
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

// First boot with an INCONSISTENT snapshot (no last-good): the consistency guard is
// exempt, so the bad config IS published (behaviour preserved) — and that degraded
// publish must be COUNTED on its own metric, distinct from the *Blocked guard counter
// (which stays 0 because nothing was blocked).
//
// Red-first: InconsistentFirstBootPublished increments only at the exemption site; a
// build without that increment leaves it at 0 and this fails.
func TestReconcile_FirstBootInconsistentPublishIsCounted(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: danglingRouteSnapshot()}, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))

	// Behaviour preserved: the (bad) snapshot WAS published so a fresh edge boots.
	snap, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err, "first boot must publish even an inconsistent snapshot")
	require.NotEmpty(t, snap.GetResources(resourcev3.ClusterType))

	// The degraded publish is now visible — and distinct from the guard block.
	assert.Equal(t, uint64(1), r.InconsistentFirstBootPublished(),
		"the inconsistent first-boot publish must be counted")
	assert.Equal(t, uint64(0), r.InconsistentSnapshotsBlocked(),
		"nothing was BLOCKED on first boot — the block counter must stay 0")
	assert.Equal(t, uint64(0), r.EmptyFirstBootPublished(),
		"an inconsistent (non-empty) publish must not move the empty series")
}

// First boot with an EMPTY snapshot (no last-good): the empty-collapse guard is
// exempt, so an empty snapshot IS published (behaviour preserved). This was the
// least-observable state in the reconciler — no warn, no counter. It must now be
// counted, distinct from the block counter.
func TestReconcile_FirstBootEmptyPublishIsCounted(t *testing.T) {
	cache := newCache()
	r := NewReconciler(cache, &fakeStore{snap: &store.Snapshot{}}, testNodeID, discardLogger())

	require.NoError(t, r.Reconcile(context.Background()))

	// Behaviour preserved: an empty first-boot snapshot is published (a fresh edge
	// may legitimately come up empty).
	_, err := cache.GetSnapshot(testNodeID)
	require.NoError(t, err, "first boot must publish even an empty snapshot")

	assert.Equal(t, uint64(1), r.EmptyFirstBootPublished(),
		"the empty first-boot publish must be counted")
	assert.Equal(t, uint64(0), r.EmptySnapshotsBlocked(),
		"nothing was BLOCKED on first boot — the block counter must stay 0")
	assert.Equal(t, uint64(0), r.InconsistentFirstBootPublished(),
		"an empty snapshot is internally consistent — the inconsistent series must stay 0")
}

// The new degraded-publish counters must be exported as
// xds_snapshots_published_degraded_total{reason=...}, present from t=0 and tracking
// each exemption exactly — without touching xds_snapshots_blocked_total.
func TestFirstBootMetrics_ExportDegradedPublishCounts(t *testing.T) {
	cache := newCache()
	fs := &fakeStore{snap: sampleSnapshot()}
	r := NewReconciler(cache, fs, testNodeID, discardLogger())
	h := NewMetricsHandler(r)

	// Both degraded reasons exist and read 0 before any exemption.
	require.Equal(t, 0.0, degradedCount(t, h, "empty_first_boot"))
	require.Equal(t, 0.0, degradedCount(t, h, "inconsistent_first_boot"))

	// First reconcile is healthy (establishes a last-good), so no exemption fires.
	require.NoError(t, r.Reconcile(context.Background()))
	require.Equal(t, 0.0, degradedCount(t, h, "empty_first_boot"))
	require.Equal(t, 0.0, degradedCount(t, h, "inconsistent_first_boot"))

	// A fresh process (prev == nil) that first sees an inconsistent config publishes
	// it and increments only the inconsistent_first_boot series.
	r2 := NewReconciler(newCache(), &fakeStore{snap: danglingRouteSnapshot()}, testNodeID, discardLogger())
	h2 := NewMetricsHandler(r2)
	require.NoError(t, r2.Reconcile(context.Background()))
	require.Equal(t, 1.0, degradedCount(t, h2, "inconsistent_first_boot"))
	require.Equal(t, 0.0, degradedCount(t, h2, "empty_first_boot"))
	// And the blocked metric is untouched by a degraded PUBLISH.
	require.Equal(t, 0.0, blockedCount(t, h2, "inconsistent"))

	body := scrapeMetrics(t, h2)
	require.Contains(t, body, "# TYPE xds_snapshots_published_degraded_total counter")
}
