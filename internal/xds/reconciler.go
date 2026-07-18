package xds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"

	"github.com/edge-infra/control-plane/internal/ha"
	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds/builders"
)

// Reconciler converts the store's domain configuration into an xDS snapshot
// and publishes it to the snapshot cache for every known node.
type Reconciler struct {
	cache     cachev3.SnapshotCache
	store     store.Store
	nodeID    string
	log       *slog.Logger
	triggerCh chan struct{}
	ha        ha.Coordinator // nil = single-instance mode
	rateLimit builders.RateLimitOptions
	extAuthz  builders.ExtAuthzOptions
	rls       builders.RateLimitServiceOptions

	// allowEmpty disables the empty-collapse guard (EDGE_ALLOW_EMPTY_SNAPSHOT),
	// permitting an intentional scale-to-zero / drain. Read once at construction.
	allowEmpty bool

	localLast                    atomic.Pointer[reconcileResult]
	lastSnap                     atomic.Pointer[cachev3.Snapshot]
	emptySnapshotsBlocked        atomic.Uint64
	inconsistentSnapshotsBlocked atomic.Uint64

	// authWantedButExtAuthzOff counts reconciles where a route requested auth but
	// ext_authz was globally disabled (so auth could not be enforced). A loud
	// signal — never a silent bypass.
	authWantedButExtAuthzOff atomic.Uint64

	// First-boot degraded-PUBLISH counters — distinct from the *Blocked guard
	// counters above. On first boot (prev == nil) the empty-collapse and
	// inconsistent guards are EXEMPT and the bad config IS published so a fresh edge
	// can come up. That is the one path where bad config actually reaches Envoy;
	// these count those publishes so it is observable (surfaced as
	// xds_snapshots_published_degraded_total, NOT xds_snapshots_blocked_total —
	// nothing was blocked).
	emptyFirstBootPublished        atomic.Uint64
	inconsistentFirstBootPublished atomic.Uint64

	// Observability (additive; read by the metrics collector). NONE of these affect
	// a guard or publish decision — they only describe what the reconciler did.
	lastReconcileUnix  atomic.Int64 // unix seconds of the last successful reconcile
	lastReconcileNanos atomic.Int64 // duration of the last reconcile, in nanoseconds
	activeStreams      atomic.Int64 // currently-open xDS (ADS) gRPC streams

	// nodeAcks tracks, per connected node, the last xDS (CDS) version_info the node
	// ACKed. NodesBehind compares it to the current published version to count nodes
	// that have NOT acknowledged it — the delivery-divergence signal that
	// xds_snapshots_blocked_total is blind to (the control-plane publishes
	// successfully; only DELIVERY to a node is withheld, e.g. the #47 version
	// collision). Populated by the server callbacks; keyed by node id.
	ackMu    sync.Mutex
	nodeAcks map[string]string
}

type reconcileResult struct {
	Version string
	Hash    string
}

// NewReconciler constructs a Reconciler bound to the given snapshot cache,
// store and default node ID. A nil logger falls back to slog.Default().
func NewReconciler(c cachev3.SnapshotCache, s store.Store, nodeID string, log *slog.Logger) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	return &Reconciler{
		cache:      c,
		store:      s,
		nodeID:     nodeID,
		log:        log,
		triggerCh:  make(chan struct{}, 1),
		allowEmpty: allowEmptySnapshot(),
		nodeAcks:   make(map[string]string),
	}
}

// InconsistentSnapshotsBlocked reports how many times the consistency guard has
// kept the last-good config instead of publishing an inconsistent snapshot.
func (r *Reconciler) InconsistentSnapshotsBlocked() uint64 {
	return r.inconsistentSnapshotsBlocked.Load()
}

// shouldBlockInconsistent reports whether snap must be withheld to keep the
// last-good config: an inconsistent snapshot is blocked ONLY once a healthy one
// has been published (hasPrev) — first boot is exempt.
func shouldBlockInconsistent(snap *cachev3.Snapshot, hasPrev bool) bool {
	return hasPrev && snapshotConsistencyError(snap) != nil
}

// snapshotConsistencyError returns the reason a snapshot must not be published, or
// nil if it is safe. It combines two fail-static checks:
//   - Envoy's own Snapshot.Consistent() — dangling CDS->EDS (an EDS cluster with no
//     endpoint assignment) or LDS->RDS (a listener referencing an absent route
//     config) references. NOTE: the current builders cannot actually emit either
//     (BuildEndpoints emits a CLA per cluster; BuildListeners/BuildRouteConfigs both
//     iterate the same gateways), so this arm is defence-in-depth against a future
//     builder regression.
//   - danglingRouteClusterError — a route whose target cluster is absent from CDS.
//     Consistent() does NOT traverse route->cluster references, yet this IS
//     producible by the data path (a routes row left pointing at a deleted/absent
//     cluster), and Envoy would blackhole it. This is the reachable R8 case.
func snapshotConsistencyError(snap *cachev3.Snapshot) error {
	if err := snap.Consistent(); err != nil {
		return err
	}
	return danglingRouteClusterError(snap)
}

// danglingRouteClusterError returns an error naming the first RDS route that
// forwards to a cluster absent from CDS (Envoy would blackhole it), or nil when
// every single-cluster route action targets a cluster present in CDS. Weighted /
// redirect / non-forwarding actions have an empty GetCluster() and are skipped.
func danglingRouteClusterError(snap *cachev3.Snapshot) error {
	clusters := snap.GetResources(resourcev3.ClusterType)
	for _, res := range snap.GetResources(resourcev3.RouteType) {
		rc, ok := res.(*routev3.RouteConfiguration)
		if !ok {
			continue
		}
		for _, vh := range rc.GetVirtualHosts() {
			for _, rt := range vh.GetRoutes() {
				name := rt.GetRoute().GetCluster()
				if name == "" {
					continue
				}
				if _, present := clusters[name]; !present {
					return fmt.Errorf("route %q on %q forwards to cluster %q absent from CDS (would blackhole)",
						rt.GetName(), rc.GetName(), name)
				}
			}
		}
	}
	return nil
}

// EmptySnapshotsBlocked reports how many times the empty-collapse guard has
// suppressed a publish. Exposed for tests and future metrics wiring.
func (r *Reconciler) EmptySnapshotsBlocked() uint64 {
	return r.emptySnapshotsBlocked.Load()
}

// AuthWantedButExtAuthzOff reports how many reconciles saw a route requesting
// auth while ext_authz was globally disabled. Exposed for tests and metrics.
func (r *Reconciler) AuthWantedButExtAuthzOff() uint64 {
	return r.authWantedButExtAuthzOff.Load()
}

// EmptyFirstBootPublished reports how many times a first-boot reconcile (no
// last-good) PUBLISHED an empty snapshot (zero listeners or clusters) under the
// empty-collapse guard's first-boot exemption — a degraded publish, not a block.
func (r *Reconciler) EmptyFirstBootPublished() uint64 {
	return r.emptyFirstBootPublished.Load()
}

// InconsistentFirstBootPublished reports how many times a first-boot reconcile (no
// last-good) PUBLISHED an internally inconsistent snapshot (dangling route/cluster)
// under the consistency guard's first-boot exemption — a degraded publish, not a
// block.
func (r *Reconciler) InconsistentFirstBootPublished() uint64 {
	return r.inconsistentFirstBootPublished.Load()
}

// allowEmptySnapshot reports whether the empty-collapse guard is disabled via
// EDGE_ALLOW_EMPTY_SNAPSHOT (accepts 1/t/true/… per strconv.ParseBool).
// Defaults to false, so the guard is on unless an operator opts out.
func allowEmptySnapshot() bool {
	v, _ := strconv.ParseBool(os.Getenv("EDGE_ALLOW_EMPTY_SNAPSHOT"))
	return v
}

// WithCoordinator sets the HA coordinator used for shared hash and version
// tracking across replicas. Must be called before Run.
func (r *Reconciler) WithCoordinator(c ha.Coordinator) {
	r.ha = c
}

// WithRateLimit configures the per-listener Envoy local_ratelimit filter
// emitted on every gateway listener. Must be called before Run. The zero
// value (Enabled=false) leaves listeners unchanged.
func (r *Reconciler) WithRateLimit(opts builders.RateLimitOptions) {
	r.rateLimit = opts
}

// WithExtAuthz configures the Envoy ext_authz filter (and its auth-service
// cluster) emitted on every gateway listener. Must be called before Run. The
// zero value (Enabled=false) leaves listeners and clusters unchanged. The
// emitted filter is fail-closed.
func (r *Reconciler) WithExtAuthz(opts builders.ExtAuthzOptions) {
	r.extAuthz = opts
}

// WithRateLimitService configures the Envoy global ratelimit filter, its RLS
// cluster, and per-route descriptors. Must be called before Run. The zero
// value (Enabled=false) leaves listeners/clusters/routes unchanged. The filter
// is fail-open.
func (r *Reconciler) WithRateLimitService(opts builders.RateLimitServiceOptions) {
	r.rls = opts
}

// TriggerNow requests an out-of-band reconcile. It is safe to call from any
// goroutine and never blocks: if a trigger is already pending the call is a
// no-op (coalescing semantics).
func (r *Reconciler) TriggerNow() {
	select {
	case r.triggerCh <- struct{}{}:
	default:
	}
}

// Reconcile loads the latest store snapshot, builds xDS resources and pushes
// them to the cache when the resource set has actually changed.
func (r *Reconciler) Reconcile(ctx context.Context) (err error) {
	// Observability only: record when the reconcile loop last completed without error
	// (loop-liveness, incl. the fast-path and guard-block return-nil paths) and how
	// long it took. Never affects the outcome.
	start := time.Now()
	defer func() {
		if err == nil {
			r.lastReconcileUnix.Store(time.Now().Unix())
			r.lastReconcileNanos.Store(time.Since(start).Nanoseconds())
		}
	}()

	domain, err := r.store.LoadSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}

	// FAIL-CLOSED (CFG-1): per-service auth is renderable ONLY when ext_authz is
	// globally configured (its filter needs the auth-service cluster/target, both
	// gated on ExtAuthz.Enabled). A route that wants auth (auth_policy != none)
	// while ext_authz is off would serve UNAUTHENTICATED — an identity-bearing
	// listener with an open gateway. REFUSE to build/publish the snapshot rather
	// than serve it open (was warn-and-serve-open). The reconcile loop logs this
	// and retries, keeping the last-good config (or nothing on first boot), so an
	// operator who turns ext_authz off can never silently open an identity listener.
	if !r.extAuthz.Enabled && builders.AnyRouteWantsAuth(domain.Routes) {
		r.authWantedButExtAuthzOff.Add(1)
		return fmt.Errorf("refusing to build snapshot: a route requests per-service auth " +
			"(auth_policy != none) but ext_authz is globally disabled — an identity-bearing " +
			"listener without ext_authz would serve unauthenticated; enable ext_authz " +
			"(EXT_AUTHZ_ENABLED) and configure the auth-service, or set auth_policy=none")
	}

	resources := map[resourcev3.Type][]types.Resource{
		resourcev3.ListenerType: builders.BuildListeners(domain.Gateways, domain.Routes, r.rateLimit, r.extAuthz, r.rls),
		resourcev3.RouteType:    builders.BuildRouteConfigs(domain.Gateways, domain.Routes, r.rls),
		resourcev3.ClusterType:  builders.BuildClusters(domain.Clusters, r.extAuthz, r.rls),
		resourcev3.EndpointType: builders.BuildEndpoints(domain.Clusters, domain.Endpoints),
		resourcev3.SecretType:   builders.BuildSecrets(domain.Secrets),
	}

	hash := hashResources(resources)

	// Fast path: local state confirms nothing has changed on this replica.
	prev := r.localLast.Load()
	if prev != nil && prev.Hash == hash {
		// Config is unchanged, but a proxy that connected since the last change
		// holds no snapshot yet — the fan-out below only runs on a change. Catch up
		// any newly-connected node so a restarted/scaled/new edge-proxy receives
		// config on connect instead of staying dark until the next config change.
		r.catchUpConnectedNodes(ctx, prev.Version)
		return nil
	}

	// Fail-static empty-collapse guard.
	//
	// Once a healthy snapshot has been published (prev != nil), refuse to
	// replace it with one that has zero listeners or zero clusters. xDS is
	// state-of-the-world: a push with no listeners removes every listener on
	// every proxy, and a push with no clusters blackholes every route. An
	// empty-but-successful read is almost always a source fault (a truncated
	// table, a failover to an un-seeded replica) rather than a real teardown,
	// so we keep serving the last-good snapshot until the source recovers.
	//
	// Triggers ONLY on total collapse: a partial change (some listeners/clusters
	// removed while others remain) is non-zero and publishes normally. First
	// boot (prev == nil) is exempt so a fresh edge can come up empty. An
	// intentional decommission sets EDGE_ALLOW_EMPTY_SNAPSHOT=true.
	//
	// Placed before resolveVersion: on a block we return without touching the
	// local or shared (Redis) version counter, so a transient empty read can
	// never advance or pin a version.
	//
	// TODO(f1-follow-up): widen the floor from "zero" to "collapsed far below
	// last-good" (e.g. refuse if new listeners/clusters < ~50% of prev counts).
	nListeners := len(resources[resourcev3.ListenerType])
	nClusters := len(resources[resourcev3.ClusterType])
	emptySnapshot := nListeners == 0 || nClusters == 0

	if prev != nil && !r.allowEmpty && emptySnapshot {
		r.emptySnapshotsBlocked.Add(1)
		r.log.Error("refusing to publish empty snapshot; keeping last-good config",
			"new_listeners", nListeners,
			"new_clusters", nClusters,
			"last_good_version", prev.Version,
			"blocked_total", r.emptySnapshotsBlocked.Load(),
		)
		return nil
	}

	// First-boot empty exemption (prev == nil): an empty snapshot IS published so a
	// fresh edge can come up — but that removes every listener/cluster on the proxies,
	// the least-observable degraded state in the reconciler (an empty snapshot is also
	// internally consistent, so the inconsistency warn below never fires for it).
	// Publish-anyway behaviour is unchanged; we only make it VISIBLE (warn + counter).
	// Note: EDGE_ALLOW_EMPTY_SNAPSHOT with prev != nil stays intentionally silent — an
	// operator opt-out, unchanged here.
	if prev == nil && emptySnapshot {
		r.emptyFirstBootPublished.Add(1)
		r.log.Warn("first snapshot is empty (no listeners or clusters); publishing (no last-good yet)",
			"new_listeners", nListeners,
			"new_clusters", nClusters,
			"degraded_total", r.emptyFirstBootPublished.Load(),
		)
	}

	version, err := r.resolveVersion(ctx, hash)
	if err != nil {
		return err
	}

	snap, err := cachev3.NewSnapshot(version, resources)
	if err != nil {
		return fmt.Errorf("new snapshot: %w", err)
	}
	// Fail-static bad-config guard: an inconsistent snapshot — a dangling Envoy
	// reference (CDS->EDS / LDS->RDS, via Consistent()) OR a route forwarding to a
	// cluster absent from CDS (which Consistent() does NOT check but the data path
	// CAN produce) — would blackhole traffic if pushed. Once a healthy snapshot
	// exists (prev != nil), refuse it and keep the last-good config; first boot is
	// exempt (nothing to keep — surface it as a warning).
	if shouldBlockInconsistent(snap, prev != nil) {
		r.inconsistentSnapshotsBlocked.Add(1)
		r.log.Error("refusing to publish inconsistent snapshot; keeping last-good config",
			"err", snapshotConsistencyError(snap),
			"last_good_version", prev.Version,
			"blocked_total", r.inconsistentSnapshotsBlocked.Load(),
		)
		return nil
	}
	if cErr := snapshotConsistencyError(snap); cErr != nil {
		// Reached only on first boot (prev == nil): when a last-good exists the block
		// above returns first. The inconsistent snapshot IS published so a fresh edge
		// can come up, but a dangling route/cluster will blackhole that traffic —
		// count it so this degraded publish is observable, not just logged.
		r.inconsistentFirstBootPublished.Add(1)
		r.log.Warn("first snapshot not internally consistent; publishing (no last-good yet)",
			"err", cErr,
			"degraded_total", r.inconsistentFirstBootPublished.Load(),
		)
	}

	nodes := r.targetNodes()
	for _, n := range nodes {
		if err := r.cache.SetSnapshot(ctx, n, snap); err != nil {
			return fmt.Errorf("set snapshot node=%s: %w", n, err)
		}
	}

	r.lastSnap.Store(snap)
	r.localLast.Store(&reconcileResult{Version: version, Hash: hash})
	r.log.Info("snapshot pushed",
		"version", version,
		"listeners", len(resources[resourcev3.ListenerType]),
		"routes", len(resources[resourcev3.RouteType]),
		"clusters", len(resources[resourcev3.ClusterType]),
		"endpoints", len(resources[resourcev3.EndpointType]),
		"secrets", len(resources[resourcev3.SecretType]),
		"nodes", len(nodes),
	)
	return nil
}

// resolveVersion determines the version string to stamp on the current snapshot.
//
// The version is a PURE FUNCTION OF THE CONFIG HASH (versionFromHash). This is the
// key invariant — same config hash → same version string, for every replica and
// ACROSS process restarts — and it is what makes xDS delivery correct:
//
//   - Unchanged config after a restart yields the SAME version, so
//     go-control-plane's SnapshotCache correctly dedups (no needless re-push).
//   - Changed config ALWAYS yields a different version, so the cache delivers it to
//     a still-connected Envoy. A per-process counter (the previous scheme) reset to
//     "v1" on restart, colliding with the version Envoy already held; the cache
//     compares the equal opaque version strings (pkg/cache/v3/simple.go) and
//     withholds the changed CDS/LDS. Envoy shows cds/lds update_failure with
//     update_rejected=0 — withheld delivery, not a NACK. A content-derived version
//     cannot collide, so the roll-edge-proxy workaround is no longer needed.
//
// Because the hash is deterministic, replicas agree without any coordination. In HA
// mode we still RECORD the live hash with the coordinator (best-effort, non-fatal)
// so the shared store reflects "which config is current" for failover/observability
// and for a future published-vs-ACKed divergence signal — but the version string is
// hash-derived either way, so the two paths never disagree.
func (r *Reconciler) resolveVersion(ctx context.Context, hash string) (string, error) {
	if r.ha != nil {
		if _, err := r.ha.StoreHash(ctx, hash); err != nil {
			r.log.Warn("ha: store hash failed (non-fatal; version is hash-derived)", "err", err)
		}
	}
	return versionFromHash(hash), nil
}

// versionFromHash derives the xDS snapshot version string from the sha256 config
// hash. Envoy and go-control-plane treat the version as opaque, so a stable
// function of the content is ideal. A 16-hex-char (64-bit) prefix distinguishes the
// handful of live configs with a negligible collision probability while keeping the
// version readable in logs and config_dump.
func versionFromHash(hash string) string {
	const n = 16
	if len(hash) >= n {
		return hash[:n]
	}
	return hash
}

// Run executes an immediate Reconcile, then loops on a ticker plus the
// trigger channel until ctx is cancelled. It returns ctx.Err() on exit.
func (r *Reconciler) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if err := r.Reconcile(ctx); err != nil {
		r.log.Error("initial reconcile failed", "err", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := r.Reconcile(ctx); err != nil {
				r.log.Error("reconcile failed", "err", err)
			}
		case <-r.triggerCh:
			if err := r.Reconcile(ctx); err != nil {
				r.log.Error("triggered reconcile failed", "err", err)
			}
		}
	}
}

func (r *Reconciler) targetNodes() []string {
	keys := r.cache.GetStatusKeys()
	seen := make(map[string]struct{}, len(keys)+1)
	out := make([]string, 0, len(keys)+1)
	for _, k := range keys {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	if _, ok := seen[r.nodeID]; !ok {
		out = append(out, r.nodeID)
	}
	return out
}

// catchUpConnectedNodes pushes the last-published snapshot to any connected node
// (present in GetStatusKeys) that does not yet hold the current version. Called on
// the unchanged-config fast path so a proxy that connects while config is stable
// receives it on connect — without this, SetSnapshot only runs on a config change,
// leaving a restarted/scaled/new edge-proxy with no config until the next change.
//
// NOTE: this shares the connected-node fan-out that XDS-1 (per-node SDS scoping)
// would extend to per-node snapshots; keep them in mind together, but XDS-1 is out
// of scope here.
func (r *Reconciler) catchUpConnectedNodes(ctx context.Context, version string) {
	snap := r.lastSnap.Load()
	if snap == nil {
		return
	}
	for _, n := range r.cache.GetStatusKeys() {
		if cur, err := r.cache.GetSnapshot(n); err == nil && cur != nil &&
			cur.GetVersion(resourcev3.ClusterType) == version {
			continue // already has the current snapshot
		}
		if err := r.cache.SetSnapshot(ctx, n, snap); err != nil {
			r.log.Warn("late-join catch-up failed", "node", n, "err", err)
			continue
		}
		r.log.Info("late-join: pushed current snapshot to newly-connected node",
			"node", n, "version", version)
	}
}

func hashResources(m map[resourcev3.Type][]types.Resource) string {
	h := sha256.New()
	opts := proto.MarshalOptions{Deterministic: true}
	for _, k := range orderedTypes {
		fmt.Fprintf(h, "type=%s|", k)
		for _, res := range m[k] {
			b, err := opts.Marshal(res)
			if err != nil {
				fmt.Fprintf(h, "err=%s|", err)
				continue
			}
			fmt.Fprintf(h, "len=%d|", len(b))
			h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

var orderedTypes = []resourcev3.Type{
	resourcev3.ClusterType,
	resourcev3.EndpointType,
	resourcev3.ListenerType,
	resourcev3.RouteType,
	resourcev3.SecretType,
}
