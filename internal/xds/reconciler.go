package xds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync/atomic"
	"time"

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

	localVersion                 atomic.Uint64
	localLast                    atomic.Pointer[reconcileResult]
	lastSnap                     atomic.Pointer[cachev3.Snapshot]
	emptySnapshotsBlocked        atomic.Uint64
	inconsistentSnapshotsBlocked atomic.Uint64

	// authWantedButExtAuthzOff counts reconciles where a route requested auth but
	// ext_authz was globally disabled (so auth could not be enforced). A loud
	// signal — never a silent bypass.
	authWantedButExtAuthzOff atomic.Uint64
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
	return hasPrev && snap.Consistent() != nil
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
func (r *Reconciler) Reconcile(ctx context.Context) error {
	domain, err := r.store.LoadSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}

	// Authority-path signal: per-service auth is renderable ONLY when ext_authz is
	// globally configured (its filter needs the auth-service cluster/target, both
	// gated on ExtAuthz.Enabled). If a route wants auth while ext_authz is off it
	// is NOT authenticated — the gateway is already open — so signal loudly rather
	// than let anyone believe per-service auth is active. Never a silent bypass.
	if !r.extAuthz.Enabled && builders.AnyRouteWantsAuth(domain.Routes) {
		r.authWantedButExtAuthzOff.Add(1)
		r.log.Warn("per-service auth_policy requested but ext_authz is globally disabled; " +
			"affected routes are NOT authenticated (set EXT_AUTHZ_ENABLED and configure the auth-service)")
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
	if prev != nil && !r.allowEmpty {
		nListeners := len(resources[resourcev3.ListenerType])
		nClusters := len(resources[resourcev3.ClusterType])
		if nListeners == 0 || nClusters == 0 {
			r.emptySnapshotsBlocked.Add(1)
			r.log.Error("refusing to publish empty snapshot; keeping last-good config",
				"new_listeners", nListeners,
				"new_clusters", nClusters,
				"last_good_version", prev.Version,
				"blocked_total", r.emptySnapshotsBlocked.Load(),
			)
			return nil
		}
	}

	version, err := r.resolveVersion(ctx, hash)
	if err != nil {
		return err
	}

	snap, err := cachev3.NewSnapshot(version, resources)
	if err != nil {
		return fmt.Errorf("new snapshot: %w", err)
	}
	// Fail-static bad-config guard: an internally-inconsistent snapshot (e.g. a
	// listener referencing an absent route config, or an EDS cluster with no
	// endpoint assignment) would blackhole traffic if pushed. Once a healthy
	// snapshot exists (prev != nil), refuse it and keep the last-good config;
	// first boot is exempt (nothing to keep — surface it as a warning).
	if shouldBlockInconsistent(snap, prev != nil) {
		r.inconsistentSnapshotsBlocked.Add(1)
		r.log.Error("refusing to publish inconsistent snapshot; keeping last-good config",
			"err", snap.Consistent(),
			"last_good_version", prev.Version,
			"blocked_total", r.inconsistentSnapshotsBlocked.Load(),
		)
		return nil
	}
	if cErr := snap.Consistent(); cErr != nil {
		r.log.Warn("first snapshot not internally consistent; publishing (no last-good yet)", "err", cErr)
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
// In HA mode all replicas share a single version counter via Redis so that
// Envoy always sees the same version for the same config regardless of which
// control-plane replica it is connected to. On Redis error the local counter
// is used as a fallback so the server keeps running.
//
// Key invariant: same config hash → same version string across all replicas.
func (r *Reconciler) resolveVersion(ctx context.Context, hash string) (string, error) {
	if r.ha == nil {
		return fmt.Sprintf("v%d", r.localVersion.Add(1)), nil
	}

	sharedHash, sharedVer, err := r.ha.LoadHash(ctx)
	if err != nil {
		r.log.Warn("ha: load hash failed, using local version", "err", err)
		return fmt.Sprintf("v%d", r.localVersion.Add(1)), nil
	}

	if sharedHash == hash {
		// Another replica already recorded and pushed this config. We still
		// populate our local in-memory cache for the nodes connected to this
		// instance, but we reuse the existing version so Envoy sees a
		// consistent picture across replicas on failover.
		return fmt.Sprintf("v%d", sharedVer), nil
	}

	newVer, err := r.ha.StoreHash(ctx, hash)
	if err != nil {
		r.log.Warn("ha: store hash failed, using local version", "err", err)
		return fmt.Sprintf("v%d", r.localVersion.Add(1)), nil
	}
	return fmt.Sprintf("v%d", newVer), nil
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
