package xds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
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

	localVersion atomic.Uint64
	localLast    atomic.Pointer[reconcileResult]
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
		cache:     c,
		store:     s,
		nodeID:    nodeID,
		log:       log,
		triggerCh: make(chan struct{}, 1),
	}
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

	resources := map[resourcev3.Type][]types.Resource{
		resourcev3.ListenerType: builders.BuildListeners(domain.Gateways, r.rateLimit),
		resourcev3.RouteType:    builders.BuildRouteConfigs(domain.Gateways, domain.Routes),
		resourcev3.ClusterType:  builders.BuildClusters(domain.Clusters),
		resourcev3.EndpointType: builders.BuildEndpoints(domain.Clusters, domain.Endpoints),
		resourcev3.SecretType:   builders.BuildSecrets(domain.Secrets),
	}

	hash := hashResources(resources)

	// Fast path: local state confirms nothing has changed on this replica.
	if prev := r.localLast.Load(); prev != nil && prev.Hash == hash {
		return nil
	}

	version, err := r.resolveVersion(ctx, hash)
	if err != nil {
		return err
	}

	snap, err := cachev3.NewSnapshot(version, resources)
	if err != nil {
		return fmt.Errorf("new snapshot: %w", err)
	}
	if err := snap.Consistent(); err != nil {
		r.log.Warn("snapshot not internally consistent", "err", err)
	}

	nodes := r.targetNodes()
	for _, n := range nodes {
		if err := r.cache.SetSnapshot(ctx, n, snap); err != nil {
			return fmt.Errorf("set snapshot node=%s: %w", n, err)
		}
	}

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
