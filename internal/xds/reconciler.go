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

	version atomic.Uint64
	last    atomic.Pointer[reconcileResult]
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
		resourcev3.ListenerType: builders.BuildListeners(domain.Gateways),
		resourcev3.RouteType:    builders.BuildRouteConfigs(domain.Gateways, domain.Routes),
		resourcev3.ClusterType:  builders.BuildClusters(domain.Clusters),
		resourcev3.EndpointType: builders.BuildEndpoints(domain.Clusters, domain.Endpoints),
		resourcev3.SecretType:   builders.BuildSecrets(domain.Secrets),
	}

	hash := hashResources(resources)
	if prev := r.last.Load(); prev != nil && prev.Hash == hash {
		return nil
	}

	version := fmt.Sprintf("v%d", r.version.Add(1))
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

	r.last.Store(&reconcileResult{Version: version, Hash: hash})
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
