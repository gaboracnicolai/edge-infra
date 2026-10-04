package xds

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds/builders"
)

// Per-node scoping (XDS-1). A gateway's node_selector pins it to a subset of edge
// nodes; a pinned node then receives only the listeners, routes and SDS secrets of
// the gateways that select it, so a node serving one tenant never holds another
// tenant's private key. Gateways with an empty selector are served by every node,
// which is also the whole behaviour when no gateway is pinned.
//
// A node's labels are derived from its xDS node id alone — never from Envoy's
// self-reported metadata, which go-control-plane freezes at the node's first
// connection — so a node's scope can only change when the config does, and the
// config hash (and so the version) covers every selector.

// NodeHostnameLabel is the one label an edge node carries: its xDS node id, which
// the edge-proxy chart sets to the Kubernetes node name. A selector naming any
// other label matches no node.
const NodeHostnameLabel = "kubernetes.io/hostname"

// publication is what the last publish was built from: the global snapshot the
// guards judged (and every node receives when no gateway is pinned), its
// resources, and the domain config, so catch-up can build a late node's own
// snapshot without reloading the store.
type publication struct {
	version   string
	snap      *cachev3.Snapshot
	resources map[resourcev3.Type][]types.Resource
	domain    *store.Snapshot
}

// gatewayServesNode reports whether node is selected by g's node_selector. An
// empty selector selects every node.
func gatewayServesNode(g store.Gateway, node string) bool {
	for k, v := range g.NodeSelector {
		if k != NodeHostnameLabel || v != node {
			return false
		}
	}
	return true
}

// nodePins renders every gateway's non-empty node_selector as one deterministic
// string, or "" when no gateway is pinned. It is folded into the config hash:
// the built resources do not carry selectors, so without it re-pinning a gateway
// would keep the version and the cache would never deliver the new scope.
func nodePins(gateways []store.Gateway) string {
	var pins []string
	for _, g := range gateways {
		if len(g.NodeSelector) == 0 {
			continue
		}
		kv := make([]string, 0, len(g.NodeSelector))
		for k, v := range g.NodeSelector {
			kv = append(kv, k+"="+v)
		}
		sort.Strings(kv)
		pins = append(pins, g.Name+"{"+strings.Join(kv, ",")+"}")
	}
	sort.Strings(pins)
	return strings.Join(pins, ";")
}

// hashWithPins folds the node pins into the resource hash. With no pins the hash
// is returned unchanged, so an unpinned fleet keeps exactly the versions it had.
func hashWithPins(hash, pins string) string {
	if pins == "" {
		return hash
	}
	sum := sha256.Sum256([]byte(hash + "|pins=" + pins))
	return hex.EncodeToString(sum[:])
}

// unservableSelectorKeys returns the selector labels no edge node carries, per
// gateway name — a gateway pinned by one of them is served by no node at all.
func unservableSelectorKeys(gateways []store.Gateway) map[string][]string {
	out := map[string][]string{}
	for _, g := range gateways {
		for k := range g.NodeSelector {
			if k != NodeHostnameLabel {
				out[g.Name] = append(out[g.Name], k)
			}
		}
	}
	return out
}

// snapshotForNode returns the snapshot node must hold for publication p. With no
// pinned gateway it is the global snapshot itself; otherwise it holds only the
// gateways selecting node, their routes, and the secrets those reference.
// Clusters and endpoints carry no key material and are shared as built.
func (r *Reconciler) snapshotForNode(p *publication, node string) (*cachev3.Snapshot, error) {
	if nodePins(p.domain.Gateways) == "" {
		return p.snap, nil
	}

	var gateways []store.Gateway
	served := map[string]bool{}
	referenced := map[string]bool{}
	for _, g := range p.domain.Gateways {
		if !gatewayServesNode(g, node) {
			continue
		}
		gateways = append(gateways, g)
		served[g.ID] = true
		if g.TLSSecret != "" {
			referenced[g.TLSSecret] = true
		}
	}
	var routes []store.Route
	for _, rt := range p.domain.Routes {
		if !served[rt.GatewayID] {
			continue
		}
		routes = append(routes, rt)
		if rt.TLSSecret != "" {
			referenced[rt.TLSSecret] = true
		}
		if rt.ClientCASecret != "" {
			referenced[rt.ClientCASecret] = true
		}
	}
	var secrets []store.Secret
	for _, s := range p.domain.Secrets {
		if referenced[s.Name] {
			secrets = append(secrets, s)
		}
	}

	return cachev3.NewSnapshot(p.version, map[resourcev3.Type][]types.Resource{
		resourcev3.ListenerType: builders.BuildListeners(gateways, routes, r.rateLimit, r.extAuthz, r.rls),
		resourcev3.RouteType:    builders.BuildRouteConfigs(gateways, routes, r.rls),
		resourcev3.ClusterType:  p.resources[resourcev3.ClusterType],
		resourcev3.EndpointType: p.resources[resourcev3.EndpointType],
		resourcev3.SecretType:   builders.BuildSecrets(secrets),
	})
}
