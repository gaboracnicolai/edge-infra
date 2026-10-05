package xds

import "strings"

// EgressNodePrefix marks an edge-egress Envoy: the edge-egress chart sets its xDS
// node id to "edge-egress/<pod name>". Such a node receives the egress snapshot
// and nothing else — no gateway listener, route or key — and an edge-proxy node
// (whose id is a Kubernetes node name, which cannot contain "/") never receives
// the egress one.
const EgressNodePrefix = "edge-egress/"

// IsEgressNode reports whether the xDS node id is an edge-egress Envoy.
func IsEgressNode(id string) bool { return strings.HasPrefix(id, EgressNodePrefix) }
