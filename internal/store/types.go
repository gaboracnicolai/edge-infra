// Package store defines the domain model and persistence interface for
// the edge control plane's configuration state.
package store

import (
	"context"
	"time"
)

// Gateway is the domain model for an edge listener (Envoy listener + filter chain).
type Gateway struct {
	ID           string
	Name         string
	Port         uint32
	Protocol     string
	TLSSecret    string
	NodeSelector map[string]string
}

// Route is the domain model for an HTTP route binding within a Gateway.
//
// GatewayID is the foreign-key reference used by the snapshot reconciler when
// reading. Writers (controllers) typically know only GatewayName and let the
// Store resolve it to an ID.
type Route struct {
	ID             string
	Name           string
	GatewayID      string
	GatewayName    string
	Hosts          []string
	PathPrefix     string
	ClusterName    string
	TimeoutSeconds int
}

// Cluster is the domain model for an Envoy upstream cluster.
type Cluster struct {
	ID             string
	Name           string
	ConnectTimeout time.Duration
	LbPolicy       string
}

// Endpoint is the domain model for an individual upstream endpoint (host:port).
type Endpoint struct {
	ID        string
	ClusterID string
	Address   string
	Port      uint32
	Weight    uint32
}

// Secret is the domain model for TLS material used by gateways via SDS.
type Secret struct {
	ID      string
	Name    string
	CertPEM string
	KeyPEM  string
}

// Snapshot is the full configuration state used to build an xDS snapshot.
type Snapshot struct {
	Gateways  []Gateway
	Routes    []Route
	Clusters  []Cluster
	Endpoints []Endpoint
	Secrets   []Secret
}

// Store persists domain configuration and supplies snapshots to the xDS
// reconciler. Implementations must be safe for concurrent use.
type Store interface {
	// LoadSnapshot returns the current desired state of every active resource.
	LoadSnapshot(ctx context.Context) (*Snapshot, error)

	// UpsertGateway inserts or updates a Gateway keyed by Name.
	UpsertGateway(ctx context.Context, g Gateway) error

	// DeleteGateway soft-deletes the Gateway with the given name.
	DeleteGateway(ctx context.Context, name string) error

	// UpsertRoute inserts or updates a Route keyed by (GatewayName, PathPrefix).
	// The store resolves GatewayName to the underlying gateway ID.
	UpsertRoute(ctx context.Context, r Route) error

	// DeleteRoute soft-deletes the route bound to the given gateway and path prefix.
	DeleteRoute(ctx context.Context, gatewayName, pathPrefix string) error

	// Close releases any underlying connections.
	Close()
}
