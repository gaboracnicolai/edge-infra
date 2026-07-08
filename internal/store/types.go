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

	// Per-service rate limit (R4 Stage 3a-i). RateLimitPerUnit == 0 means no
	// limit; rendered as a per-route local_ratelimit typed_per_filter_config.
	RateLimitPerUnit int
	RateLimitUnit    string // "SECOND" | "MINUTE" | "HOUR"

	// Per-service auth (R4 Stage 3a-ii). "jwt" (default) or anything other than
	// "none" => ext_authz applies (authenticated); ONLY the exact "none" disables
	// ext_authz on this route. Never let empty/unknown read as disabled.
	AuthPolicy string

	// Per-service TLS secret NAME (R4 Stage 3b-i) — the SNI cert this route's
	// service presents on the shared HTTPS gateway. A reference only (SDS resolves
	// the material from the secrets table); empty for HTTP routes. Never the key
	// material itself — OSB writes only this reference (Stage 1 boundary).
	TLSSecret string

	// Per-service client-CA secret NAME (R4 Stage 3b-mtls) — for auth_policy=mtls,
	// the validation_context (trusted_ca) the downstream client cert is verified
	// against. A reference only; empty ⇒ no downstream mTLS on this route.
	ClientCASecret string
}

// Cluster is the domain model for an Envoy upstream cluster.
type Cluster struct {
	ID             string
	Name           string
	ConnectTimeout time.Duration
	LbPolicy       string

	// Per-service active HTTP health check (R4 Stage 3a-i). An empty
	// HealthCheckPath means no health check.
	HealthCheckPath            string
	HealthCheckIntervalSeconds int
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
	KeyPEM  string // empty for a validation_context (CA-only) secret
	// Kind is "tls_certificate" (server cert+key) or "validation_context" (a
	// cert-only client-CA trust bundle). Drives the SDS secret shape.
	Kind string
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

	// The write methods below have NO production caller since the CRD
	// controllers were retired (R4): OSB is the sole writer of gateways/routes
	// and it writes via the translator's direct SQL, not this interface. They are
	// retained (implemented by PostgresStore) as the write-API a future thin
	// OSB-adapter front-end for the kept api/v1alpha1 CR types could use.

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
