package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file is the Admin READ API's storage surface. Every reader here is
// KEY-FREE BY CONSTRUCTION: none of these queries selects secrets.key_pem, and
// none of the returned types has a field that could carry key material. The
// Admin API must never be a reason to decrypt (or even read) a private key —
// that is LoadSnapshot's job, for the reconciler only. Do NOT route an admin
// read through LoadSnapshot: it calls keycrypt.Open and returns plaintext keys
// (see loadSecrets), which is exactly what an HTTP response path must never
// touch. cmd/server's admin leak-guard test enforces this at the response
// level; this file enforces it at the query level.

// Topology is the key-free configuration view served by /admin/v1/topology.
// It deliberately has NO secrets field — gateways/routes reference secrets by
// NAME only, and those references are already part of the domain types.
type Topology struct {
	Gateways  []Gateway
	Routes    []Route
	Clusters  []Cluster
	Endpoints []Endpoint
}

// CertificateRow is one secrets-table row WITHOUT key material: the query that
// produces it selects cert_pem only (never key_pem), so there is no key field
// to leak. The certificate is public material; the admin layer parses it for
// fingerprint/issuer/expiry via the custodian's parse.
type CertificateRow struct {
	ID      string
	Name    string
	Kind    string // "tls_certificate" | "validation_context"
	CertPEM string
}

// ProvisionedService is one OSB services row (desired state, cross-tenant —
// this is an admin view). webhook_url and the raw payload are deliberately
// omitted: a webhook URL can embed credentials in its query string.
type ProvisionedService struct {
	ID            string
	Name          string
	Team          string
	Host          string
	Port          int
	Protocol      string
	AuthPolicy    string
	TLSSecretName string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ProvisionRequest is one OSB provision_requests row: the async work-queue
// state an operator needs to answer "why isn't my service up" — including
// FAILED with its error. payload and webhook_url are omitted (see
// ProvisionedService).
type ProvisionRequest struct {
	ID          string
	Operation   string // CREATE | DELETE
	Status      string // PENDING | COMPLETED | FAILED
	Team        string
	Error       string
	CreatedAt   time.Time
	CompletedAt *time.Time
}

// Provisioning is the OSB state view served by /admin/v1/provisioning.
type Provisioning struct {
	Services []ProvisionedService
	Requests []ProvisionRequest
}

// LoadTopology returns the active configuration rows for the Admin API —
// gateways, routes, clusters, endpoints — and NEVER touches the secrets table.
// Same point-in-time semantics as LoadSnapshot (one REPEATABLE READ read-only
// tx over the same four key-free loaders), minus loadSecrets — reuse exactly
// where reuse is safe.
func (s *PostgresStore) LoadTopology(ctx context.Context) (*Topology, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin read tx: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed

	topo := &Topology{}
	if topo.Gateways, err = loadGateways(ctx, tx); err != nil {
		return nil, fmt.Errorf("load gateways: %w", err)
	}
	if topo.Routes, err = loadRoutes(ctx, tx); err != nil {
		return nil, fmt.Errorf("load routes: %w", err)
	}
	if topo.Clusters, err = loadClusters(ctx, tx); err != nil {
		return nil, fmt.Errorf("load clusters: %w", err)
	}
	if topo.Endpoints, err = loadEndpoints(ctx, tx); err != nil {
		return nil, fmt.Errorf("load endpoints: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit read tx: %w", err)
	}
	return topo, nil
}

// LoadCertificateRows returns every secrets row's name/kind/cert. key_pem is
// DELIBERATELY absent from the SELECT: this reader works (and must keep
// working) on a store with no KEK, because it never reads a key — sealed or
// otherwise. Do not "complete" the query.
func (s *PostgresStore) LoadCertificateRows(ctx context.Context) ([]CertificateRow, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("begin read tx: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id, name, COALESCE(kind, 'tls_certificate'), cert_pem
		FROM secrets
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []CertificateRow
	for rows.Next() {
		var r CertificateRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &r.CertPEM); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit read tx: %w", err)
	}
	return out, nil
}

// LoadProvisioning returns the OSB desired-state and request-queue view:
// active services plus the newest requestLimit provision requests (all
// statuses, including FAILED — recent failures are what an operator is here
// for). Cross-tenant by design: this is the admin view the tenant-scoped OSB
// API deliberately cannot serve. webhook_url and payload are never selected
// (a webhook URL can embed credentials).
func (s *PostgresStore) LoadProvisioning(ctx context.Context, requestLimit int) (*Provisioning, error) {
	if requestLimit <= 0 {
		requestLimit = 100
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin read tx: %w", err)
	}
	defer tx.Rollback(ctx)

	prov := &Provisioning{}

	svcRows, err := tx.Query(ctx, `
		SELECT id::text, name, team, host, port, protocol,
		       COALESCE(auth_policy, 'jwt'), COALESCE(tls_secret_name, ''),
		       created_at, updated_at
		FROM services
		WHERE deleted_at IS NULL
		ORDER BY team, name
	`)
	if err != nil {
		return nil, fmt.Errorf("load services: %w", err)
	}
	for svcRows.Next() {
		var s ProvisionedService
		if err := svcRows.Scan(&s.ID, &s.Name, &s.Team, &s.Host, &s.Port, &s.Protocol,
			&s.AuthPolicy, &s.TLSSecretName, &s.CreatedAt, &s.UpdatedAt); err != nil {
			svcRows.Close()
			return nil, fmt.Errorf("scan service: %w", err)
		}
		prov.Services = append(prov.Services, s)
	}
	svcRows.Close()
	if err := svcRows.Err(); err != nil {
		return nil, fmt.Errorf("load services: %w", err)
	}

	reqRows, err := tx.Query(ctx, `
		SELECT id::text, operation, status, COALESCE(team, ''), COALESCE(error, ''),
		       created_at, completed_at
		FROM provision_requests
		ORDER BY created_at DESC
		LIMIT $1
	`, requestLimit)
	if err != nil {
		return nil, fmt.Errorf("load provision_requests: %w", err)
	}
	for reqRows.Next() {
		var r ProvisionRequest
		if err := reqRows.Scan(&r.ID, &r.Operation, &r.Status, &r.Team, &r.Error,
			&r.CreatedAt, &r.CompletedAt); err != nil {
			reqRows.Close()
			return nil, fmt.Errorf("scan provision_request: %w", err)
		}
		prov.Requests = append(prov.Requests, r)
	}
	reqRows.Close()
	if err := reqRows.Err(); err != nil {
		return nil, fmt.Errorf("load provision_requests: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit read tx: %w", err)
	}
	return prov, nil
}
