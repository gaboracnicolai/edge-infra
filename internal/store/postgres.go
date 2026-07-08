package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgxDB is the subset of *pgxpool.Pool the store depends on. It is an
// interface so the snapshot read path can be exercised without a live
// database (see postgres_test.go).
type pgxDB interface {
	BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Ping(ctx context.Context) error
	Close()
}

// querier is the read surface shared by *pgxpool.Pool and pgx.Tx. The snapshot
// loaders take it so LoadSnapshot can funnel every read through one tx; the
// pool's own Query is deliberately kept off pgxDB so a read cannot bypass it.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// PostgresStore is a Store backed by a PostgreSQL connection pool.
type PostgresStore struct {
	pool pgxDB
}

// NewPostgresStore opens a pgxpool and verifies connectivity.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pgx config: %w", err)
	}
	cfg.MaxConns = 8
	cfg.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect pg: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping pg: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// Close releases all pooled connections.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// LoadSnapshot returns every active row across the configuration tables.
//
// All five reads run inside one REPEATABLE READ, read-only transaction so the
// result is a single point-in-time view. Without this the queries could land
// on different pooled connections and straddle a concurrent write, assembling
// a torn snapshot (e.g. a route whose gateway or cluster was just deleted)
// that is non-empty but internally inconsistent.
func (s *PostgresStore) LoadSnapshot(ctx context.Context) (*Snapshot, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin read tx: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; releases the snapshot otherwise

	snap := &Snapshot{}
	if snap.Gateways, err = loadGateways(ctx, tx); err != nil {
		return nil, fmt.Errorf("load gateways: %w", err)
	}
	if snap.Routes, err = loadRoutes(ctx, tx); err != nil {
		return nil, fmt.Errorf("load routes: %w", err)
	}
	if snap.Clusters, err = loadClusters(ctx, tx); err != nil {
		return nil, fmt.Errorf("load clusters: %w", err)
	}
	if snap.Endpoints, err = loadEndpoints(ctx, tx); err != nil {
		return nil, fmt.Errorf("load endpoints: %w", err)
	}
	if snap.Secrets, err = loadSecrets(ctx, tx); err != nil {
		return nil, fmt.Errorf("load secrets: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit read tx: %w", err)
	}
	return snap, nil
}

// UpsertGateway inserts or updates a Gateway by Name.
func (s *PostgresStore) UpsertGateway(ctx context.Context, g Gateway) error {
	ns := g.NodeSelector
	if ns == nil {
		ns = map[string]string{}
	}
	nsJSON, err := json.Marshal(ns)
	if err != nil {
		return fmt.Errorf("marshal node_selector: %w", err)
	}

	id := g.ID
	if id == "" {
		id = g.Name
	}
	var tlsSecret any
	if g.TLSSecret != "" {
		tlsSecret = g.TLSSecret
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO gateways (id, name, port, protocol, tls_secret, node_selector, deleted_at)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, NULL)
		ON CONFLICT (name) DO UPDATE SET
			port          = EXCLUDED.port,
			protocol      = EXCLUDED.protocol,
			tls_secret    = EXCLUDED.tls_secret,
			node_selector = EXCLUDED.node_selector,
			updated_at    = NOW(),
			deleted_at    = NULL
	`, id, g.Name, g.Port, g.Protocol, tlsSecret, string(nsJSON))
	return err
}

// DeleteGateway soft-deletes the Gateway row with the given name.
func (s *PostgresStore) DeleteGateway(ctx context.Context, name string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE gateways
		SET deleted_at = NOW(), updated_at = NOW()
		WHERE name = $1 AND deleted_at IS NULL
	`, name)
	return err
}

// UpsertRoute inserts or updates a Route by Name; resolves GatewayName → gateway_id.
func (s *PostgresStore) UpsertRoute(ctx context.Context, r Route) error {
	id := r.ID
	if id == "" {
		id = r.Name
	}
	hosts := r.Hosts
	if hosts == nil {
		hosts = []string{}
	}
	timeout := r.TimeoutSeconds
	if timeout <= 0 {
		timeout = 30
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO routes (id, name, gateway_id, hosts, path_prefix, cluster_name, timeout_seconds, deleted_at)
		SELECT $1, $2, g.id, $4::text[], $5, $6, $7, NULL
		FROM gateways g
		WHERE g.name = $3 AND g.deleted_at IS NULL
		ON CONFLICT (name) DO UPDATE SET
			gateway_id      = EXCLUDED.gateway_id,
			hosts           = EXCLUDED.hosts,
			path_prefix     = EXCLUDED.path_prefix,
			cluster_name    = EXCLUDED.cluster_name,
			timeout_seconds = EXCLUDED.timeout_seconds,
			updated_at      = NOW(),
			deleted_at      = NULL
	`, id, r.Name, r.GatewayName, hosts, r.PathPrefix, r.ClusterName, timeout)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("upsert route %q: gateway %q not found", r.Name, r.GatewayName)
	}
	return nil
}

// DeleteRoute soft-deletes the route bound to (gatewayName, pathPrefix).
func (s *PostgresStore) DeleteRoute(ctx context.Context, gatewayName, pathPrefix string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE routes
		SET deleted_at = NOW(), updated_at = NOW()
		WHERE gateway_id = (SELECT id FROM gateways WHERE name = $1 AND deleted_at IS NULL)
		  AND path_prefix = $2
		  AND deleted_at IS NULL
	`, gatewayName, pathPrefix)
	return err
}

func loadGateways(ctx context.Context, q querier) ([]Gateway, error) {
	rows, err := q.Query(ctx, `
		SELECT id, name, port, protocol, COALESCE(tls_secret, ''),
		       COALESCE(node_selector::text, '{}')
		FROM gateways
		WHERE deleted_at IS NULL
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Gateway
	for rows.Next() {
		var (
			g     Gateway
			nsRaw string
		)
		if err := rows.Scan(&g.ID, &g.Name, &g.Port, &g.Protocol, &g.TLSSecret, &nsRaw); err != nil {
			return nil, err
		}
		if nsRaw != "" {
			if err := json.Unmarshal([]byte(nsRaw), &g.NodeSelector); err != nil {
				return nil, fmt.Errorf("decode node_selector for %s: %w", g.Name, err)
			}
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func loadRoutes(ctx context.Context, q querier) ([]Route, error) {
	rows, err := q.Query(ctx, `
		SELECT id, name, gateway_id, hosts, path_prefix, cluster_name,
		       COALESCE(timeout_seconds, 30),
		       COALESCE(rate_limit_per_unit, 0), COALESCE(rate_limit_unit, ''),
		       COALESCE(auth_policy, 'jwt'), COALESCE(tls_secret_name, '')
		FROM routes
		WHERE deleted_at IS NULL
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Route
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.ID, &r.Name, &r.GatewayID, &r.Hosts, &r.PathPrefix, &r.ClusterName,
			&r.TimeoutSeconds, &r.RateLimitPerUnit, &r.RateLimitUnit, &r.AuthPolicy, &r.TLSSecret); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func loadClusters(ctx context.Context, q querier) ([]Cluster, error) {
	rows, err := q.Query(ctx, `
		SELECT id, name, connect_timeout_ms, lb_policy,
		       COALESCE(health_check_path, ''), COALESCE(health_check_interval_s, 0)
		FROM clusters
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Cluster
	for rows.Next() {
		var c Cluster
		var ms int64
		if err := rows.Scan(&c.ID, &c.Name, &ms, &c.LbPolicy,
			&c.HealthCheckPath, &c.HealthCheckIntervalSeconds); err != nil {
			return nil, err
		}
		c.ConnectTimeout = time.Duration(ms) * time.Millisecond
		out = append(out, c)
	}
	return out, rows.Err()
}

func loadEndpoints(ctx context.Context, q querier) ([]Endpoint, error) {
	rows, err := q.Query(ctx, `
		SELECT id, cluster_id, address, port, weight
		FROM endpoints
		ORDER BY cluster_id, address, port
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Endpoint
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.ID, &e.ClusterID, &e.Address, &e.Port, &e.Weight); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func loadSecrets(ctx context.Context, q querier) ([]Secret, error) {
	rows, err := q.Query(ctx, `
		SELECT id, name, cert_pem, COALESCE(key_pem, ''), COALESCE(kind, 'tls_certificate')
		FROM secrets
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Secret
	for rows.Next() {
		var s Secret
		if err := rows.Scan(&s.ID, &s.Name, &s.CertPEM, &s.KeyPEM, &s.Kind); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
