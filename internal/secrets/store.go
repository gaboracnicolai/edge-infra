package secrets

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrSecretNotFound is returned by GetMeta when no secret matches the name.
var ErrSecretNotFound = errors.New("secret not found")

// SecretMeta is the safe-to-return metadata about a stored secret — NEVER key
// bytes: the cert fingerprint and expiry, used to verify a rotation landed.
type SecretMeta struct {
	Name        string
	Fingerprint string // SHA-256 of the cert DER, hex
	NotAfter    time.Time
}

// SecretStore is the write/metadata surface the HTTP layer needs. An interface
// so handlers are testable against a fake without a database.
type SecretStore interface {
	Upsert(ctx context.Context, name, certPEM, keyPEM string) error
	Delete(ctx context.Context, name string) (bool, error)
	GetMeta(ctx context.Context, name string) (*SecretMeta, error)
	Ping(ctx context.Context) error
}

// Store is the SOLE production writer of the shared `secrets` table.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore opens a pgxpool against the shared DB and verifies connectivity.
func NewStore(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pg config: %w", err)
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
	return &Store{pool: pool}, nil
}

// Close releases all pooled connections.
func (s *Store) Close() { s.pool.Close() }

// Ping reports database reachability for readiness checks.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Upsert writes (or rotates) a secret by name — the only production write path
// to `secrets`. The id mirrors the name (the scheme controller/OSB rows use).
func (s *Store) Upsert(ctx context.Context, name, certPEM, keyPEM string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO secrets (id, name, cert_pem, key_pem)
		VALUES ($1, $1, $2, $3)
		ON CONFLICT (name) DO UPDATE SET
			cert_pem   = EXCLUDED.cert_pem,
			key_pem    = EXCLUDED.key_pem,
			updated_at = now()
	`, name, certPEM, keyPEM)
	return err
}

// Delete decommissions a secret. Reports whether a row was removed.
func (s *Store) Delete(ctx context.Context, name string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM secrets WHERE name = $1`, name)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// GetMeta returns metadata (fingerprint + notAfter) — NEVER the key material.
func (s *Store) GetMeta(ctx context.Context, name string) (*SecretMeta, error) {
	var certPEM string
	err := s.pool.QueryRow(ctx, `SELECT cert_pem FROM secrets WHERE name = $1`, name).Scan(&certPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSecretNotFound
	}
	if err != nil {
		return nil, err
	}
	fp, notAfter, err := certMeta(certPEM)
	if err != nil {
		return nil, err
	}
	return &SecretMeta{Name: name, Fingerprint: fp, NotAfter: notAfter}, nil
}

// certMeta parses a cert PEM and returns its SHA-256 fingerprint + notAfter.
func certMeta(certPEM string) (string, time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", time.Time{}, errors.New("no PEM block in cert")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, err
	}
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:]), c.NotAfter, nil
}
