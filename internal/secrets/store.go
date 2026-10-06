package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/edge-infra/control-plane/internal/keycrypt"

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
	// Upsert writes a secret by name. kind is "tls_certificate" (keyPEM is the
	// matching key) or "validation_context" (a cert-only CA bundle; keyPEM "").
	Upsert(ctx context.Context, name, certPEM, keyPEM, kind string) error
	Delete(ctx context.Context, name string) (bool, error)
	GetMeta(ctx context.Context, name string) (*SecretMeta, error)
	// Reseal re-seals every stored key under the current KEK (KEK rotation).
	Reseal(ctx context.Context) (ResealResult, error)
	Ping(ctx context.Context) error
}

// ResealResult reports a re-seal: the KEK every key is now sealed under, how
// many keys were re-sealed, and how many already were under it.
type ResealResult struct {
	KeyID          string
	Resealed       int
	AlreadyCurrent int
}

// Store is the SOLE production writer of the shared `secrets` table.
type Store struct {
	pool *pgxpool.Pool
	ring *keycrypt.Keyring // nil ⇒ encryption disabled (key_pem stored as plaintext)
}

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithKEK seals key material at rest under kek (AES-256-GCM). A nil kek leaves
// keys as plaintext (encryption disabled).
func WithKEK(kek []byte) StoreOption { return WithKeyring(keycrypt.NewKeyring(kek)) }

// WithKeyring seals under the keyring's current KEK and opens keys sealed
// under any KEK it holds — what Reseal needs during a rotation.
func WithKeyring(r *keycrypt.Keyring) StoreOption { return func(s *Store) { s.ring = r } }

// NewStore opens a pgxpool against the shared DB and verifies connectivity.
func NewStore(ctx context.Context, dsn string, opts ...StoreOption) (*Store, error) {
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
	s := &Store{pool: pool}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Close releases all pooled connections.
func (s *Store) Close() { s.pool.Close() }

// Ping reports database reachability for readiness checks.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Upsert writes (or rotates) a secret by name — the only production write path
// to `secrets`. The id mirrors the name (the scheme controller/OSB rows use).
func (s *Store) Upsert(ctx context.Context, name, certPEM, keyPEM, kind string) error {
	// Seal a real key at rest (AES-256-GCM under the KEK); a CA bundle's empty key
	// is left empty so NULLIF stores SQL NULL. A nil KEK is passthrough (plaintext).
	if keyPEM != "" {
		sealed, sErr := s.ring.Seal(keyPEM)
		if sErr != nil {
			return fmt.Errorf("seal key: %w", sErr)
		}
		keyPEM = sealed
	}
	// NULLIF stores a CA bundle's empty key as SQL NULL; a server cert's real key
	// (never empty — validated upstream) is stored as (sealed) ciphertext.
	_, err := s.pool.Exec(ctx, `
		INSERT INTO secrets (id, name, cert_pem, key_pem, kind)
		VALUES ($1, $1, $2, NULLIF($3, ''), $4)
		ON CONFLICT (name) DO UPDATE SET
			cert_pem   = EXCLUDED.cert_pem,
			key_pem    = EXCLUDED.key_pem,
			kind       = EXCLUDED.kind,
			updated_at = now()
	`, name, certPEM, keyPEM, kind)
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

// Reseal re-seals every stored key under the current KEK, in one transaction.
// A key under a previous KEK, in the legacy enc:v1 format, or still plaintext
// from before encryption is opened with the keyring and sealed again; a key
// already under the current KEK is left alone. The key itself never changes, so
// SDS serves the same material throughout; afterwards the previous KEKs can be
// dropped. A key no KEK held can open aborts the whole re-seal, naming it.
func (s *Store) Reseal(ctx context.Context) (ResealResult, error) {
	if s.ring == nil {
		return ResealResult{}, errors.New("no KEK configured to re-seal under")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ResealResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx,
		`SELECT name, key_pem FROM secrets WHERE key_pem IS NOT NULL AND key_pem <> '' ORDER BY name FOR UPDATE`)
	if err != nil {
		return ResealResult{}, err
	}
	type row struct{ name, key string }
	var keys []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.name, &r.key); err != nil {
			rows.Close()
			return ResealResult{}, err
		}
		keys = append(keys, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ResealResult{}, err
	}

	res := ResealResult{KeyID: s.ring.KeyID()}
	for _, r := range keys {
		if s.ring.IsCurrent(r.key) {
			res.AlreadyCurrent++
			continue
		}
		pt, err := s.ring.Open(r.key)
		if err != nil {
			return ResealResult{}, fmt.Errorf("secret %q: %w", r.name, err)
		}
		sealed, err := s.ring.Seal(pt)
		if err != nil {
			return ResealResult{}, fmt.Errorf("secret %q: seal: %w", r.name, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE secrets SET key_pem = $2 WHERE name = $1`, r.name, sealed); err != nil {
			return ResealResult{}, err
		}
		res.Resealed++
	}
	return res, tx.Commit(ctx)
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
// Composes ParseCertInfo (certinfo.go) so GetMeta and the control-plane Admin
// API's /admin/v1/certificates describe a certificate identically, forever.
func certMeta(certPEM string) (string, time.Time, error) {
	info, err := ParseCertInfo(certPEM)
	if err != nil {
		return "", time.Time{}, err
	}
	return info.Fingerprint, info.NotAfter, nil
}
