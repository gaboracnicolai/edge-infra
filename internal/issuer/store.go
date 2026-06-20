package issuer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrUserNotFound is returned by GetLogin when no user matches the email.
// Callers must treat it identically to a bad password (no user enumeration).
var ErrUserNotFound = errors.New("user not found")

// Store is the issuer's user store backed by its own Postgres pool.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore opens a pgxpool and verifies connectivity.
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

// Login is the subset of a user needed to authenticate and mint a token.
type Login struct {
	ID           string
	Email        string
	PasswordHash string
	Disabled     bool
	Teams        []string
}

// GetLogin fetches the login record for email, including team memberships.
// Returns ErrUserNotFound when the email is unknown.
func (s *Store) GetLogin(ctx context.Context, email string) (*Login, error) {
	var l Login
	var disabledAt *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT id, email, password_hash, disabled_at
		FROM users
		WHERE email = $1
	`, email).Scan(&l.ID, &l.Email, &l.PasswordHash, &disabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query user: %w", err)
	}
	l.Disabled = disabledAt != nil

	rows, err := s.pool.Query(ctx, `SELECT team FROM user_teams WHERE user_id = $1 ORDER BY team`, l.ID)
	if err != nil {
		return nil, fmt.Errorf("query teams: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("scan team: %w", err)
		}
		l.Teams = append(l.Teams, t)
	}
	return &l, rows.Err()
}

// CreateUser inserts a user and its team memberships in one transaction and
// returns the new id. Used by the `issuer adduser` CLI.
func (s *Store) CreateUser(ctx context.Context, email, passwordHash, displayName string, teams []string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful commit

	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, display_name)
		VALUES ($1, $2, $3)
		RETURNING id
	`, email, passwordHash, displayName).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert user: %w", err)
	}

	for _, t := range teams {
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_teams (user_id, team) VALUES ($1, $2)
			ON CONFLICT DO NOTHING
		`, id, t); err != nil {
			return "", fmt.Errorf("insert team %q: %w", t, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}
	return id, nil
}
