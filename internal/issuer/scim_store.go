package issuer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrUserExists is returned when a SCIM create or replace would give a second
// user the same email (SCIM's "uniqueness" error).
var ErrUserExists = errors.New("user already exists")

// SCIMUser is a user as SCIM sees it: the users row without its credentials.
// UserName is the user's email — the key OIDC sign-in matches on. SCIM sees
// only the users it created (scim_managed); an email held by an operator's
// password account is ErrUserExists to it.
type SCIMUser struct {
	ID          string
	UserName    string
	DisplayName string
	ExternalID  string
	Active      bool
	Created     time.Time
	Updated     time.Time
}

const scimColumns = `id, email, display_name, COALESCE(external_id, ''), disabled_at IS NULL, created_at, updated_at`

func scanSCIMUser(row pgx.Row) (*SCIMUser, error) {
	var u SCIMUser
	err := row.Scan(&u.ID, &u.UserName, &u.DisplayName, &u.ExternalID, &u.Active, &u.Created, &u.Updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// ListSCIMUsers returns one page of users and the total count. attr is "" (no
// filter), "userName" (case-insensitive) or "externalId" — the two equality
// filters IdPs send before they create a user.
func (s *Store) ListSCIMUsers(ctx context.Context, attr, value string, offset, limit int) ([]SCIMUser, int, error) {
	where, args := "scim_managed", []any{}
	switch attr {
	case "":
	case "userName":
		where, args = "scim_managed AND lower(email) = lower($1)", []any{value}
	case "externalId":
		where, args = "scim_managed AND external_id = $1", []any{value}
	default:
		return nil, 0, fmt.Errorf("unsupported filter attribute %q", attr)
	}

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	n := len(args)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM users WHERE %s ORDER BY created_at, id OFFSET $%d LIMIT $%d`,
		scimColumns, where, n+1, n+2), append(args, offset, limit)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var out []SCIMUser
	for rows.Next() {
		u, err := scanSCIMUser(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, *u)
	}
	return out, total, rows.Err()
}

// GetSCIMUser fetches one user by id, or ErrUserNotFound.
func (s *Store) GetSCIMUser(ctx context.Context, id string) (*SCIMUser, error) {
	return scanSCIMUser(s.pool.QueryRow(ctx, `SELECT `+scimColumns+` FROM users WHERE id = $1 AND scim_managed`, id))
}

// CreateSCIMUser inserts a password-less user (OIDC sign-in only). An email
// already held by any user, in any letter case, is ErrUserExists.
func (s *Store) CreateSCIMUser(ctx context.Context, u SCIMUser) (*SCIMUser, error) {
	created, err := scanSCIMUser(s.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, display_name, external_id, disabled_at, scim_managed)
		SELECT lower($1), '', $2, NULLIF($3, ''), CASE WHEN $4::bool THEN NULL ELSE now() END, true
		WHERE NOT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1))
		RETURNING `+scimColumns, u.UserName, u.DisplayName, u.ExternalID, u.Active))
	if errors.Is(err, ErrUserNotFound) || isUniqueViolation(err) {
		return nil, ErrUserExists
	}
	return created, err
}

// ReplaceSCIMUser overwrites a user's SCIM attributes. Deactivating sets
// disabled_at (no new tokens, by OIDC or password); reactivating clears it.
func (s *Store) ReplaceSCIMUser(ctx context.Context, id string, u SCIMUser) (*SCIMUser, error) {
	updated, err := scanSCIMUser(s.pool.QueryRow(ctx, `
		UPDATE users SET
			email        = lower($2),
			display_name = $3,
			external_id  = NULLIF($4, ''),
			disabled_at  = CASE WHEN $5::bool THEN NULL ELSE COALESCE(disabled_at, now()) END,
			updated_at   = now()
		WHERE id = $1 AND scim_managed
		  AND NOT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($2) AND id <> $1)
		RETURNING `+scimColumns, id, u.UserName, u.DisplayName, u.ExternalID, u.Active))
	if isUniqueViolation(err) {
		return nil, ErrUserExists
	}
	if errors.Is(err, ErrUserNotFound) {
		// Either no such id, or the new email belongs to someone else.
		if _, getErr := s.GetSCIMUser(ctx, id); getErr == nil {
			return nil, ErrUserExists
		}
	}
	return updated, err
}

// DeleteSCIMUser removes a user and its team memberships.
func (s *Store) DeleteSCIMUser(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1 AND scim_managed`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// GetLoginByEmail finds the SCIM-provisioned user an OIDC sign-in names,
// matched case-insensitively (an IdP may send the email in a different case
// than SCIM provisioned it). A password account is never returned: it signs
// in through /login only. Two matches are ambiguous: ErrUserNotFound.
func (s *Store) GetLoginByEmail(ctx context.Context, email string) (*Login, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, email, password_hash, disabled_at
		FROM users
		WHERE lower(email) = lower($1) AND scim_managed
		LIMIT 2
	`, email)
	if err != nil {
		return nil, fmt.Errorf("query user: %w", err)
	}
	var found []Login
	for rows.Next() {
		var l Login
		var disabledAt *time.Time
		if err := rows.Scan(&l.ID, &l.Email, &l.PasswordHash, &disabledAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan user: %w", err)
		}
		l.Disabled = disabledAt != nil
		found = append(found, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query user: %w", err)
	}
	if len(found) != 1 {
		return nil, ErrUserNotFound
	}
	l := found[0]
	if l.Teams, err = s.teams(ctx, l.ID); err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *Store) teams(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT team FROM user_teams WHERE user_id = $1 ORDER BY team`, userID)
	if err != nil {
		return nil, fmt.Errorf("query teams: %w", err)
	}
	defer rows.Close()
	var teams []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("scan team: %w", err)
		}
		teams = append(teams, t)
	}
	return teams, rows.Err()
}
