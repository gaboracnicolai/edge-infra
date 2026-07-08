// Package migrate applies ordered SQL migration sets to the shared database,
// idempotently. Idempotency is by TRACKING (a schema_migrations table records
// each applied file) rather than by relying on the SQL itself being re-runnable
// — the control-plane set includes bare `ALTER TABLE ... ADD COLUMN` migrations
// that would error on a second apply. A re-run is therefore a true no-op.
package migrate

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Set is one ordered collection of *.sql files embedded from a directory. Name
// namespaces the tracking key ("cp", "osb") so files with the same number in
// different sets never collide.
type Set struct {
	Name string
	FS   embed.FS
}

// Baseline adopts the runner on a database that ALREADY has the schema but no
// schema_migrations tracking (a manually-migrated / pre-runner deploy). It
// refuses unless (a) tracking is absent/empty — otherwise the DB is already
// adopted — and (b) currentSchemaProbe returns true — proving the DB is at the
// current schema, so recording every file as applied is safe. It then RECORDS
// every migration file WITHOUT running any. A subsequent Apply is a no-op; a
// genuinely-new migration added later still applies normally. Returns the count
// recorded.
func Baseline(ctx context.Context, dsn string, sets []Set, currentSchemaProbe string) (int, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return 0, fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	// Guard 1: refuse if tracking already exists and is non-empty (already adopted).
	var tracked int
	if err := pool.QueryRow(ctx, `
		SELECT CASE WHEN to_regclass('public.schema_migrations') IS NULL THEN 0
		            ELSE (SELECT count(*) FROM schema_migrations) END`).Scan(&tracked); err != nil {
		return 0, fmt.Errorf("check existing tracking: %w", err)
	}
	if tracked > 0 {
		return 0, fmt.Errorf(
			"refusing to baseline: schema_migrations already has %d row(s) — this DB is already "+
				"adopted; use the normal runner", tracked)
	}

	// Guard 2: refuse unless the DB is at the current schema, so recording every
	// file as applied can't mask a genuinely-missing migration.
	var atCurrent bool
	if err := pool.QueryRow(ctx, "SELECT "+currentSchemaProbe).Scan(&atCurrent); err != nil {
		return 0, fmt.Errorf("current-schema probe: %w", err)
	}
	if !atCurrent {
		return 0, fmt.Errorf(
			"refusing to baseline: the database is not at the current schema (probe returned false) " +
				"— run the normal migrate instead")
	}

	// Record every file as applied WITHOUT running it.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("ensure schema_migrations: %w", err)
	}
	recorded := 0
	for _, set := range sets {
		entries, err := set.FS.ReadDir(".")
		if err != nil {
			return recorded, fmt.Errorf("read %s migrations: %w", set.Name, err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			ct, err := pool.Exec(ctx,
				`INSERT INTO schema_migrations (name) VALUES ($1) ON CONFLICT (name) DO NOTHING`,
				set.Name+"/"+name)
			if err != nil {
				return recorded, fmt.Errorf("record %s/%s: %w", set.Name, name, err)
			}
			recorded += int(ct.RowsAffected())
		}
	}
	return recorded, nil
}

// Apply runs every migration across all sets — in set order, then lexical
// filename order — skipping any already recorded in schema_migrations, each in
// its own transaction. Returns the count of migrations newly applied.
func Apply(ctx context.Context, dsn string, sets []Set) (int, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return 0, fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	// The tracking table records each applied file so a re-run skips it — this
	// is the one piece that must itself be safe to run repeatedly.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("ensure schema_migrations: %w", err)
	}

	applied := 0
	for _, set := range sets {
		entries, err := set.FS.ReadDir(".")
		if err != nil {
			return applied, fmt.Errorf("read %s migrations: %w", set.Name, err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)

		for _, name := range names {
			key := set.Name + "/" + name

			var seen bool
			if err := pool.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, key).Scan(&seen); err != nil {
				return applied, fmt.Errorf("check %s: %w", key, err)
			}
			if seen {
				continue
			}

			body, err := set.FS.ReadFile(name)
			if err != nil {
				return applied, fmt.Errorf("read %s: %w", key, err)
			}

			// Apply the file and record it in ONE transaction: either the whole
			// migration lands and is marked applied, or neither happens.
			tx, err := pool.Begin(ctx)
			if err != nil {
				return applied, fmt.Errorf("begin %s: %w", key, err)
			}
			if _, err := tx.Exec(ctx, string(body)); err != nil {
				_ = tx.Rollback(ctx)
				return applied, fmt.Errorf("apply %s: %w", key, err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO schema_migrations (name) VALUES ($1)`, key); err != nil {
				_ = tx.Rollback(ctx)
				return applied, fmt.Errorf("record %s: %w", key, err)
			}
			if err := tx.Commit(ctx); err != nil {
				return applied, fmt.Errorf("commit %s: %w", key, err)
			}
			applied++
		}
	}
	return applied, nil
}
