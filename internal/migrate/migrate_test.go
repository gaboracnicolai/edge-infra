//go:build integration

package migrate_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/edge-infra/control-plane/internal/migrate"
	cpmig "github.com/edge-infra/control-plane/migrations"
	osbmig "github.com/edge-infra/control-plane/osb/migrations"
)

// TestApply_FreshDBIdempotent applies both migration sets to a pristine database
// twice. The first run creates the full schema and records every file; the second
// is a no-op (0 new). This proves the tracking runner is safe to re-run even
// though the control-plane set has non-idempotent `ALTER TABLE ADD COLUMN`
// migrations (0006/0007) that would error on a second raw apply.
func TestApply_FreshDBIdempotent(t *testing.T) {
	dsn := os.Getenv("MIGRATE_TEST_DSN")
	if dsn == "" {
		t.Skip("MIGRATE_TEST_DSN required (a throwaway DB — the test resets the public schema)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	conn.Close(ctx)

	sets := []migrate.Set{
		{Name: "cp", FS: cpmig.FS},
		{Name: "osb", FS: osbmig.FS},
	}

	// First apply creates everything.
	n1, err := migrate.Apply(ctx, dsn, sets)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if n1 == 0 {
		t.Fatalf("first apply: applied 0 migrations; want >0 on a fresh DB")
	}

	// Second apply is a no-op — every file already tracked.
	n2, err := migrate.Apply(ctx, dsn, sets)
	if err != nil {
		t.Fatalf("second apply (idempotency): %v", err)
	}
	if n2 != 0 {
		t.Errorf("second apply: applied %d; want 0 (a re-run must be a no-op)", n2)
	}

	// The schema is present: control-plane tables AND the OSB table both exist.
	conn2, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close(ctx)
	for _, tbl := range []string{"gateways", "routes", "secrets", "clusters", "endpoints", "services"} {
		var exists bool
		if err := conn2.QueryRow(ctx,
			"SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name=$1)", tbl).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("table %q missing after migrate", tbl)
		}
	}

	// Every applied file is recorded (so re-runs can skip them).
	var count int
	if err := conn2.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	if count != n1 {
		t.Errorf("schema_migrations has %d rows; want %d (all applied files)", count, n1)
	}
}

func resetSchema(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
}

func truncateTracking(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "TRUNCATE schema_migrations"); err != nil {
		t.Fatalf("truncate tracking: %v", err)
	}
}

var baselineSets = []migrate.Set{
	{Name: "cp", FS: cpmig.FS},
	{Name: "osb", FS: osbmig.FS},
}

// dead_letter (OSB 0003) is the latest migration — its presence stands in for
// "the DB is at the current schema".
const currentSchemaProbe = "to_regclass('public.dead_letter') IS NOT NULL"

// A DB with the full schema but NO tracking (manually migrated) is adopted:
// baseline records every file (running none), after which a normal migrate is a
// no-op.
func TestBaseline_AdoptsUntrackedSchema(t *testing.T) {
	dsn := os.Getenv("MIGRATE_TEST_DSN")
	if dsn == "" {
		t.Skip("MIGRATE_TEST_DSN required (a throwaway DB)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resetSchema(t, ctx, dsn)
	if _, err := migrate.Apply(ctx, dsn, baselineSets); err != nil {
		t.Fatal(err)
	}
	truncateTracking(t, ctx, dsn) // simulate a pre-runner, untracked deploy

	n, err := migrate.Baseline(ctx, dsn, baselineSets, currentSchemaProbe)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if n == 0 {
		t.Fatal("baseline must record the already-applied files")
	}
	applied, err := migrate.Apply(ctx, dsn, baselineSets)
	if err != nil {
		t.Fatalf("post-baseline migrate: %v", err)
	}
	if applied != 0 {
		t.Errorf("after baseline, a normal migrate must be a no-op; applied %d", applied)
	}
}

// Baseline refuses a DB that is NOT at the current schema — never marks a
// migration applied whose effect is absent.
func TestBaseline_RefusesWhenBehind(t *testing.T) {
	dsn := os.Getenv("MIGRATE_TEST_DSN")
	if dsn == "" {
		t.Skip("MIGRATE_TEST_DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resetSchema(t, ctx, dsn)
	// Apply ONLY the control-plane set — no OSB dead_letter → probe is false.
	if _, err := migrate.Apply(ctx, dsn, []migrate.Set{{Name: "cp", FS: cpmig.FS}}); err != nil {
		t.Fatal(err)
	}
	truncateTracking(t, ctx, dsn)
	if _, err := migrate.Baseline(ctx, dsn, baselineSets, currentSchemaProbe); err == nil {
		t.Error("baseline must refuse when the DB is not at the current schema")
	}
}

// Baseline refuses a DB that already has tracking (already adopted).
func TestBaseline_RefusesWhenAlreadyTracked(t *testing.T) {
	dsn := os.Getenv("MIGRATE_TEST_DSN")
	if dsn == "" {
		t.Skip("MIGRATE_TEST_DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resetSchema(t, ctx, dsn)
	if _, err := migrate.Apply(ctx, dsn, baselineSets); err != nil { // tracking populated
		t.Fatal(err)
	}
	if _, err := migrate.Baseline(ctx, dsn, baselineSets, currentSchemaProbe); err == nil {
		t.Error("baseline must refuse a DB that already has schema_migrations tracking")
	}
}
