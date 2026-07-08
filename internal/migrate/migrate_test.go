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
