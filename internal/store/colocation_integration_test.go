//go:build integration

package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/edge-infra/control-plane/internal/migrate"
	"github.com/edge-infra/control-plane/internal/store"
	cpmig "github.com/edge-infra/control-plane/migrations"
	osbmig "github.com/edge-infra/control-plane/osb/migrations"
)

// TestVerifyColocation asserts the fail-closed co-location self-check: a DB with
// ONLY the control-plane schema (OSB pointed elsewhere) is rejected; a DB with
// BOTH schemas (the shared, co-located DB) is accepted.
func TestVerifyColocation(t *testing.T) {
	dsn := os.Getenv("COLOCATION_TEST_DSN")
	if dsn == "" {
		t.Skip("COLOCATION_TEST_DSN required (a throwaway DB — the test resets the public schema)")
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

	// Control-plane schema ONLY → not co-located → must be rejected.
	if _, err := migrate.Apply(ctx, dsn, []migrate.Set{{Name: "cp", FS: cpmig.FS}}); err != nil {
		t.Fatalf("apply cp migrations: %v", err)
	}
	st, err := store.NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyColocation(ctx); err == nil {
		t.Error("a DB with only the control-plane schema must FAIL the co-location check")
	}
	st.Close()

	// Add the OSB schema → both present → co-located → accepted.
	if _, err := migrate.Apply(ctx, dsn, []migrate.Set{{Name: "osb", FS: osbmig.FS}}); err != nil {
		t.Fatalf("apply osb migrations: %v", err)
	}
	st2, err := store.NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if err := st2.VerifyColocation(ctx); err != nil {
		t.Errorf("a DB with both schemas (co-located) must PASS; got %v", err)
	}
}
