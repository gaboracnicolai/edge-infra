package issuer

import (
	"context"
	"os"
	"testing"
)

// TestMigrateIsIdempotentAndCreatesSchema drops the schema, migrates twice
// (must not error the second time), and confirms the resulting schema is
// usable. Skipped without ISSUER_TEST_DATABASE_URL.
func TestMigrateIsIdempotentAndCreatesSchema(t *testing.T) {
	dsn := os.Getenv("ISSUER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ISSUER_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	ctx := context.Background()

	s, err := NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := s.pool.Exec(ctx, "DROP TABLE IF EXISTS user_teams, users CASCADE"); err != nil {
		t.Fatalf("drop: %v", err)
	}
	s.Close()

	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("second migrate (idempotency): %v", err)
	}

	// Schema is usable.
	s2, err := NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer s2.Close()
	if _, err := s2.CreateUser(ctx, "migrate@b.com", "h", "", []string{"eng"}); err != nil {
		t.Fatalf("create user after migrate: %v", err)
	}
}
