package issuer

import (
	"context"
	"errors"
	"os"
	"testing"
)

// testStore connects to the database named by ISSUER_TEST_DATABASE_URL and
// truncates the tables. When the env var is unset the test is skipped, so the
// no-DB `go test ./...` gate stays green while the dedicated issuer CI job
// (which provisions Postgres) runs these for real.
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("ISSUER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ISSUER_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	ctx := context.Background()
	s, err := NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := s.pool.Exec(ctx, "TRUNCATE user_teams, users CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestCreateAndGetLogin(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	id, err := s.CreateUser(ctx, "a@b.com", "stored-hash", "Ada", []string{"platform", "eng"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	l, err := s.GetLogin(ctx, "a@b.com")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if l.ID != id || l.PasswordHash != "stored-hash" || l.Disabled {
		t.Fatalf("unexpected login: %+v", l)
	}
	// Teams come back ordered.
	if len(l.Teams) != 2 || l.Teams[0] != "eng" || l.Teams[1] != "platform" {
		t.Fatalf("teams wrong: %v", l.Teams)
	}
}

func TestGetLoginUnknownIsNotFound(t *testing.T) {
	s := testStore(t)
	_, err := s.GetLogin(context.Background(), "nobody@b.com")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}
}

func TestCreateUserDuplicateEmailFails(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "dup@b.com", "h", "", nil); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := s.CreateUser(ctx, "dup@b.com", "h", "", nil); err == nil {
		t.Fatal("duplicate email must fail the unique constraint")
	}
}
