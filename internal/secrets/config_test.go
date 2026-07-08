package secrets

import "testing"

// FAIL-CLOSED: with a DB and server TLS but NEITHER an admin CA nor an admin key
// (no auth mechanism), the component must refuse to start.
func TestConfigFromEnv_FailClosed_NoAuth(t *testing.T) {
	t.Setenv("SECRETS_DATABASE_URL", "postgres://x")
	t.Setenv("SECRETS_TLS_CERT", "/c")
	t.Setenv("SECRETS_TLS_KEY", "/k")
	t.Setenv("SECRETS_ADMIN_CA", "")
	t.Setenv("SECRETS_ADMIN_API_KEY", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("no auth (no admin CA, no admin key) must fail closed — refuse to start")
	}
}

func TestConfigFromEnv_OK_WithAdminCA(t *testing.T) {
	t.Setenv("SECRETS_DATABASE_URL", "postgres://x")
	t.Setenv("SECRETS_TLS_CERT", "/c")
	t.Setenv("SECRETS_TLS_KEY", "/k")
	t.Setenv("SECRETS_ADMIN_CA", "/ca")
	t.Setenv("SECRETS_ADMIN_API_KEY", "")
	if _, err := ConfigFromEnv(); err != nil {
		t.Fatalf("admin CA configured must start: %v", err)
	}
}

// TLS is mandatory — key material ships over the wire.
func TestConfigFromEnv_FailClosed_NoTLS(t *testing.T) {
	t.Setenv("SECRETS_DATABASE_URL", "postgres://x")
	t.Setenv("SECRETS_TLS_CERT", "")
	t.Setenv("SECRETS_TLS_KEY", "")
	t.Setenv("SECRETS_ADMIN_API_KEY", "k")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("no server TLS must fail closed (key material over the wire)")
	}
}
