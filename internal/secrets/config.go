// Package secrets is the edge-secrets custodian: the SOLE writer of the shared
// `secrets` table (TLS cert/key material referenced by routes/gateways via SDS).
// It authenticates OPERATORS over mTLS against a SEPARATE admin CA (never the
// data-plane edge-internal-ca) with a constant-time admin-key fallback, and
// fails closed. OSB stays reference-only; this component ingests key material.
package secrets

import (
	"fmt"
	"os"
)

// Config is the edge-secrets runtime configuration, sourced from the environment.
type Config struct {
	ListenAddr  string // SECRETS_LISTEN_ADDR (default :8082)
	DatabaseURL string // SECRETS_DATABASE_URL (required — the shared DB)
	TLSCertFile string // SECRETS_TLS_CERT (required — key material over the wire ⇒ TLS mandatory)
	TLSKeyFile  string // SECRETS_TLS_KEY (required, together with the cert)
	AdminCAFile string // SECRETS_ADMIN_CA — operator client CA (mTLS). NEVER the data-plane CA.
	AdminAPIKey string // SECRETS_ADMIN_API_KEY — constant-time fallback auth
	LogLevel    string // SECRETS_LOG_LEVEL (default info)
}

// ConfigFromEnv loads and validates the serving configuration. It fails closed
// on any missing required value rather than starting in a degraded state.
func ConfigFromEnv() (*Config, error) {
	required := func(k string) (string, error) {
		v := os.Getenv(k)
		if v == "" {
			return "", fmt.Errorf("missing required env var %s", k)
		}
		return v, nil
	}
	optional := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}

	cfg := &Config{
		ListenAddr: optional("SECRETS_LISTEN_ADDR", ":8082"),
		LogLevel:   optional("SECRETS_LOG_LEVEL", "info"),
	}

	var err error
	if cfg.DatabaseURL, err = required("SECRETS_DATABASE_URL"); err != nil {
		return nil, err
	}
	// TLS is mandatory — this surface ships private keys over the wire.
	if cfg.TLSCertFile, err = required("SECRETS_TLS_CERT"); err != nil {
		return nil, err
	}
	if cfg.TLSKeyFile, err = required("SECRETS_TLS_KEY"); err != nil {
		return nil, err
	}

	cfg.AdminCAFile = os.Getenv("SECRETS_ADMIN_CA")
	cfg.AdminAPIKey = os.Getenv("SECRETS_ADMIN_API_KEY")

	// Fail closed: refuse to start with NO way to authenticate an operator —
	// this surface ingests private keys.
	if cfg.AdminCAFile == "" && cfg.AdminAPIKey == "" {
		return nil, fmt.Errorf(
			"no auth configured: set SECRETS_ADMIN_CA (operator mTLS) and/or SECRETS_ADMIN_API_KEY")
	}

	return cfg, nil
}
