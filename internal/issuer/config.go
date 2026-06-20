package issuer

import (
	"fmt"
	"os"
	"time"
)

// Config is the issuer's runtime configuration, sourced from the environment.
type Config struct {
	ListenAddr  string        // ISSUER_LISTEN_ADDR (default :8081)
	DatabaseURL string        // ISSUER_DATABASE_URL (required)
	IssuerURL   string        // ISSUER_URL — the `iss` claim (required)
	Audience    string        // ISSUER_AUDIENCE — the `aud` claim (required)
	TokenTTL    time.Duration // ISSUER_TOKEN_TTL (default 1h)
	KeysDir     string        // ISSUER_KEYS_DIR — dir of <kid>.pem (required)
	ActiveKID   string        // ISSUER_ACTIVE_KID — signer (required)
	TLSCertFile string        // ISSUER_TLS_CERT (optional)
	TLSKeyFile  string        // ISSUER_TLS_KEY (optional)
	LogLevel    string        // ISSUER_LOG_LEVEL (default info)
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
		ListenAddr: optional("ISSUER_LISTEN_ADDR", ":8081"),
		LogLevel:   optional("ISSUER_LOG_LEVEL", "info"),
	}

	var err error
	if cfg.DatabaseURL, err = required("ISSUER_DATABASE_URL"); err != nil {
		return nil, err
	}
	if cfg.IssuerURL, err = required("ISSUER_URL"); err != nil {
		return nil, err
	}
	if cfg.Audience, err = required("ISSUER_AUDIENCE"); err != nil {
		return nil, err
	}
	if cfg.KeysDir, err = required("ISSUER_KEYS_DIR"); err != nil {
		return nil, err
	}
	if cfg.ActiveKID, err = required("ISSUER_ACTIVE_KID"); err != nil {
		return nil, err
	}

	ttl := optional("ISSUER_TOKEN_TTL", "1h")
	if cfg.TokenTTL, err = time.ParseDuration(ttl); err != nil {
		return nil, fmt.Errorf("ISSUER_TOKEN_TTL: %w", err)
	}

	cfg.TLSCertFile = os.Getenv("ISSUER_TLS_CERT")
	cfg.TLSKeyFile = os.Getenv("ISSUER_TLS_KEY")
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, fmt.Errorf("ISSUER_TLS_CERT and ISSUER_TLS_KEY must be set together")
	}

	return cfg, nil
}
