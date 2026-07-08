package secrets

import (
	"log/slog"
	"net/http"
	"time"
)

// NewHTTPServer builds the mTLS HTTP server for the secrets API: operator auth
// (mTLS against the admin CA + admin-key fallback), server cert from config.
// The cert/key live in the returned server's TLSConfig, so serve it with
// ListenAndServeTLS("", "").
func NewHTTPServer(cfg *Config, store SecretStore, log *slog.Logger) (*http.Server, error) {
	tlsCfg, err := buildServerTLS(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           NewServer(store, cfg.AdminAPIKey, log).Routes(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
}
