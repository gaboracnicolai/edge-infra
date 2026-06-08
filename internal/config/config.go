package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr        string
	HealthAddr        string
	PostgresDSN       string
	NodeID            string
	ReconcileInterval time.Duration

	// HA — all optional. When RedisAddr is empty the server runs in
	// single-instance mode with local in-process state.
	RedisAddr     string
	RedisPassword string
	InstanceID    string // unique per replica; defaults to POD_NAME or a random ID

	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string
}

func FromEnv() (*Config, error) {
	c := &Config{
		ListenAddr:        getenv("XDS_LISTEN_ADDR", ":18000"),
		HealthAddr:        getenv("XDS_HEALTH_ADDR", ":18001"),
		PostgresDSN:       os.Getenv("POSTGRES_DSN"),
		NodeID:            getenv("XDS_NODE_ID", "edge-envoy"),
		ReconcileInterval: 5 * time.Second,
		RedisAddr:         os.Getenv("REDIS_ADDR"),
		RedisPassword:     os.Getenv("REDIS_PASSWORD"),
		InstanceID:        getenv("XDS_INSTANCE_ID", getenv("POD_NAME", randomID())),
		TLSCertFile:       os.Getenv("XDS_TLS_CERT"),
		TLSKeyFile:        os.Getenv("XDS_TLS_KEY"),
		TLSCAFile:         os.Getenv("XDS_TLS_CA"),
	}
	if c.PostgresDSN == "" {
		return nil, fmt.Errorf("POSTGRES_DSN is required")
	}
	if v := os.Getenv("XDS_RECONCILE_INTERVAL_MS"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("XDS_RECONCILE_INTERVAL_MS: %w", err)
		}
		c.ReconcileInterval = time.Duration(ms) * time.Millisecond
	}
	return c, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
