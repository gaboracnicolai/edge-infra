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

	// Gateway rate limiting (Envoy local_ratelimit, a per-listener token
	// bucket served via LDS). Fail-open by design: unlike auth, a limiter
	// problem must never block traffic. Per Envoy instance.
	RateLimitEnabled       bool
	RateLimitMaxTokens     uint32        // burst size
	RateLimitTokensPerFill uint32        // tokens added each fill interval
	RateLimitFillInterval  time.Duration // refill period (must be > 0)
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

	c.RateLimitEnabled = getenvBool("GW_RATELIMIT_ENABLED", true)
	c.RateLimitMaxTokens = getenvU32("GW_RATELIMIT_MAX_TOKENS", 200)
	c.RateLimitTokensPerFill = getenvU32("GW_RATELIMIT_TOKENS_PER_FILL", 100)
	fillMS := getenvU32("GW_RATELIMIT_FILL_INTERVAL_MS", 1000)
	if fillMS == 0 {
		fillMS = 1000 // Envoy requires fill_interval > 0
	}
	c.RateLimitFillInterval = time.Duration(fillMS) * time.Millisecond

	return c, nil
}

func getenvBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getenvU32(k string, def uint32) uint32 {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return def
	}
	return uint32(n)
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
