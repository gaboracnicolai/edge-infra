package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr        string
	PostgresDSN       string
	NodeID            string
	ReconcileInterval time.Duration
}

func FromEnv() (*Config, error) {
	c := &Config{
		ListenAddr:        getenv("XDS_LISTEN_ADDR", ":18000"),
		PostgresDSN:       os.Getenv("POSTGRES_DSN"),
		NodeID:            getenv("XDS_NODE_ID", "edge-envoy"),
		ReconcileInterval: 5 * time.Second,
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
