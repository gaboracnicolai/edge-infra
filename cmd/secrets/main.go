// Command secrets is the edge-secrets custodian: the SOLE writer of the shared
// `secrets` table (TLS cert/key material referenced by routes/gateways via SDS).
// It authenticates OPERATORS over mTLS against a SEPARATE admin CA (never the
// data-plane edge-internal-ca) with a constant-time admin-key fallback, fails
// closed, and never logs or returns key material.
//
// Usage:
//
//	secrets                                              # serve (default)
//	secrets serve                                        # serve
//	secrets put    --name N --cert c.pem --key k.pem --server https://host:8082 \
//	               [--client-cert op.pem --client-key op.key --ca admin-server-ca.pem] [--admin-key K]
//	secrets delete --name N --server https://host:8082  [mTLS flags | --admin-key K]
//
// The CLI is an mTLS HTTP CLIENT of the component — never a direct-DB writer — so
// validation always runs at the component's write chokepoint.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/edge-infra/control-plane/internal/secrets"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cmd := "serve"
	if len(os.Args) > 1 && !isFlag(os.Args[1]) {
		cmd = os.Args[1]
	}

	var err error
	switch cmd {
	case "serve":
		err = runServe(log)
	case "put":
		err = runPut(os.Args[2:])
	case "delete":
		err = runDelete(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q (want: serve | put | delete)", cmd)
	}
	if err != nil {
		log.Error("secrets exited with error", "cmd", cmd, "err", err)
		os.Exit(1)
	}
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

func runServe(log *slog.Logger) error {
	cfg, err := secrets.ConfigFromEnv()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	store, err := secrets.NewStore(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()

	httpSrv, err := secrets.NewHTTPServer(cfg, store, log)
	if err != nil {
		return err
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info("edge-secrets listening (mTLS)",
			"addr", cfg.ListenAddr, "admin_ca", cfg.AdminCAFile != "", "admin_key", cfg.AdminAPIKey != "")
		// Cert/key are already in the TLSConfig.
		if serveErr := httpSrv.ListenAndServeTLS("", ""); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErr <- serveErr
		}
		close(serverErr)
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-serverErr:
		if err != nil {
			return err
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	return httpSrv.Shutdown(shutdownCtx)
}

// --- CLI: mTLS HTTP client of the component ---------------------------------

type clientFlags struct {
	server, clientCert, clientKey, ca, adminKey string
}

func addClientFlags(fs *flag.FlagSet) *clientFlags {
	c := &clientFlags{}
	fs.StringVar(&c.server, "server", "", "edge-secrets base URL, e.g. https://edge-secrets:8082 (required)")
	fs.StringVar(&c.clientCert, "client-cert", "", "operator client cert PEM (mTLS)")
	fs.StringVar(&c.clientKey, "client-key", "", "operator client key PEM (mTLS)")
	fs.StringVar(&c.ca, "ca", "", "server CA PEM (to trust the component)")
	fs.StringVar(&c.adminKey, "admin-key", "", "admin API key (fallback auth)")
	return c
}

func (c *clientFlags) httpClient() (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if c.ca != "" {
		pem, err := os.ReadFile(c.ca)
		if err != nil {
			return nil, fmt.Errorf("read server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("server CA contained no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	if c.clientCert != "" && c.clientKey != "" {
		cert, err := tls.LoadX509KeyPair(c.clientCert, c.clientKey)
		if err != nil {
			return nil, fmt.Errorf("load operator client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

func (c *clientFlags) do(method, path string, body []byte) (*http.Response, error) {
	if c.server == "" {
		return nil, errors.New("--server is required")
	}
	client, err := c.httpClient()
	if err != nil {
		return nil, err
	}
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.server+path, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.adminKey != "" {
		req.Header.Set("X-Admin-Key", c.adminKey)
	}
	return client.Do(req)
}

func runPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ContinueOnError)
	name := fs.String("name", "", "secret name (required)")
	certFile := fs.String("cert", "", "cert PEM file (required)")
	keyFile := fs.String("key", "", "key PEM file (required)")
	cf := addClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *certFile == "" || *keyFile == "" {
		return errors.New("--name, --cert and --key are required")
	}
	cert, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	key, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"cert_pem": string(cert), "key_pem": string(key)})
	resp, err := cf.do(http.MethodPut, "/v1/secrets/"+*name, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("put failed: %s", resp.Status)
	}
	fmt.Printf("secret %q written\n", *name)
	return nil
}

func runDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	name := fs.String("name", "", "secret name (required)")
	cf := addClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	resp, err := cf.do(http.MethodDelete, "/v1/secrets/"+*name, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete failed: %s", resp.Status)
	}
	fmt.Printf("secret %q deleted\n", *name)
	return nil
}
