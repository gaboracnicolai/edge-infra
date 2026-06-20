// Command issuer is the Talyvor token-issuer: it authenticates users from its
// own store and mints RS256 JWTs that the edge auth-service validates, and
// serves the JWKS the auth-service fetches.
//
// Usage:
//
//	issuer            # serve (default)
//	issuer serve      # serve
//	issuer adduser --email a@b.com --password '...' [--display-name N] [--team eng --team platform]
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/edge-infra/control-plane/internal/issuer"
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
	case "adduser":
		err = runAddUser(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q (want: serve | adduser)", cmd)
	}
	if err != nil {
		log.Error("issuer exited with error", "cmd", cmd, "err", err)
		os.Exit(1)
	}
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

func runServe(log *slog.Logger) error {
	cfg, err := issuer.ConfigFromEnv()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	store, err := issuer.NewStore(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()

	keys, err := issuer.LoadKeySet(cfg.KeysDir, cfg.ActiveKID)
	if err != nil {
		return err
	}
	minter := issuer.NewMinter(keys, cfg.IssuerURL, cfg.Audience, cfg.TokenTTL)
	srv := issuer.NewServer(store, minter, keys, log)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if cfg.TLSCertFile != "" {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info("issuer listening",
			"addr", cfg.ListenAddr, "tls", cfg.TLSCertFile != "", "active_kid", cfg.ActiveKID)
		var serveErr error
		if cfg.TLSCertFile != "" {
			serveErr = httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			log.Warn("issuer serving WITHOUT TLS — set ISSUER_TLS_CERT/ISSUER_TLS_KEY; the auth-service requires https for JWKS")
			serveErr = httpSrv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
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

// teamList collects repeated --team flags.
type teamList []string

func (t *teamList) String() string { return fmt.Sprintf("%v", []string(*t)) }
func (t *teamList) Set(v string) error {
	*t = append(*t, v)
	return nil
}

func runAddUser(args []string) error {
	fs := flag.NewFlagSet("adduser", flag.ContinueOnError)
	email := fs.String("email", "", "user email (required)")
	password := fs.String("password", "", "user password (required)")
	displayName := fs.String("display-name", "", "display name")
	var teams teamList
	fs.Var(&teams, "team", "team membership (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" || *password == "" {
		return errors.New("--email and --password are required")
	}

	dsn := os.Getenv("ISSUER_DATABASE_URL")
	if dsn == "" {
		return errors.New("ISSUER_DATABASE_URL must be set")
	}

	hash, err := issuer.HashPassword(*password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store, err := issuer.NewStore(ctx, dsn)
	if err != nil {
		return err
	}
	defer store.Close()

	id, err := store.CreateUser(ctx, *email, hash, *displayName, teams)
	if err != nil {
		return err
	}
	fmt.Printf("created user %s (%s)\n", id, *email)
	return nil
}
