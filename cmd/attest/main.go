// Command attest is the confidential-compute attestation gate (B27.34).
//
// Usage:
//
//	attest gate            # init container: verify a fresh report, exit 0; refuse with exit 1
//	attest mock-attester   # a stand-in TEE attester that signs reports (kind / tests only)
//	attest keygen          # print a mock attester key pair as JSON
//
// gate reads ATTEST_EVIDENCE_URL, ATTEST_TRUSTED_KEY (base64 ed25519 public key),
// ATTEST_MEASUREMENTS (comma-separated hex), ATTEST_MAX_AGE and ATTEST_TIMEOUT.
// mock-attester reads MOCK_ATTESTER_KEY (base64 ed25519 seed), MOCK_MEASUREMENT
// and LISTEN_ADDR (default :8006).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/edge-infra/control-plane/internal/attest"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "gate":
		err = runGate(log)
	case "mock-attester":
		err = runMockAttester(log)
	case "keygen":
		err = runKeygen()
	default:
		err = fmt.Errorf("unknown command %q (want: gate | mock-attester | keygen)", cmd)
	}
	if err != nil {
		os.Exit(1)
	}
}

func runGate(log *slog.Logger) error {
	refuse := func(reason string) error {
		log.Error("attestation REFUSED — the workload will not start", "reason", reason)
		// Surfaces in the pod's status (lastState.terminated.message).
		_ = os.WriteFile("/dev/termination-log", []byte("attestation REFUSED: "+reason), 0o644)
		return errors.New(reason)
	}

	evidenceURL := os.Getenv("ATTEST_EVIDENCE_URL")
	if evidenceURL == "" {
		return refuse("ATTEST_EVIDENCE_URL is not set")
	}
	pub, err := base64.StdEncoding.DecodeString(os.Getenv("ATTEST_TRUSTED_KEY"))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return refuse("ATTEST_TRUSTED_KEY is not a base64 ed25519 public key")
	}
	var measurements []string
	for _, m := range strings.Split(os.Getenv("ATTEST_MEASUREMENTS"), ",") {
		if m = strings.TrimSpace(m); m != "" {
			measurements = append(measurements, m)
		}
	}
	if len(measurements) == 0 {
		return refuse("ATTEST_MEASUREMENTS is empty — no launch measurement is allowed to start")
	}
	maxAge, err := durationEnv("ATTEST_MAX_AGE", 5*time.Minute)
	if err != nil {
		return refuse(err.Error())
	}
	timeout, err := durationEnv("ATTEST_TIMEOUT", 30*time.Second)
	if err != nil {
		return refuse(err.Error())
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return refuse("no randomness for the nonce: " + err.Error())
	}

	// The attester may come up after this pod, so a failed fetch is retried until
	// the timeout; a report that arrives and does not verify is refused at once.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := &http.Client{Timeout: 5 * time.Second}
	var ev attest.Evidence
	for {
		ev, err = attest.Fetch(ctx, client, evidenceURL, nonce)
		if err == nil {
			break
		}
		log.Warn("no attestation report yet", "url", evidenceURL, "err", err.Error())
		select {
		case <-ctx.Done():
			return refuse(fmt.Sprintf("no attestation report from %s within %s: %v", evidenceURL, timeout, err))
		case <-time.After(2 * time.Second):
		}
	}

	r, err := attest.Verify(ev, nonce, attest.Policy{TrustedKey: pub, Measurements: measurements, MaxAge: maxAge}, time.Now())
	if err != nil {
		return refuse(err.Error())
	}
	log.Info("attestation verified — starting the workload", "tee", r.TEE, "measurement", r.Measurement, "issued_at", r.IssuedAt)
	return nil
}

func runMockAttester(log *slog.Logger) error {
	seed, err := base64.StdEncoding.DecodeString(os.Getenv("MOCK_ATTESTER_KEY"))
	if err != nil || len(seed) != ed25519.SeedSize {
		log.Error("MOCK_ATTESTER_KEY is not a base64 ed25519 seed")
		return errors.New("bad key")
	}
	key := ed25519.NewKeyFromSeed(seed)
	measurement := os.Getenv("MOCK_MEASUREMENT")
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8006"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /aa/evidence", func(w http.ResponseWriter, req *http.Request) {
		nonce := req.URL.Query().Get("runtime_data")
		if _, err := hex.DecodeString(nonce); err != nil || nonce == "" {
			http.Error(w, "runtime_data must be hex", http.StatusBadRequest)
			return
		}
		ev, err := attest.Sign(attest.Report{TEE: attest.TEEMock, Measurement: measurement, ReportData: nonce, IssuedAt: time.Now().UTC()}, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Info("issued a mock report", "measurement", measurement, "remote", req.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ev)
	})
	log.Info("mock attester listening — not a TEE, for kind and tests only", "addr", addr,
		"public_key", base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}

func runKeygen() error {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{
		"private_key": base64.StdEncoding.EncodeToString(key.Seed()),
		"public_key":  base64.StdEncoding.EncodeToString(pub),
	})
}

func durationEnv(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a duration", name, v)
	}
	return d, nil
}
