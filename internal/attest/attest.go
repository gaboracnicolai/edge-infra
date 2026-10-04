// Package attest is the confidential-compute attestation gate (B27.34). Before a
// workload on a confidential node starts, the gate asks the attester for a report
// bound to a fresh nonce and verifies it; the workload is refused unless the
// report verifies.
//
// Only the "mock" TEE has a verifier: an attester that signs its reports with an
// ed25519 key the operator pins. Real AMD SEV-SNP and Intel TDX reports need
// confidential VMs to produce and the vendor's certificate chain to verify — a
// report from either is refused here as unverifiable, never waved through.
package attest

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TEEMock is the only TEE this package can verify.
const TEEMock = "mock"

// Report is what the attester vouches for.
type Report struct {
	TEE         string    `json:"tee"`
	Measurement string    `json:"measurement"` // hex launch measurement of the guest
	ReportData  string    `json:"report_data"` // hex; must equal the gate's nonce
	IssuedAt    time.Time `json:"issued_at"`
}

// Evidence is the attester's answer: the report bytes exactly as signed, and the
// signature over them. Both travel base64-encoded in JSON.
type Evidence struct {
	Report    []byte `json:"report"`
	Signature []byte `json:"signature"`
}

// Policy is what the gate accepts.
type Policy struct {
	TrustedKey   ed25519.PublicKey
	Measurements []string // allowed launch measurements, hex
	MaxAge       time.Duration
}

// Verify checks ev against p for the nonce the gate sent. It returns the report
// only when every check passes; the error says which one refused it.
func Verify(ev Evidence, nonce []byte, p Policy, now time.Time) (Report, error) {
	var r Report
	if len(ev.Report) == 0 {
		return r, errors.New("no attestation report")
	}
	if err := json.Unmarshal(ev.Report, &r); err != nil {
		return r, fmt.Errorf("report does not parse: %w", err)
	}
	if r.TEE != TEEMock {
		return r, fmt.Errorf("no verifier for tee %q: only %q reports can be checked; SEV-SNP and TDX reports need confidential VMs and the vendor certificate chain", r.TEE, TEEMock)
	}
	if len(p.TrustedKey) != ed25519.PublicKeySize || !ed25519.Verify(p.TrustedKey, ev.Report, ev.Signature) {
		return r, errors.New("report is not signed by the trusted attester key")
	}
	if !strings.EqualFold(r.ReportData, hex.EncodeToString(nonce)) {
		return r, errors.New("report is not bound to this gate's nonce (replayed or stale)")
	}
	allowed := false
	for _, m := range p.Measurements {
		if strings.EqualFold(strings.TrimSpace(m), r.Measurement) {
			allowed = true
			break
		}
	}
	if !allowed {
		return r, fmt.Errorf("measurement %s is not in the allowed list", r.Measurement)
	}
	if age := now.Sub(r.IssuedAt); age > p.MaxAge || age < -time.Minute {
		return r, fmt.Errorf("report issued at %s is outside the %s window", r.IssuedAt.Format(time.RFC3339), p.MaxAge)
	}
	return r, nil
}

// Sign is the attester's side: it signs r with key.
func Sign(r Report, key ed25519.PrivateKey) (Evidence, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{Report: b, Signature: ed25519.Sign(key, b)}, nil
}

// Fetch asks the attester at evidenceURL for evidence bound to nonce, passed as
// ?runtime_data=<hex> — the shape of the Confidential Containers attestation
// agent's /aa/evidence endpoint.
func Fetch(ctx context.Context, c *http.Client, evidenceURL string, nonce []byte) (Evidence, error) {
	u, err := url.Parse(evidenceURL)
	if err != nil {
		return Evidence{}, fmt.Errorf("evidence URL: %w", err)
	}
	q := u.Query()
	q.Set("runtime_data", hex.EncodeToString(nonce))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Evidence{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return Evidence{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Evidence{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Evidence{}, fmt.Errorf("attester answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var ev Evidence
	if err := json.Unmarshal(body, &ev); err != nil {
		return Evidence{}, fmt.Errorf("attester answer does not parse: %w", err)
	}
	return ev, nil
}
