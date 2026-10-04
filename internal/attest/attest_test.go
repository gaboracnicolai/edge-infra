package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

const measurement = "8f3a0c1d"

func TestVerify(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	nonce := []byte("0123456789abcdef0123456789abcdef")
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	policy := Policy{TrustedKey: pub, Measurements: []string{measurement}, MaxAge: 5 * time.Minute}
	good := Report{TEE: TEEMock, Measurement: measurement, ReportData: hex.EncodeToString(nonce), IssuedAt: now}

	sign := func(r Report, k ed25519.PrivateKey) Evidence {
		ev, err := Sign(r, k)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	with := func(f func(*Report)) Report { r := good; f(&r); return r }

	if _, err := Verify(sign(good, key), nonce, policy, now); err != nil {
		t.Fatalf("a valid report was refused: %v", err)
	}

	for _, tc := range []struct {
		name string
		ev   Evidence
		want string
	}{
		{"no report", Evidence{}, "no attestation report"},
		{"signed by an untrusted key", sign(good, otherKey), "not signed by the trusted attester key"},
		{"tampered after signing", func() Evidence {
			ev := sign(good, key)
			ev.Report = []byte(strings.Replace(string(ev.Report), measurement, "deadbeef", 1))
			return ev
		}(), "not signed by the trusted attester key"},
		{"replayed for another nonce", sign(with(func(r *Report) { r.ReportData = "00" }), key), "not bound to this gate's nonce"},
		{"measurement not allowed", sign(with(func(r *Report) { r.Measurement = "deadbeef" }), key), "not in the allowed list"},
		{"too old", sign(with(func(r *Report) { r.IssuedAt = now.Add(-6 * time.Minute) }), key), "outside the 5m0s window"},
		{"real hardware report", sign(with(func(r *Report) { r.TEE = "snp" }), key), `no verifier for tee "snp"`},
	} {
		if _, err := Verify(tc.ev, nonce, policy, now); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want refusal containing %q", tc.name, err, tc.want)
		}
	}
}
