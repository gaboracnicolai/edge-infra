package keycrypt

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testKEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// Seal must produce a MARKED value that is not the plaintext.
func TestSeal_ProducesMarkedCiphertext(t *testing.T) {
	kek := testKEK(t)
	out, err := Seal(kek, "-----BEGIN PRIVATE KEY-----secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, Marker) {
		t.Errorf("sealed value must carry the %q marker; got %q", Marker, out)
	}
	if out == "-----BEGIN PRIVATE KEY-----secret" {
		t.Error("sealed value must not equal the plaintext")
	}
}

// Seal then Open round-trips to the original plaintext.
func TestRoundTrip(t *testing.T) {
	kek := testKEK(t)
	pt := "-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----"
	sealed, err := Seal(kek, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(kek, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got != pt {
		t.Errorf("round-trip mismatch: got %q want %q", got, pt)
	}
}

// A marked value opened with the WRONG KEK errors loudly — never returns garbage.
func TestOpen_WrongKEK_Errors(t *testing.T) {
	sealed, err := Seal(testKEK(t), "topsecret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(testKEK(t), sealed); err == nil {
		t.Error("opening with the wrong KEK must error, not return garbage")
	}
}

// An unmarked value is plaintext (pre-encryption backward-compat) — passthrough.
func TestOpen_PlaintextPassthrough(t *testing.T) {
	got, err := Open(testKEK(t), "-----BEGIN CERTIFICATE-----plain")
	if err != nil {
		t.Fatal(err)
	}
	if got != "-----BEGIN CERTIFICATE-----plain" {
		t.Errorf("unmarked value must pass through unchanged; got %q", got)
	}
}

// A marked value with no KEK errors (fail-closed) — never serves ciphertext.
func TestOpen_MarkedNoKEK_Errors(t *testing.T) {
	if _, err := Open(nil, Marker+"Zm9v"); err == nil {
		t.Error("a sealed value with no KEK configured must error")
	}
}

// A nil KEK disables encryption: Seal is passthrough.
func TestSeal_NilKEK_Passthrough(t *testing.T) {
	out, err := Seal(nil, "plain")
	if err != nil || out != "plain" {
		t.Errorf("nil KEK must pass through; got %q err %v", out, err)
	}
}

func TestParseKEK(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if k, err := ParseKEK(valid); err != nil || len(k) != 32 {
		t.Errorf("valid 32-byte KEK: got len %d err %v", len(k), err)
	}
	if k, err := ParseKEK(""); err != nil || k != nil {
		t.Error("empty KEK must parse to nil (disabled)")
	}
	if _, err := ParseKEK(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Error("a 16-byte KEK must be rejected (need 32)")
	}
	if _, err := ParseKEK("not base64!!!"); err == nil {
		t.Error("non-base64 KEK must be rejected")
	}
}
