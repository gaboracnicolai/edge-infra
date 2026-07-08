package secrets

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// THE LEAD TEST: a mutating request with NO client cert and NO admin key must be
// rejected 401 and MUST NOT touch the store. Fail-closed.
func TestServer_UnauthenticatedWrite_Rejected(t *testing.T) {
	fake := &fakeStore{}
	srv := NewServer(fake, "s3cret", discardLog()) // admin key configured
	rec := doPut(t, srv, "svc", "cert", "key", "") // but NONE sent
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated write: want 401; got %d (%s)", rec.Code, rec.Body.String())
	}
	if fake.upserts != 0 {
		t.Errorf("unauthenticated write must not reach the store; got %d upserts", fake.upserts)
	}
}

// A wrong admin key is also rejected (constant-time compare, zero write).
func TestServer_WrongAdminKey_Rejected(t *testing.T) {
	fake := &fakeStore{}
	srv := NewServer(fake, "s3cret", discardLog())
	rec := doPut(t, srv, "svc", "cert", "key", "not-the-key")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong admin key: want 401; got %d", rec.Code)
	}
	if fake.upserts != 0 {
		t.Errorf("wrong admin key must not reach the store; got %d upserts", fake.upserts)
	}
}

// The right admin key authenticates a valid write.
func TestServer_AdminKeyWrite_Accepted(t *testing.T) {
	ca := newTestCA(t, "ca")
	cert, key := ca.leaf(t, "svc.example.com", true)
	fake := &fakeStore{}
	srv := NewServer(fake, "s3cret", discardLog())
	rec := doPut(t, srv, "svc", string(cert), string(key), "s3cret")
	if rec.Code != http.StatusOK {
		t.Fatalf("authed valid write: want 200; got %d (%s)", rec.Code, rec.Body.String())
	}
	if fake.upserts != 1 {
		t.Errorf("authed valid write must store exactly once; got %d", fake.upserts)
	}
}

// validateKeyPair: a matching pair validates; a mismatched key and malformed PEM
// are rejected.
func TestValidateKeyPair(t *testing.T) {
	ca := newTestCA(t, "ca")
	certA, keyA := ca.leaf(t, "a", true)
	_, keyB := ca.leaf(t, "b", true) // a different key
	if err := validateKeyPair(string(certA), string(keyA)); err != nil {
		t.Errorf("matching pair must validate: %v", err)
	}
	if err := validateKeyPair(string(certA), string(keyB)); err == nil {
		t.Error("mismatched key must be rejected")
	}
	if err := validateKeyPair("not a pem", "not a pem"); err == nil {
		t.Error("malformed PEM must be rejected")
	}
}

// API-level: an authed write of a MISMATCHED pair is rejected 400, zero write.
func TestServer_MismatchedPair_Rejected(t *testing.T) {
	ca := newTestCA(t, "ca")
	certA, _ := ca.leaf(t, "a", true)
	_, keyB := ca.leaf(t, "b", true)
	fake := &fakeStore{}
	srv := NewServer(fake, "s3cret", discardLog())
	rec := doPut(t, srv, "svc", string(certA), string(keyB), "s3cret")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched pair: want 400; got %d", rec.Code)
	}
	if fake.upserts != 0 {
		t.Errorf("mismatched pair must not be stored; got %d upserts", fake.upserts)
	}
}

// Key material must NEVER appear in logs.
func TestServer_NeverLogsKeyMaterial(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	ca := newTestCA(t, "ca")
	cert, key := ca.leaf(t, "svc.example.com", true)
	srv := NewServer(&fakeStore{}, "s3cret", log)
	doPut(t, srv, "svc", string(cert), string(key), "s3cret")

	logs := buf.String()
	if strings.Contains(logs, "PRIVATE KEY") || strings.Contains(logs, string(key)) {
		t.Error("logs must NEVER contain private key material")
	}
	if strings.Contains(logs, string(cert)) {
		t.Error("logs must not contain cert material")
	}
	if strings.Contains(logs, "s3cret") {
		t.Error("logs must never contain the admin key")
	}
}

// Rotation: a second authed PUT for the same name overwrites the pair (the store
// upserts by name; BuildSecrets then serves the new material — see the E2E).
func TestServer_Rotation_Overwrites(t *testing.T) {
	ca := newTestCA(t, "ca")
	cert1, key1 := ca.leaf(t, "svc.example.com", true)
	cert2, key2 := ca.leaf(t, "svc.example.com", true) // a fresh pair, same host
	fake := &fakeStore{}
	srv := NewServer(fake, "s3cret", discardLog())

	if rec := doPut(t, srv, "svc", string(cert1), string(key1), "s3cret"); rec.Code != http.StatusOK {
		t.Fatalf("first write: want 200; got %d", rec.Code)
	}
	if rec := doPut(t, srv, "svc", string(cert2), string(key2), "s3cret"); rec.Code != http.StatusOK {
		t.Fatalf("rotation write: want 200; got %d", rec.Code)
	}
	if fake.upserts != 2 {
		t.Errorf("rotation must upsert again; got %d upserts", fake.upserts)
	}
	if fake.lastCert != string(cert2) {
		t.Error("rotation must overwrite with the NEW cert (upsert by name)")
	}
}

// GET returns metadata only — never key/cert bytes.
func TestServer_GetReturnsMetadataOnly(t *testing.T) {
	srv := NewServer(&fakeStore{metaFingerprint: "abc123fingerprint"}, "s3cret", discardLog())
	rec := doReq(t, srv, "GET", "svc", "", "s3cret")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET meta: want 200; got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "abc123fingerprint") {
		t.Error("metadata must include the fingerprint")
	}
	if strings.Contains(body, "PRIVATE KEY") || strings.Contains(body, "cert_pem") || strings.Contains(body, "key_pem") {
		t.Error("GET must NEVER return cert/key material")
	}
}
