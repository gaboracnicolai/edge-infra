package secrets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func doPutCABundle(t *testing.T, srv *Server, name, caPEM, adminKey string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(putSecretRequest{CertPEM: caPEM, Kind: kindValidationContext})
	return doReq(t, srv, "PUT", name, string(body), adminKey)
}

// ACCEPT: a valid cert-only CA bundle is stored as kind=validation_context, no key.
func TestCustodian_AcceptsValidCABundle(t *testing.T) {
	ca := newTestCA(t, "client-ca") // a valid CA cert
	fake := &fakeStore{}
	srv := NewServer(fake, "s3cret", discardLog())
	rec := doPutCABundle(t, srv, "client-ca", string(ca.certPEM), "s3cret")
	if rec.Code != http.StatusOK {
		t.Fatalf("valid CA bundle: want 200; got %d (%s)", rec.Code, rec.Body.String())
	}
	if fake.upserts != 1 {
		t.Fatalf("want 1 upsert; got %d", fake.upserts)
	}
	if fake.lastKind != kindValidationContext {
		t.Errorf("kind = %q; want validation_context", fake.lastKind)
	}
	if fake.lastKey != "" {
		t.Error("a CA bundle must be stored with NO key")
	}
}

// REJECT (the hardening): not-a-CA (leaf), expired, malformed → 400, zero write.
func TestCustodian_RejectsBadCABundle(t *testing.T) {
	cases := map[string]string{
		"not-a-CA (leaf)": string(caCertPEM(t, "leaf", time.Now().Add(24*time.Hour), false)),
		"expired CA":      string(caCertPEM(t, "old-ca", time.Now().Add(-time.Hour), true)),
		"malformed PEM":   "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----",
	}
	for label, caPEM := range cases {
		fake := &fakeStore{}
		srv := NewServer(fake, "s3cret", discardLog())
		rec := doPutCABundle(t, srv, "bad", caPEM, "s3cret")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400; got %d", label, rec.Code)
		}
		if fake.upserts != 0 {
			t.Errorf("%s: must not be stored; got %d upserts", label, fake.upserts)
		}
	}
}

// A key supplied for a validation_context is a contract violation → 400.
func TestCustodian_CABundleWithKey_Rejected(t *testing.T) {
	ca := newTestCA(t, "client-ca")
	fake := &fakeStore{}
	srv := NewServer(fake, "s3cret", discardLog())
	body, _ := json.Marshal(putSecretRequest{
		CertPEM: string(ca.certPEM), KeyPEM: "-----BEGIN PRIVATE KEY-----", Kind: kindValidationContext,
	})
	rec := doReq(t, srv, "PUT", "ca", string(body), "s3cret")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("CA bundle carrying a key: want 400; got %d", rec.Code)
	}
	if fake.upserts != 0 {
		t.Error("must not store a validation_context that carries a key")
	}
}

// AUTH boundary holds for the new kind: an unauthenticated CA-bundle PUT is rejected.
func TestCustodian_CABundle_UnauthRejected(t *testing.T) {
	ca := newTestCA(t, "client-ca")
	fake := &fakeStore{}
	srv := NewServer(fake, "s3cret", discardLog())
	rec := doPutCABundle(t, srv, "ca", string(ca.certPEM), "") // no admin key
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated CA PUT: want 401; got %d", rec.Code)
	}
	if fake.upserts != 0 {
		t.Error("unauthenticated CA PUT must not store")
	}
}
