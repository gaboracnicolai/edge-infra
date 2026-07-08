package secrets

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// --- test PKI: a tiny CA + leaf issuer, in-memory --------------------------

type testCA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, certPEM: pemBlock("CERTIFICATE", der)}
}

// leaf issues a cert+key signed by the CA. isServer sets serverAuth EKU + SANs;
// otherwise clientAuth (an operator or proxy identity).
func (ca *testCA) leaf(t *testing.T, cn string, isServer bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if isServer {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pemBlock("CERTIFICATE", der), pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "pem-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return f.Name()
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// --- fake store (no DB) -----------------------------------------------------

type fakeStore struct {
	upserts, deletes  int
	lastCert, lastKey string
	metaFingerprint   string
	deleteReturns     bool
}

func (f *fakeStore) Upsert(_ context.Context, _, certPEM, keyPEM string) error {
	f.upserts++
	f.lastCert, f.lastKey = certPEM, keyPEM
	return nil
}
func (f *fakeStore) Delete(_ context.Context, _ string) (bool, error) {
	f.deletes++
	return f.deleteReturns, nil
}
func (f *fakeStore) GetMeta(_ context.Context, name string) (*SecretMeta, error) {
	return &SecretMeta{Name: name, Fingerprint: f.metaFingerprint, NotAfter: time.Now()}, nil
}
func (f *fakeStore) Ping(_ context.Context) error { return nil }

// --- handler-level request helpers (plaintext; auth via X-Admin-Key) --------

func doReq(t *testing.T, srv *Server, method, name, body, adminKey string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "/v1/secrets/"+name, r)
	if adminKey != "" {
		req.Header.Set("X-Admin-Key", adminKey)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func doPut(t *testing.T, srv *Server, name, certPEM, keyPEM, adminKey string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(putSecretRequest{CertPEM: certPEM, KeyPEM: keyPEM})
	return doReq(t, srv, "PUT", name, string(body), adminKey)
}
