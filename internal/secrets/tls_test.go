package secrets

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mtlsClient(t *testing.T, serverCAPEM, clientCertPEM, clientKeyPEM []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(serverCAPEM)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if clientCertPEM != nil {
		cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

// tlsTestServer starts an httptest TLS server using the component's own
// buildServerTLS (the code under test), with the given admin CA.
func tlsTestServer(t *testing.T, srv *Server, serverCA *testCA, adminKey, adminCAFile string) *httptest.Server {
	t.Helper()
	srvCert, srvKey := serverCA.leaf(t, "localhost", true)
	cfg := &Config{
		TLSCertFile: writeTemp(t, srvCert),
		TLSKeyFile:  writeTemp(t, srvKey),
		AdminCAFile: adminCAFile,
		AdminAPIKey: adminKey,
	}
	tlsCfg, err := buildServerTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv.Routes())
	ts.TLS = tlsCfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// THE TRUST-DOMAIN PROOF (load-bearing): a client cert signed by the data-plane
// CA (edge-internal-ca) MUST be rejected; only an edge-admin-ca operator cert is
// accepted; no cert at all is rejected. The operator trust domain is SEPARATE
// from the data plane — a proxy can never write keys.
func TestServer_ProxyCert_Rejected(t *testing.T) {
	serverCA := newTestCA(t, "server-ca")
	adminCA := newTestCA(t, "edge-admin-ca")    // operator trust domain
	proxyCA := newTestCA(t, "edge-internal-ca") // data-plane trust domain

	// mTLS only (no admin key) → RequireAndVerifyClientCert against the admin CA.
	srv := NewServer(&fakeStore{metaFingerprint: "fp"}, "", discardLog())
	ts := tlsTestServer(t, srv, serverCA, "", writeTemp(t, adminCA.certPEM))

	// A data-plane PROXY cert must be rejected at the handshake.
	proxyCert, proxyKey := proxyCA.leaf(t, "edge-proxy", false)
	if _, err := mtlsClient(t, serverCA.certPEM, proxyCert, proxyKey).Get(ts.URL + "/v1/secrets/probe"); err == nil {
		t.Fatal("a data-plane (edge-internal-ca) proxy cert MUST be rejected — admin CA is a separate trust domain")
	}

	// An OPERATOR cert (edge-admin-ca) is accepted (reaches the handler).
	opCert, opKey := adminCA.leaf(t, "operator", false)
	resp, err := mtlsClient(t, serverCA.certPEM, opCert, opKey).Get(ts.URL + "/v1/secrets/probe")
	if err != nil {
		t.Fatalf("an edge-admin-ca operator cert must be accepted: %v", err)
	}
	resp.Body.Close()

	// No client cert → rejected (mTLS is the only auth here).
	if _, err := mtlsClient(t, serverCA.certPEM, nil, nil).Get(ts.URL + "/v1/secrets/probe"); err == nil {
		t.Fatal("no client cert MUST be rejected when mTLS is the only auth")
	}
}
