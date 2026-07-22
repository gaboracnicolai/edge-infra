package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/config"
	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds"
)

// ---------------------------------------------------------------------------
// The leak guard. This is the point of the Admin API PR: an admin page must
// never be a reason to decrypt (or serve) a private key. Every endpoint test
// below runs its response body through this check, and the teeth test proves
// the check catches the exact naive mistake it exists to prevent — marshaling
// a store.LoadSnapshot result, which carries PLAINTEXT private keys.
// ---------------------------------------------------------------------------

// bodyLeaksKeyMaterial reports whether an admin response body contains key
// material: any PEM private-key header ("PRIVATE KEY" covers RSA/EC/PKCS#8,
// BEGIN and END alike) or any of the caller's known key-byte sentinels.
func bodyLeaksKeyMaterial(body []byte, sentinels ...string) bool {
	if bytes.Contains(body, []byte("PRIVATE KEY")) {
		return true
	}
	for _, s := range sentinels {
		if s != "" && bytes.Contains(body, []byte(s)) {
			return true
		}
	}
	return false
}

// adminTestCertKey generates a self-signed cert + EC private key pair (PEM).
func adminTestCertKey(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// keyByteSentinel extracts a distinctive run of the key's base64 body — a
// sentinel that detects the key VALUE leaking even without its PEM header.
func keyByteSentinel(t *testing.T, keyPEM string) string {
	t.Helper()
	for _, line := range strings.Split(keyPEM, "\n") {
		if len(line) >= 40 && !strings.Contains(line, "-----") {
			return line[:40]
		}
	}
	t.Fatal("no base64 body line in key PEM")
	return ""
}

// The teeth: the guard MUST flag a marshaled LoadSnapshot result — the exact
// body a naive "reuse the loader that already exists" implementation would
// serve — and must not false-positive on a clean admin body. This keeps the
// guard honest forever, independent of the live red-run during development.
func TestAdminLeakGuard_CatchesNaiveLoadSnapshotBody(t *testing.T) {
	certPEM, keyPEM := adminTestCertKey(t, "leak-guard")
	naive := &store.Snapshot{
		Gateways: []store.Gateway{{ID: "gw", Name: "gw", Port: 443, Protocol: "HTTPS", TLSSecret: "edge-cert"}},
		Secrets: []store.Secret{{
			ID: "edge-cert", Name: "edge-cert", Kind: "tls_certificate",
			CertPEM: certPEM,
			KeyPEM:  keyPEM, // what loadSecrets returns: DECRYPTED plaintext
		}},
	}
	body, err := json.Marshal(naive)
	require.NoError(t, err)

	require.True(t, bodyLeaksKeyMaterial(body),
		"guard MUST catch a marshaled LoadSnapshot result by its PEM header")
	require.True(t, bodyLeaksKeyMaterial(body, keyByteSentinel(t, keyPEM)),
		"guard MUST catch the key bytes themselves")

	clean := []byte(`{"certificates":[{"name":"edge-cert","kind":"tls_certificate",` +
		`"fingerprint_sha256":"abc123","issuer":"CN=leak-guard","not_after":"2027-01-01T00:00:00Z"}]}`)
	require.False(t, bodyLeaksKeyMaterial(clean, keyByteSentinel(t, keyPEM)),
		"guard must not false-positive on the intended key-free admin shape")
}

// ---------------------------------------------------------------------------
// Fakes (unit tests only — the integration test wires the real store).
// ---------------------------------------------------------------------------

type fakeAdminStore struct {
	topo     *store.Topology
	topoErr  error
	certRows []store.CertificateRow
	certErr  error
	prov     *store.Provisioning
	provErr  error
}

func (f *fakeAdminStore) LoadTopology(context.Context) (*store.Topology, error) {
	return f.topo, f.topoErr
}
func (f *fakeAdminStore) LoadCertificateRows(context.Context) ([]store.CertificateRow, error) {
	return f.certRows, f.certErr
}
func (f *fakeAdminStore) LoadProvisioning(context.Context, int) (*store.Provisioning, error) {
	return f.prov, f.provErr
}

type fakeNodeSource struct {
	statuses  []xds.NodeStatus
	published string
	streams   int64
	behind    int
	lastUnix  int64
	lastDur   float64
}

func (f *fakeNodeSource) NodeStatuses() []xds.NodeStatus        { return f.statuses }
func (f *fakeNodeSource) PublishedVersion() string              { return f.published }
func (f *fakeNodeSource) ActiveStreams() int64                  { return f.streams }
func (f *fakeNodeSource) NodesBehind() int                      { return f.behind }
func (f *fakeNodeSource) LastReconcileUnix() int64              { return f.lastUnix }
func (f *fakeNodeSource) LastReconcileDurationSeconds() float64 { return f.lastDur }

const testAdminKey = "unit-test-admin-key"

func happyAdminDeps(t *testing.T) adminDeps {
	t.Helper()
	certPEM, _ := adminTestCertKey(t, "route-cert")
	return adminDeps{
		store: &fakeAdminStore{
			topo: &store.Topology{
				Gateways: []store.Gateway{{ID: "gw-1", Name: "edge-gw", Port: 443, Protocol: "HTTPS",
					TLSSecret: "edge-cert", NodeSelector: map[string]string{"zone": "a"}}},
				Routes: []store.Route{{ID: "rt-1", Name: "svc-route", GatewayID: "gw-1",
					Hosts: []string{"api.example.com"}, PathPrefix: "/api", ClusterName: "svc-cl",
					TimeoutSeconds: 30, AuthPolicy: "none", TLSSecret: "svc-cert"}},
				Clusters: []store.Cluster{{ID: "cl-1", Name: "svc-cl",
					ConnectTimeout: 5 * time.Second, LbPolicy: "ROUND_ROBIN", HealthCheckPath: "/healthz"}},
				Endpoints: []store.Endpoint{{ID: "ep-1", ClusterID: "cl-1", Address: "10.0.0.9", Port: 8080, Weight: 1}},
			},
			certRows: []store.CertificateRow{
				{ID: "edge-cert", Name: "edge-cert", Kind: "tls_certificate", CertPEM: certPEM},
				{ID: "broken", Name: "broken", Kind: "tls_certificate", CertPEM: "not a pem"},
			},
			prov: &store.Provisioning{
				Services: []store.ProvisionedService{{ID: "svc-1", Name: "billing", Team: "payments",
					Host: "billing.internal", Port: 8080, Protocol: "HTTP", AuthPolicy: "jwt"}},
				Requests: []store.ProvisionRequest{
					{ID: "req-2", Operation: "CREATE", Status: "FAILED", Team: "payments",
						Error: "translator: gateway port conflict", CreatedAt: time.Now()},
					{ID: "req-1", Operation: "CREATE", Status: "COMPLETED", Team: "payments",
						CreatedAt: time.Now().Add(-time.Hour)},
				},
			},
		},
		nodes: &fakeNodeSource{
			statuses: []xds.NodeStatus{
				{NodeID: "envoy-a", AckedVersion: "v-current", Behind: false},
				{NodeID: "envoy-b", AckedVersion: "v-old", Behind: true},
			},
			published: "v-current",
			streams:   2,
			behind:    1,
			lastUnix:  1700000000,
			lastDur:   0.05,
		},
		cfg: newAdminConfigView(&config.Config{
			ListenAddr:         ":18000",
			NodeID:             "edge-proxy",
			ReconcileInterval:  5 * time.Second,
			TLSCertFile:        "/tls/cert.pem",
			TLSKeyFile:         "/tls/key.pem",
			ExtAuthzEnabled:    true,
			ExtAuthzAddress:    "auth-service.infra.svc.cluster.local",
			ExtAuthzPort:       50051,
			ExtAuthzCAFile:     "/authz/ca.crt",
			RateLimitEnabled:   true,
			RateLimitMaxTokens: 200, RateLimitTokensPerFill: 100, RateLimitFillInterval: time.Second,
			RateLimitServiceEnabled: false,
			RateLimitServiceAddress: "ratelimit.infra.svc.cluster.local",
			RateLimitServicePort:    8082,
			RateLimitServiceDomain:  "edge",
			RedisAddr:               "redis:6379",
			InstanceID:              "cp-0",
		}),
		key: testAdminKey,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func adminTestServer(t *testing.T, d adminDeps) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(newAdminHandler(d))
	t.Cleanup(ts.Close)
	return ts
}

func adminGET(t *testing.T, ts *httptest.Server, path, key string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	require.NoError(t, err)
	if key != "" {
		req.Header.Set("X-Admin-Key", key)
	}
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

var adminPaths = []string{
	"/admin/v1/topology",
	"/admin/v1/nodes",
	"/admin/v1/certificates",
	"/admin/v1/provisioning",
	"/admin/v1/config",
}

// ---------------------------------------------------------------------------
// Auth: fail-closed on every route, custodian-style constant-time key match.
// ---------------------------------------------------------------------------

func TestAdminAPI_AuthFailClosed(t *testing.T) {
	ts := adminTestServer(t, happyAdminDeps(t))

	for _, p := range adminPaths {
		code, _ := adminGET(t, ts, p, "")
		assert.Equal(t, http.StatusUnauthorized, code, "%s without key must 401", p)

		code, _ = adminGET(t, ts, p, "wrong-key")
		assert.Equal(t, http.StatusUnauthorized, code, "%s with wrong key must 401", p)

		code, _ = adminGET(t, ts, p, testAdminKey)
		assert.Equal(t, http.StatusOK, code, "%s with the right key must 200", p)
	}
}

// A handler constructed with an EMPTY key must refuse everything — even an
// empty presented key. main.go never starts the listener without a key; this
// is the defense-in-depth layer under that (mirrors the custodian's
// constantTimeMatch: empty configured key disables the key path).
func TestAdminAPI_EmptyConfiguredKey_RefusesAll(t *testing.T) {
	d := happyAdminDeps(t)
	d.key = ""
	ts := adminTestServer(t, d)

	for _, p := range adminPaths {
		code, _ := adminGET(t, ts, p, "")
		assert.Equal(t, http.StatusUnauthorized, code, "%s must fail closed with no configured key", p)
	}
}

func TestAdminAPI_WriteMethodsRejected(t *testing.T) {
	ts := adminTestServer(t, happyAdminDeps(t))
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req, err := http.NewRequest(method, ts.URL+"/admin/v1/topology", nil)
		require.NoError(t, err)
		req.Header.Set("X-Admin-Key", testAdminKey)
		resp, err := ts.Client().Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode,
			"read-only API: %s must be rejected", method)
	}
}

// ---------------------------------------------------------------------------
// Endpoints.
// ---------------------------------------------------------------------------

func TestAdminAPI_Topology(t *testing.T) {
	ts := adminTestServer(t, happyAdminDeps(t))
	code, body := adminGET(t, ts, "/admin/v1/topology", testAdminKey)
	require.Equal(t, http.StatusOK, code)
	require.False(t, bodyLeaksKeyMaterial(body), "topology must be key-free")

	var got struct {
		Gateways []struct {
			Name         string            `json:"name"`
			Port         uint32            `json:"port"`
			Protocol     string            `json:"protocol"`
			TLSSecret    string            `json:"tls_secret"`
			NodeSelector map[string]string `json:"node_selector"`
		} `json:"gateways"`
		Routes []struct {
			Name           string `json:"name"`
			AuthPolicy     string `json:"auth_policy"`
			ClusterName    string `json:"cluster_name"`
			TLSSecretName  string `json:"tls_secret_name"`
			ClientCASecret string `json:"client_ca_secret_name"`
		} `json:"routes"`
		Clusters []struct {
			Name             string `json:"name"`
			ConnectTimeoutMS int64  `json:"connect_timeout_ms"`
		} `json:"clusters"`
		Endpoints []struct {
			ClusterID string `json:"cluster_id"`
			Address   string `json:"address"`
		} `json:"endpoints"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	require.Len(t, got.Gateways, 1)
	assert.Equal(t, "edge-gw", got.Gateways[0].Name)
	assert.Equal(t, "edge-cert", got.Gateways[0].TLSSecret, "secret NAME references are fine — never material")
	require.Len(t, got.Routes, 1)
	assert.Equal(t, "none", got.Routes[0].AuthPolicy,
		"auth_policy must surface so an unauthenticated route is visible in red on the admin page")
	require.Len(t, got.Clusters, 1)
	assert.Equal(t, int64(5000), got.Clusters[0].ConnectTimeoutMS)
	require.Len(t, got.Endpoints, 1)
	assert.Equal(t, "10.0.0.9", got.Endpoints[0].Address)
}

func TestAdminAPI_Topology_StoreError(t *testing.T) {
	d := happyAdminDeps(t)
	d.store = &fakeAdminStore{topoErr: errors.New("pg down: connection refused to 10.1.2.3")}
	ts := adminTestServer(t, d)

	code, body := adminGET(t, ts, "/admin/v1/topology", testAdminKey)
	assert.Equal(t, http.StatusInternalServerError, code)
	assert.JSONEq(t, `{"error":"internal error"}`, string(body),
		"errors must be generic — never echo internals (custodian convention)")
}

func TestAdminAPI_Nodes_ConnectedOnlyScope(t *testing.T) {
	ts := adminTestServer(t, happyAdminDeps(t))
	code, body := adminGET(t, ts, "/admin/v1/nodes", testAdminKey)
	require.Equal(t, http.StatusOK, code)
	require.False(t, bodyLeaksKeyMaterial(body))

	var got struct {
		Scope            string `json:"scope"`
		Note             string `json:"note"`
		PublishedVersion string `json:"published_version"`
		ActiveStreams    int64  `json:"active_streams"`
		NodesBehind      int    `json:"nodes_behind"`
		Nodes            []struct {
			NodeID       string `json:"node_id"`
			AckedVersion string `json:"acked_version"`
			Behind       bool   `json:"behind"`
		} `json:"nodes"`
	}
	require.NoError(t, json.Unmarshal(body, &got))

	// The response SHAPE must say what this is: connected nodes only. There is
	// no expected-node registry, and a UI must not be able to read "every
	// connected node acked" as "all nodes healthy".
	assert.Equal(t, "connected-only", got.Scope)
	assert.Contains(t, got.Note, "not connected",
		"the note must spell out that absence means not-connected, not healthy")
	assert.Contains(t, got.Note, "registry",
		"the note must state that no expected-node registry exists")

	assert.Equal(t, "v-current", got.PublishedVersion)
	assert.Equal(t, int64(2), got.ActiveStreams)
	assert.Equal(t, 1, got.NodesBehind)
	require.Len(t, got.Nodes, 2)
	assert.Equal(t, "envoy-a", got.Nodes[0].NodeID)
	assert.False(t, got.Nodes[0].Behind)
	assert.Equal(t, "envoy-b", got.Nodes[1].NodeID)
	assert.True(t, got.Nodes[1].Behind)
}

func TestAdminAPI_Certificates(t *testing.T) {
	ts := adminTestServer(t, happyAdminDeps(t))
	code, body := adminGET(t, ts, "/admin/v1/certificates", testAdminKey)
	require.Equal(t, http.StatusOK, code)
	require.False(t, bodyLeaksKeyMaterial(body), "certificates must be metadata only")

	var got struct {
		Certificates []struct {
			Name        string `json:"name"`
			Kind        string `json:"kind"`
			Fingerprint string `json:"fingerprint_sha256"`
			Issuer      string `json:"issuer"`
			NotAfter    string `json:"not_after"`
			ParseError  bool   `json:"parse_error"`
		} `json:"certificates"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	require.Len(t, got.Certificates, 2)

	ok := got.Certificates[0]
	assert.Equal(t, "edge-cert", ok.Name)
	assert.Equal(t, "tls_certificate", ok.Kind)
	assert.Len(t, ok.Fingerprint, 64, "SHA-256 hex fingerprint (custodian GetMeta parity)")
	assert.Contains(t, ok.Issuer, "route-cert")
	assert.NotEmpty(t, ok.NotAfter)
	assert.False(t, ok.ParseError)

	// An unparseable row is REPORTED, not silently dropped — an admin page
	// showing 4 of 5 certs is how an expiry gets missed.
	broken := got.Certificates[1]
	assert.Equal(t, "broken", broken.Name)
	assert.True(t, broken.ParseError)
	assert.Empty(t, broken.Fingerprint)
}

func TestAdminAPI_Provisioning_IncludesFailed(t *testing.T) {
	ts := adminTestServer(t, happyAdminDeps(t))
	code, body := adminGET(t, ts, "/admin/v1/provisioning", testAdminKey)
	require.Equal(t, http.StatusOK, code)
	require.False(t, bodyLeaksKeyMaterial(body))

	var got struct {
		Services []struct {
			Name string `json:"name"`
			Team string `json:"team"`
		} `json:"services"`
		Requests []struct {
			ID          string  `json:"id"`
			Status      string  `json:"status"`
			Error       string  `json:"error"`
			CompletedAt *string `json:"completed_at"`
		} `json:"requests"`
		RequestLimit int `json:"request_limit"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	require.Len(t, got.Services, 1)
	assert.Equal(t, "payments", got.Services[0].Team, "cross-tenant by design — this is the admin view")

	require.Len(t, got.Requests, 2)
	assert.Equal(t, "FAILED", got.Requests[0].Status)
	assert.Equal(t, "translator: gateway port conflict", got.Requests[0].Error,
		"a FAILED request's error is the whole point of this endpoint")
	assert.Nil(t, got.Requests[0].CompletedAt)
	assert.Positive(t, got.RequestLimit)
}

func TestAdminAPI_ConfigReflectsEffectiveFlags(t *testing.T) {
	ts := adminTestServer(t, happyAdminDeps(t))
	code, body := adminGET(t, ts, "/admin/v1/config", testAdminKey)
	require.Equal(t, http.StatusOK, code)
	require.False(t, bodyLeaksKeyMaterial(body))

	var got struct {
		ReadOnly            bool   `json:"read_only"`
		NodeID              string `json:"node_id"`
		ReconcileIntervalMS int64  `json:"reconcile_interval_ms"`
		XDS                 struct {
			TLS      bool `json:"tls"`
			ClientCA bool `json:"client_ca"`
		} `json:"xds"`
		ExtAuthz struct {
			Enabled bool   `json:"enabled"`
			Address string `json:"address"`
			TLS     bool   `json:"tls"`
			MTLS    bool   `json:"mtls"`
		} `json:"ext_authz"`
		RateLimitLocal struct {
			Enabled bool `json:"enabled"`
		} `json:"rate_limit_local"`
		HA struct {
			RedisConfigured bool   `json:"redis_configured"`
			InstanceID      string `json:"instance_id"`
		} `json:"ha"`
	}
	require.NoError(t, json.Unmarshal(body, &got))

	assert.True(t, got.ReadOnly, "the response itself must declare this surface read-only")
	assert.Equal(t, "edge-proxy", got.NodeID)
	assert.Equal(t, int64(5000), got.ReconcileIntervalMS)
	assert.True(t, got.XDS.TLS, "cert+key set ⇒ xDS TLS on")
	assert.False(t, got.XDS.ClientCA)
	assert.True(t, got.ExtAuthz.Enabled, "the EFFECTIVE env-derived flag — only this process can answer this")
	assert.Equal(t, "auth-service.infra.svc.cluster.local", got.ExtAuthz.Address)
	assert.True(t, got.ExtAuthz.TLS, "CA file set ⇒ upstream TLS rendered")
	assert.False(t, got.ExtAuthz.MTLS, "no client cert ⇒ no mTLS")
	assert.True(t, got.RateLimitLocal.Enabled)
	assert.True(t, got.HA.RedisConfigured)
	assert.Equal(t, "cp-0", got.HA.InstanceID)
}

// Every 200 body across all endpoints is key-free — the blanket sweep.
func TestAdminAPI_NoEndpointLeaksKeyMaterial(t *testing.T) {
	d := happyAdminDeps(t)
	_, keyPEM := adminTestCertKey(t, "sweep")
	sentinel := keyByteSentinel(t, keyPEM)
	ts := adminTestServer(t, d)

	for _, p := range adminPaths {
		code, body := adminGET(t, ts, p, testAdminKey)
		require.Equal(t, http.StatusOK, code, p)
		assert.False(t, bodyLeaksKeyMaterial(body, sentinel), "%s leaked key material", p)
	}
}
