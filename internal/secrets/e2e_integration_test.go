//go:build integration

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/jackc/pgx/v5"

	"github.com/edge-infra/control-plane/internal/keycrypt"
	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds/builders"
)

// END-TO-END: an operator (mTLS, edge-admin-ca cert) writes a cert+key THROUGH
// the component; the row lands in `secrets`; then 3b-i per-SNI rendering serves
// it — LoadSnapshot -> HTTPS filter chain referencing that cert, BuildSecrets
// serves the material. Proves the custody path end to end, reference-only.
func TestE2E_PutViaComponentThenRender(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required (integration)")
	}
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx,
		"TRUNCATE secrets, routes, gateways, clusters, endpoints CASCADE"); err != nil {
		t.Fatal(err)
	}

	// The component's SOLE writer, over mTLS against a SEPARATE admin CA.
	st, err := NewStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	serverCA := newTestCA(t, "server-ca")
	adminCA := newTestCA(t, "edge-admin-ca")
	ts := tlsTestServer(t, NewServer(st, "", discardLog()), serverCA, "", writeTemp(t, adminCA.certPEM))

	// A valid serving cert+key for sni.example.com, PUT with an operator cert.
	leafCert, leafKey := serverCA.leaf(t, "sni.example.com", true)
	opCert, opKey := adminCA.leaf(t, "operator", false)
	body, _ := json.Marshal(putSecretRequest{CertPEM: string(leafCert), KeyPEM: string(leafKey)})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/secrets/sni-cert", bytes.NewReader(body))
	resp, err := mtlsClient(t, serverCA.certPEM, opCert, opKey).Do(req)
	if err != nil {
		t.Fatalf("operator PUT via component: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("component PUT: want 200; got %d", resp.StatusCode)
	}

	// A 3b-i HTTPS route referencing that secret by name (mirrors the OSB write).
	for _, q := range []string{
		`INSERT INTO gateways (id,name,port,protocol) VALUES ('osb-shared-https','osb-shared-https',443,'HTTPS')`,
		`INSERT INTO clusters (id,name,connect_timeout_ms,lb_policy) VALUES ('osb-t-svc','osb-t-svc',5000,'ROUND_ROBIN')`,
		`INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,tls_secret_name)
		 VALUES ('osb-t-svc','osb-t-svc','osb-shared-https',ARRAY['sni.example.com'],'/','osb-t-svc','sni-cert')`,
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatalf("seed route: %v", err)
		}
	}
	conn.Close(ctx)

	// LoadSnapshot -> render. The HTTPS listener presents sni-cert for the SNI host.
	pg, err := store.NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	snap, err := pg.LoadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	listeners := builders.BuildListeners(snap.Gateways, snap.Routes,
		builders.RateLimitOptions{}, builders.ExtAuthzOptions{}, builders.RateLimitServiceOptions{})
	if got := listenerSNICert(listeners, "osb-shared-https", "sni.example.com"); got != "sni-cert" {
		t.Errorf("per-SNI cert for sni.example.com = %q; want sni-cert", got)
	}
	if !secretServedInSDS(builders.BuildSecrets(snap.Secrets), "sni-cert") {
		t.Error("BuildSecrets must serve the component-written sni-cert material")
	}
}

// END-TO-END (CA bundle): an operator (mTLS) PUTs a cert-only client-CA trust
// bundle THROUGH the component; the row lands kind=validation_context with a NULL
// key; BuildSecrets serves it as a trusted_ca (validation_context), NOT a
// tls_certificate. Proves the new custody kind end to end.
func TestE2E_CABundlePutThenValidationContext(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required (integration)")
	}
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "TRUNCATE secrets, routes, gateways, clusters, endpoints CASCADE"); err != nil {
		t.Fatal(err)
	}

	st, err := NewStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	serverCA := newTestCA(t, "server-ca")
	adminCA := newTestCA(t, "edge-admin-ca")
	ts := tlsTestServer(t, NewServer(st, "", discardLog()), serverCA, "", writeTemp(t, adminCA.certPEM))

	// A client-CA trust bundle (cert-only), PUT with an operator cert.
	clientCA := newTestCA(t, "client-ca")
	opCert, opKey := adminCA.leaf(t, "operator", false)
	body, _ := json.Marshal(putSecretRequest{CertPEM: string(clientCA.certPEM), Kind: kindValidationContext})
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/secrets/client-ca", bytes.NewReader(body))
	resp, err := mtlsClient(t, serverCA.certPEM, opCert, opKey).Do(req)
	if err != nil {
		t.Fatalf("operator CA-bundle PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CA bundle PUT: want 200; got %d", resp.StatusCode)
	}

	// The row: kind=validation_context, key_pem NULL.
	var kind string
	var keyNull bool
	if err := conn.QueryRow(ctx,
		"SELECT kind, key_pem IS NULL FROM secrets WHERE name='client-ca'").Scan(&kind, &keyNull); err != nil {
		t.Fatalf("query secret: %v", err)
	}
	conn.Close(ctx)
	if kind != "validation_context" {
		t.Errorf("stored kind = %q; want validation_context", kind)
	}
	if !keyNull {
		t.Error("a CA bundle must be stored with key_pem NULL")
	}

	// LoadSnapshot -> BuildSecrets serves it as a validation_context (trusted_ca).
	pg, err := store.NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	snap, err := pg.LoadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sec := findSDSSecret(t, builders.BuildSecrets(snap.Secrets), "client-ca")
	if sec.GetValidationContext() == nil {
		t.Error("component-written CA bundle must render as a validation_context")
	}
	if sec.GetTlsCertificate() != nil {
		t.Error("a CA bundle must NOT render as a tls_certificate")
	}
}

func findSDSSecret(t *testing.T, res []cachetypes.Resource, name string) *tlsv3.Secret {
	t.Helper()
	for _, r := range res {
		if s, ok := r.(*tlsv3.Secret); ok && s.GetName() == name {
			return s
		}
	}
	t.Fatalf("secret %q not in SDS output", name)
	return nil
}

func listenerSNICert(res []cachetypes.Resource, listenerName, host string) string {
	for _, r := range res {
		l, ok := r.(*listenerv3.Listener)
		if !ok || l.GetName() != listenerName {
			continue
		}
		for _, fc := range l.GetFilterChains() {
			sn := fc.GetFilterChainMatch().GetServerNames()
			if len(sn) != 1 || sn[0] != host || fc.GetTransportSocket() == nil {
				continue
			}
			var dtc tlsv3.DownstreamTlsContext
			if fc.GetTransportSocket().GetTypedConfig().UnmarshalTo(&dtc) != nil {
				return ""
			}
			sds := dtc.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs()
			if len(sds) == 1 {
				return sds[0].GetName()
			}
		}
	}
	return ""
}

func secretServedInSDS(res []cachetypes.Resource, name string) bool {
	for _, r := range res {
		if s, ok := r.(*tlsv3.Secret); ok && s.GetName() == name {
			return true
		}
	}
	return false
}

// R5: the custodian seals a key at rest (ciphertext on disk); the control-plane
// decrypts on load so BuildSecrets serves the ORIGINAL PEM; a control-plane with
// no/wrong KEK fails LOUDLY rather than serving ciphertext.
func TestE2E_KeyEncryptedAtRest(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required (integration)")
	}
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "TRUNCATE secrets, routes, gateways, clusters, endpoints CASCADE"); err != nil {
		t.Fatal(err)
	}

	kek := []byte("0123456789abcdef0123456789abcdef") // 32 bytes, test only

	cs, err := NewStore(ctx, dsn, WithKEK(kek))
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	srvCA := newTestCA(t, "svc-ca")
	certPEM, keyPEM := srvCA.leaf(t, "svc", true)
	if err := cs.Upsert(ctx, "enc-cert", string(certPEM), string(keyPEM), "tls_certificate"); err != nil {
		t.Fatal(err)
	}

	// On disk: ciphertext, never the raw key.
	var stored string
	if err := conn.QueryRow(ctx, "SELECT key_pem FROM secrets WHERE name='enc-cert'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	if !strings.HasPrefix(stored, keycrypt.MarkerV2+keycrypt.KeyID(kek)+":") {
		t.Errorf("key must be sealed at rest; got prefix %.10q", stored)
	}
	if strings.Contains(stored, "PRIVATE KEY") {
		t.Error("the raw private key must not be stored on disk")
	}

	// Control-plane WITH the KEK: decrypts → BuildSecrets serves the original PEM.
	pg, err := store.NewPostgresStore(ctx, dsn, store.WithKEK(kek))
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	snap, err := pg.LoadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sec := findSDSSecret(t, builders.BuildSecrets(snap.Secrets), "enc-cert")
	if got := sec.GetTlsCertificate().GetPrivateKey().GetInlineString(); got != string(keyPEM) {
		t.Error("BuildSecrets must serve the DECRYPTED original key PEM")
	}

	// Control-plane with NO KEK: a sealed key must fail LOUDLY (never serve ciphertext).
	pgNoKEK, err := store.NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pgNoKEK.Close()
	if _, err := pgNoKEK.LoadSnapshot(ctx); err == nil {
		t.Error("LoadSnapshot with no KEK must fail on a sealed key (fail-closed)")
	}
}

// KEK ROTATION (B28.234): a key written under KEK A; the custodian and the
// control-plane move to KEK B with A as previous; an operator re-seals through
// the component; A is dropped — and the control-plane, holding B alone, still
// serves the ORIGINAL key over SDS. A keyring of A alone no longer can.
func TestE2E_KEKRotationKeepsSDSServing(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required (integration)")
	}
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "TRUNCATE secrets, routes, gateways, clusters, endpoints CASCADE"); err != nil {
		t.Fatal(err)
	}
	kekA := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // 32 bytes, test only
	kekB := []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	storedKey := func() string {
		t.Helper()
		var v string
		if err := conn.QueryRow(ctx, "SELECT key_pem FROM secrets WHERE name='rot-cert'").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	// servedKey loads a snapshot as a control-plane holding ring and returns
	// the private key BuildSecrets serves for rot-cert.
	servedKey := func(ring *keycrypt.Keyring) (string, error) {
		t.Helper()
		pg, err := store.NewPostgresStore(ctx, dsn, store.WithKeyring(ring))
		if err != nil {
			t.Fatal(err)
		}
		defer pg.Close()
		snap, err := pg.LoadSnapshot(ctx)
		if err != nil {
			return "", err
		}
		return findSDSSecret(t, builders.BuildSecrets(snap.Secrets), "rot-cert").
			GetTlsCertificate().GetPrivateKey().GetInlineString(), nil
	}

	// 1. Written under A.
	before, err := NewStore(ctx, dsn, WithKEK(kekA))
	if err != nil {
		t.Fatal(err)
	}
	srvCA := newTestCA(t, "svc-ca")
	certPEM, keyPEM := srvCA.leaf(t, "rot.example.com", true)
	if err := before.Upsert(ctx, "rot-cert", string(certPEM), string(keyPEM), "tls_certificate"); err != nil {
		t.Fatal(err)
	}
	before.Close()
	if v := storedKey(); !strings.HasPrefix(v, keycrypt.MarkerV2+keycrypt.KeyID(kekA)+":") {
		t.Fatalf("written under A: want enc:v2:%s:...; got %.24q", keycrypt.KeyID(kekA), v)
	}

	// 2. Mid-rotation (B current, A previous): still served.
	during := keycrypt.NewKeyring(kekB, kekA)
	if got, err := servedKey(during); err != nil || got != string(keyPEM) {
		t.Fatalf("mid-rotation SDS must serve the original key; err %v", err)
	}

	// 3. The operator re-seals through the component (mTLS, admin CA).
	cs, err := NewStore(ctx, dsn, WithKeyring(during))
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	serverCA := newTestCA(t, "server-ca")
	adminCA := newTestCA(t, "edge-admin-ca")
	ts := tlsTestServer(t, NewServer(cs, "", discardLog()), serverCA, "", writeTemp(t, adminCA.certPEM))
	opCert, opKey := adminCA.leaf(t, "operator", false)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/reseal", nil)
	resp, err := mtlsClient(t, serverCA.certPEM, opCert, opKey).Do(req)
	if err != nil {
		t.Fatalf("operator re-seal via component: %v", err)
	}
	var res struct {
		KeyID    string `json:"key_id"`
		Resealed int    `json:"resealed"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || res.KeyID != keycrypt.KeyID(kekB) || res.Resealed != 1 {
		t.Fatalf("re-seal: want 200, key_id %s, 1 re-sealed; got %d, %+v", keycrypt.KeyID(kekB), resp.StatusCode, res)
	}
	if v := storedKey(); !strings.HasPrefix(v, keycrypt.MarkerV2+keycrypt.KeyID(kekB)+":") {
		t.Fatalf("after re-seal: want enc:v2:%s:...; got %.24q", keycrypt.KeyID(kekB), v)
	}

	// 4. A dropped: the control-plane holding B alone serves the original key.
	if got, err := servedKey(keycrypt.NewKeyring(kekB)); err != nil || got != string(keyPEM) {
		t.Fatalf("after rotation SDS must serve the original key; err %v", err)
	}
	if _, err := servedKey(keycrypt.NewKeyring(kekA)); err == nil {
		t.Error("the retired KEK alone must no longer open the key (fail-closed)")
	}
}
