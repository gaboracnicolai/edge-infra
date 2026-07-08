//go:build integration

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/jackc/pgx/v5"

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
