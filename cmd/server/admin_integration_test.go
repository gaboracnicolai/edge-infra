//go:build integration

// End-to-end proof for the Admin READ API against a REAL Postgres: every
// endpoint serves 200 through the real store + reconciler wiring, and NO
// response body carries key material — by PEM header, by plaintext key bytes,
// or by sealed ciphertext — even though the database holds both a plaintext
// and a KEK-sealed private key.
//
// The admin store handle is deliberately constructed WITHOUT the KEK: the
// admin readers must not merely avoid leaking keys, they must not even need
// the ABILITY to decrypt them. (The reconciler's own handle gets the KEK —
// decrypting for SDS is its job, and only its job.)
package main

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/config"
	"github.com/edge-infra/control-plane/internal/keycrypt"
	"github.com/edge-infra/control-plane/internal/store"
	"github.com/edge-infra/control-plane/internal/xds"
)

const e2ePrefix = "admine2e-"

// e2eSnapshotStore is a minimal store.Store serving one consistent, secret-free
// snapshot so the REAL reconciler can publish and track ACKs without touching
// the shared database (see the wiring comment in the test body). The write
// methods are never called.
type e2eSnapshotStore struct{}

func (e2eSnapshotStore) LoadSnapshot(context.Context) (*store.Snapshot, error) {
	return &store.Snapshot{
		Gateways: []store.Gateway{{ID: "e2e-gw", Name: "e2e-gw", Port: 8080, Protocol: "HTTP"}},
		Routes: []store.Route{{ID: "e2e-rt", Name: "e2e-rt", GatewayID: "e2e-gw",
			Hosts: []string{"*"}, PathPrefix: "/", ClusterName: "e2e-cl",
			TimeoutSeconds: 30, AuthPolicy: "none"}},
		Clusters:  []store.Cluster{{ID: "e2e-cl", Name: "e2e-cl", ConnectTimeout: 5 * time.Second, LbPolicy: "ROUND_ROBIN"}},
		Endpoints: []store.Endpoint{{ID: "e2e-ep", ClusterID: "e2e-cl", Address: "10.0.0.1", Port: 8080, Weight: 1}},
	}, nil
}
func (e2eSnapshotStore) UpsertGateway(context.Context, store.Gateway) error { return nil }
func (e2eSnapshotStore) DeleteGateway(context.Context, string) error        { return nil }
func (e2eSnapshotStore) UpsertRoute(context.Context, store.Route) error     { return nil }
func (e2eSnapshotStore) DeleteRoute(context.Context, string, string) error  { return nil }
func (e2eSnapshotStore) Close()                                             {}

func TestAdminAPI_E2E_AllEndpointsServeAndNothingLeaks(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required (shared DB with BOTH schemas — supplied by make test-integration / osb-test.yaml)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)

	// --- Seed a world under e2ePrefix ------------------------------------
	certPEM, keyPEM := adminTestCertKey(t, "admine2e-cert")
	kek := make([]byte, 32)
	_, err = rand.Read(kek)
	require.NoError(t, err)
	sealed, err := keycrypt.Seal(kek, keyPEM)
	require.NoError(t, err)

	// Cleanup registered BEFORE seeding (partial seeds clean up too), on its
	// OWN connection: t.Cleanup runs after the deferred conn.Close above, so
	// the test's connection is already gone by then.
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer ccancel()
		cleanConn, cErr := pgx.Connect(cctx, dsn)
		if cErr != nil {
			t.Errorf("cleanup connect: %v", cErr)
			return
		}
		defer cleanConn.Close(cctx)
		for _, sql := range []string{
			`DELETE FROM routes WHERE name LIKE 'admine2e-%'`,
			`DELETE FROM clusters WHERE name LIKE 'admine2e-%'`,
			`DELETE FROM gateways WHERE name LIKE 'admine2e-%'`,
			`DELETE FROM secrets WHERE name LIKE 'admine2e-%'`,
			`DELETE FROM services WHERE team = 'admine2e-team'`,
			`DELETE FROM provision_requests WHERE team = 'admine2e-team'`,
		} {
			if _, dErr := cleanConn.Exec(cctx, sql); dErr != nil {
				t.Errorf("cleanup %q: %v", sql, dErr)
			}
		}
	})

	exec := func(sql string, args ...any) {
		t.Helper()
		_, execErr := conn.Exec(ctx, sql, args...)
		require.NoError(t, execErr, sql)
	}
	exec(`INSERT INTO secrets (id, name, cert_pem, key_pem, kind) VALUES
		('admine2e-cert-plain','admine2e-cert-plain',$1,$2,'tls_certificate'),
		('admine2e-cert-sealed','admine2e-cert-sealed',$1,$3,'tls_certificate')`,
		certPEM, keyPEM, sealed)
	exec(`INSERT INTO gateways (id, name, port, protocol, tls_secret, node_selector) VALUES
		('admine2e-gw','admine2e-gw',9443,'HTTPS','admine2e-cert-plain','{}')`)
	exec(`INSERT INTO clusters (id, name, connect_timeout_ms, lb_policy) VALUES
		('admine2e-cl','admine2e-cl',5000,'ROUND_ROBIN')`)
	exec(`INSERT INTO endpoints (id, cluster_id, address, port, weight) VALUES
		('admine2e-ep','admine2e-cl','10.7.7.7',8080,1)`)
	exec(`INSERT INTO routes (id, name, gateway_id, hosts, path_prefix, cluster_name, auth_policy) VALUES
		('admine2e-rt','admine2e-rt','admine2e-gw','{e2e.local}','/e2e','admine2e-cl','jwt')`)
	exec(`INSERT INTO services (name, team, host, port, protocol, auth_policy) VALUES
		('admine2e-svc','admine2e-team','svc.e2e.local',8080,'HTTP','jwt')`)
	exec(`INSERT INTO provision_requests (id, operation, status, payload, team, error, created_at) VALUES
		(gen_random_uuid(),'CREATE','FAILED','{}','admine2e-team','admine2e boom',NOW() + interval '4 hours')`)

	// --- Real wiring ------------------------------------------------------
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Admin handle: WITHOUT the KEK — the admin path must never need it.
	adminPG, err := store.NewPostgresStore(ctx, dsn)
	require.NoError(t, err)
	defer adminPG.Close()

	// The reconciler feeds /admin/v1/nodes purely from in-memory ACK state —
	// it never reads the DB for that view — so it publishes from an in-test
	// snapshot here. Pointing it at the shared DB would couple THIS test to
	// every secret's decryptability (the earlier custodian E2E leaves a row
	// sealed under its own KEK), which is exactly the coupling the admin path
	// itself is proven free of.
	cache := cachev3.NewSnapshotCache(true, cachev3.IDHash{}, nil)
	rec := xds.NewReconciler(cache, e2eSnapshotStore{}, "admine2e-node", log)
	require.NoError(t, rec.Reconcile(ctx), "reconcile must publish the in-test snapshot")
	published := rec.PublishedVersion()
	require.NotEmpty(t, published)
	rec.RecordNodeAck("admine2e-envoy-current", published)
	rec.RecordNodeAck("admine2e-envoy-stale", "old-version")

	cfg := &config.Config{
		ListenAddr:        ":18000",
		NodeID:            "admine2e-node",
		ReconcileInterval: 5 * time.Second,
		ExtAuthzAddress:   "auth-service.infra.svc.cluster.local",
		ExtAuthzPort:      50051,
	}
	deps := adminDeps{
		store: adminPG,
		nodes: rec,
		cfg:   newAdminConfigView(cfg),
		key:   "e2e-admin-key",
		log:   log,
	}
	ts := httptest.NewServer(newAdminHandler(deps))
	defer ts.Close()

	get := func(path, key string) (int, []byte) {
		t.Helper()
		req, reqErr := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		require.NoError(t, reqErr)
		if key != "" {
			req.Header.Set("X-Admin-Key", key)
		}
		resp, doErr := ts.Client().Do(req)
		require.NoError(t, doErr)
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		return resp.StatusCode, body
	}

	// --- Auth fail-closed -------------------------------------------------
	code, _ := get("/admin/v1/topology", "")
	assert.Equal(t, http.StatusUnauthorized, code)
	code, _ = get("/admin/v1/topology", "wrong")
	assert.Equal(t, http.StatusUnauthorized, code)

	// --- Every endpoint: 200 and key-free ---------------------------------
	keySentinel := keyByteSentinel(t, keyPEM)
	sealedSentinel := sealed[:40] // ciphertext leaking would be a bug too
	bodies := map[string][]byte{}
	for _, p := range adminPaths {
		code, body := get(p, "e2e-admin-key")
		require.Equal(t, http.StatusOK, code, "%s must serve against the real DB", p)
		require.False(t, bodyLeaksKeyMaterial(body, keySentinel, sealedSentinel),
			"%s response carries key material", p)
		bodies[p] = body
	}

	// --- Spot-check content from the real DB ------------------------------
	assert.Contains(t, string(bodies["/admin/v1/topology"]), "admine2e-gw")
	assert.Contains(t, string(bodies["/admin/v1/topology"]), `"auth_policy":"jwt"`)
	assert.Contains(t, string(bodies["/admin/v1/certificates"]), "admine2e-cert-sealed",
		"the SEALED cert row must be reportable without the KEK")
	assert.Contains(t, string(bodies["/admin/v1/certificates"]), `"fingerprint_sha256"`)
	assert.Contains(t, string(bodies["/admin/v1/provisioning"]), `"admine2e boom"`,
		"FAILED request error must surface")
	assert.Contains(t, string(bodies["/admin/v1/nodes"]), `"scope":"connected-only"`)
	assert.Contains(t, string(bodies["/admin/v1/nodes"]), "admine2e-envoy-stale")
	assert.Contains(t, string(bodies["/admin/v1/nodes"]), `"behind":true`)
	assert.Contains(t, string(bodies["/admin/v1/config"]), `"read_only":true`)
	assert.Contains(t, string(bodies["/admin/v1/config"]), `"enabled":false`,
		"effective ext_authz state (default off) must be reported")
}
