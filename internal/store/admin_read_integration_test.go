//go:build integration

// Real-PG tests for the Admin READ API's key-free store readers, against the
// shared co-located schema (both migration sets applied — the same DB shape
// osb-test.yaml and test/integration/run.sh provide via TEST_DATABASE_URL).
//
// The property under test everywhere here: these readers NEVER touch
// secrets.key_pem. LoadCertificateRows works on a database whose stored key is
// sealed under a KEK the reader does not have — because it never reads it.
package store_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edge-infra/control-plane/internal/keycrypt"
	"github.com/edge-infra/control-plane/internal/store"
)

const adminSeedPrefix = "admintest-"

func adminReadDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required (shared DB with BOTH schemas — supplied by make test-integration / osb-test.yaml)")
	}
	return dsn
}

func adminReadCertKey(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// cleanupAdminRows removes every row a seeder created, on a FRESH connection:
// t.Cleanup runs AFTER the test's deferred conn.Close, so reusing the test's
// connection would silently no-op and leak rows into the shared CI database.
func cleanupAdminRows(t *testing.T, dsn string, teamName string, namePattern string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Errorf("cleanup connect: %v", err)
			return
		}
		defer conn.Close(ctx)
		for _, sql := range []string{
			`DELETE FROM routes WHERE name LIKE '` + namePattern + `'`,
			`DELETE FROM clusters WHERE name LIKE '` + namePattern + `'`, // endpoints cascade
			`DELETE FROM gateways WHERE name LIKE '` + namePattern + `'`,
			`DELETE FROM secrets WHERE name LIKE '` + namePattern + `'`,
			`DELETE FROM services WHERE team = '` + teamName + `'`,
			`DELETE FROM provision_requests WHERE team = '` + teamName + `'`,
		} {
			if _, cErr := conn.Exec(ctx, sql); cErr != nil {
				t.Errorf("cleanup %q: %v", sql, cErr)
			}
		}
	})
}

// seedAdminFixtures inserts a full admin-readable world under adminSeedPrefix:
// active + soft-deleted gateways/routes, a cluster + endpoint, three secrets
// (plaintext key, SEALED key, CA-only), an OSB service and three provision
// requests (newest FAILED). Cleanup (registered FIRST, so partial seeds clean
// up too) removes everything it created.
func seedAdminFixtures(t *testing.T, ctx context.Context, conn *pgx.Conn, dsn string) (plainKeyPEM, sealedValue string) {
	t.Helper()
	cleanupAdminRows(t, dsn, "admintest-team", "admintest-%")

	certPEM, keyPEM := adminReadCertKey(t, "admintest-cert")
	caPEM, _ := adminReadCertKey(t, "admintest-ca")

	// A key sealed under a KEK the store under test does NOT have: proof the
	// readers never attempt (or need) decryption.
	kek := make([]byte, 32)
	_, err := rand.Read(kek)
	require.NoError(t, err)
	sealed, err := keycrypt.Seal(kek, keyPEM)
	require.NoError(t, err)

	exec := func(sql string, args ...any) {
		t.Helper()
		_, execErr := conn.Exec(ctx, sql, args...)
		require.NoError(t, execErr, sql)
	}

	exec(`INSERT INTO secrets (id, name, cert_pem, key_pem, kind) VALUES
		('admintest-cert-plain','admintest-cert-plain',$1,$2,'tls_certificate'),
		('admintest-cert-sealed','admintest-cert-sealed',$1,$3,'tls_certificate'),
		('admintest-ca','admintest-ca',$4,NULL,'validation_context')`,
		certPEM, keyPEM, sealed, caPEM)

	exec(`INSERT INTO gateways (id, name, port, protocol, tls_secret, node_selector) VALUES
		('admintest-gw','admintest-gw',8443,'HTTPS','admintest-cert-plain','{"zone":"a"}'),
		('admintest-gw-deleted','admintest-gw-deleted',8081,'HTTP',NULL,'{}')`)
	exec(`UPDATE gateways SET deleted_at = NOW() WHERE name = 'admintest-gw-deleted'`)

	exec(`INSERT INTO clusters (id, name, connect_timeout_ms, lb_policy) VALUES
		('admintest-cl','admintest-cl',5000,'ROUND_ROBIN')`)
	exec(`INSERT INTO endpoints (id, cluster_id, address, port, weight) VALUES
		('admintest-ep','admintest-cl','10.9.9.9',8080,1)`)

	exec(`INSERT INTO routes (id, name, gateway_id, hosts, path_prefix, cluster_name, auth_policy) VALUES
		('admintest-rt','admintest-rt','admintest-gw','{api.admintest.local}','/admintest','admintest-cl','none'),
		('admintest-rt-deleted','admintest-rt-deleted','admintest-gw','{gone.admintest.local}','/admintest-gone','admintest-cl','jwt')`)
	exec(`UPDATE routes SET deleted_at = NOW() WHERE name = 'admintest-rt-deleted'`)

	exec(`INSERT INTO services (name, team, host, port, protocol, auth_policy) VALUES
		('admintest-svc','admintest-team','svc.admintest.local',8080,'HTTP','jwt')`)

	// created_at pushed into the future so these three are the globally newest
	// rows even in the shared CI database — makes the limit assertion exact.
	exec(`INSERT INTO provision_requests (id, operation, status, payload, team, error, created_at, completed_at) VALUES
		(gen_random_uuid(),'CREATE','PENDING','{}','admintest-team',NULL,NOW() + interval '1 hour',NULL),
		(gen_random_uuid(),'CREATE','COMPLETED','{}','admintest-team',NULL,NOW() + interval '2 hours',NOW() + interval '2 hours'),
		(gen_random_uuid(),'CREATE','FAILED','{}','admintest-team','admintest boom: port conflict',NOW() + interval '3 hours',NULL)`)

	return keyPEM, sealed
}

func TestAdminRead_Topology(t *testing.T) {
	dsn := adminReadDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	seedAdminFixtures(t, ctx, conn, dsn)

	// NOTE: no WithKEK — the topology reader must not need decryption ability.
	s, err := store.NewPostgresStore(ctx, dsn)
	require.NoError(t, err)
	defer s.Close()

	topo, err := s.LoadTopology(ctx)
	require.NoError(t, err)

	var gwNames []string
	for _, g := range topo.Gateways {
		gwNames = append(gwNames, g.Name)
	}
	assert.Contains(t, gwNames, "admintest-gw")
	assert.NotContains(t, gwNames, "admintest-gw-deleted", "soft-deleted gateways are not topology")

	var routeByName = map[string]store.Route{}
	for _, r := range topo.Routes {
		routeByName[r.Name] = r
	}
	require.Contains(t, routeByName, "admintest-rt")
	assert.Equal(t, "none", routeByName["admintest-rt"].AuthPolicy)
	assert.NotContains(t, routeByName, "admintest-rt-deleted")

	var clNames []string
	for _, c := range topo.Clusters {
		clNames = append(clNames, c.Name)
	}
	assert.Contains(t, clNames, "admintest-cl")

	found := false
	for _, e := range topo.Endpoints {
		if e.ClusterID == "admintest-cl" && e.Address == "10.9.9.9" {
			found = true
		}
	}
	assert.True(t, found, "seeded endpoint must be in the topology")
}

func TestAdminRead_CertificateRows_KeyFreeEvenWhenSealed(t *testing.T) {
	dsn := adminReadDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	plainKey, sealed := seedAdminFixtures(t, ctx, conn, dsn)

	// No WithKEK: this store CANNOT decrypt the sealed row. The reader must
	// still succeed, because it never selects key_pem at all. (LoadSnapshot on
	// this same store would FAIL on the sealed row — that contrast is the point.)
	s, err := store.NewPostgresStore(ctx, dsn)
	require.NoError(t, err)
	defer s.Close()

	rows, err := s.LoadCertificateRows(ctx)
	require.NoError(t, err, "cert rows must load WITHOUT any key/KEK involvement")

	byName := map[string]store.CertificateRow{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	require.Contains(t, byName, "admintest-cert-plain")
	require.Contains(t, byName, "admintest-cert-sealed")
	require.Contains(t, byName, "admintest-ca")
	assert.Equal(t, "tls_certificate", byName["admintest-cert-sealed"].Kind)
	assert.Equal(t, "validation_context", byName["admintest-ca"].Kind)

	// The rows carry certificates — never key material in any form.
	for name, r := range byName {
		if !strings.HasPrefix(name, adminSeedPrefix) {
			continue
		}
		assert.NotContains(t, r.CertPEM, "PRIVATE KEY", "row %s", name)
		assert.NotContains(t, r.CertPEM, plainKey, "row %s", name)
		assert.NotContains(t, r.CertPEM, sealed, "row %s", name)
	}
}

func TestAdminRead_Provisioning_IncludesFailedAndHonorsLimit(t *testing.T) {
	dsn := adminReadDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	seedAdminFixtures(t, ctx, conn, dsn)

	s, err := store.NewPostgresStore(ctx, dsn)
	require.NoError(t, err)
	defer s.Close()

	prov, err := s.LoadProvisioning(ctx, 100)
	require.NoError(t, err)

	var teams []string
	for _, svc := range prov.Services {
		teams = append(teams, svc.Team)
	}
	assert.Contains(t, teams, "admintest-team", "cross-tenant admin view includes every team")

	var failed *store.ProvisionRequest
	for i := range prov.Requests {
		if prov.Requests[i].Team == "admintest-team" && prov.Requests[i].Status == "FAILED" {
			failed = &prov.Requests[i]
		}
	}
	require.NotNil(t, failed, "FAILED requests are the whole point of this endpoint")
	assert.Equal(t, "admintest boom: port conflict", failed.Error)
	assert.Nil(t, failed.CompletedAt)

	// Newest-first + limit: the three seeded rows are the globally newest
	// (future created_at), so limit=2 must return exactly [FAILED, COMPLETED].
	limited, err := s.LoadProvisioning(ctx, 2)
	require.NoError(t, err)
	require.Len(t, limited.Requests, 2)
	assert.Equal(t, "FAILED", limited.Requests[0].Status, "newest first")
	assert.Equal(t, "COMPLETED", limited.Requests[1].Status)
}
