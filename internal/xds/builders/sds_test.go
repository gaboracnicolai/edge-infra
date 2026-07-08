package builders

import (
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"

	"github.com/edge-infra/control-plane/internal/store"
)

func secretByName(t *testing.T, res []types.Resource, name string) *tlsv3.Secret {
	t.Helper()
	for _, r := range res {
		if s, ok := r.(*tlsv3.Secret); ok && s.GetName() == name {
			return s
		}
	}
	t.Fatalf("secret %q not found", name)
	return nil
}

// THE SDS-SHAPE TEST (load-bearing): a validation_context secret is served as a
// trusted_ca (CertificateValidationContext), NEVER as a tls_certificate, and
// carries no private key.
func TestBuildSecrets_ValidationContext(t *testing.T) {
	sec := secretByName(t, BuildSecrets([]store.Secret{
		{Name: "client-ca", CertPEM: "CA-PEM", Kind: "validation_context"},
	}), "client-ca")

	vc := sec.GetValidationContext()
	if vc == nil {
		t.Fatal("a validation_context secret must emit a ValidationContext (trusted_ca)")
	}
	if got := vc.GetTrustedCa().GetInlineString(); got != "CA-PEM" {
		t.Errorf("trusted_ca = %q; want CA-PEM", got)
	}
	if sec.GetTlsCertificate() != nil {
		t.Error("a validation_context must NOT be emitted as a tls_certificate")
	}
}

// A tls_certificate secret is served as cert+key (unchanged from before).
func TestBuildSecrets_TlsCertificate(t *testing.T) {
	sec := secretByName(t, BuildSecrets([]store.Secret{
		{Name: "server", CertPEM: "CERT", KeyPEM: "KEY", Kind: "tls_certificate"},
	}), "server")

	tc := sec.GetTlsCertificate()
	if tc == nil {
		t.Fatal("a tls_certificate secret must emit a TlsCertificate")
	}
	if tc.GetCertificateChain().GetInlineString() != "CERT" {
		t.Error("certificate chain mismatch")
	}
	if tc.GetPrivateKey().GetInlineString() != "KEY" {
		t.Error("private key mismatch")
	}
	if sec.GetValidationContext() != nil {
		t.Error("a tls_certificate must NOT be emitted as a validation_context")
	}
}

// Backward-compat: an empty Kind (pre-migration read) defaults to tls_certificate.
func TestBuildSecrets_EmptyKind_DefaultsTlsCertificate(t *testing.T) {
	sec := secretByName(t, BuildSecrets([]store.Secret{
		{Name: "legacy", CertPEM: "CERT", KeyPEM: "KEY"}, // Kind == ""
	}), "legacy")
	if sec.GetTlsCertificate() == nil {
		t.Error("an empty-kind secret must default to tls_certificate")
	}
}
