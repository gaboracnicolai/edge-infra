package secrets

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ParseCertInfo is the custodian's GetMeta parse (certMeta) in exported,
// list-form shape for the control-plane Admin API. It reads ONLY the
// certificate — there is no key parameter to even pass. Red before the
// exported parse exists.
func TestParseCertInfo_ValidCert(t *testing.T) {
	notAfter := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	pemBytes := caCertPEM(t, "Edge Admin Test CA", notAfter, true)

	info, err := ParseCertInfo(string(pemBytes))
	require.NoError(t, err)

	// Fingerprint must be the SHA-256 of the DER — the exact value GetMeta
	// computes, so a rotation verified via the custodian matches the admin list.
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	c, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	sum := sha256.Sum256(c.Raw)
	assert.Equal(t, hex.EncodeToString(sum[:]), info.Fingerprint)

	assert.Contains(t, info.Issuer, "Edge Admin Test CA",
		"issuer must carry the certificate's issuer DN")
	assert.WithinDuration(t, c.NotAfter, info.NotAfter, time.Second)
}

// ParseCertInfo and the custodian's certMeta must agree — the admin list and
// GetMeta describe the same certificate the same way.
func TestParseCertInfo_MatchesCustodianCertMeta(t *testing.T) {
	pemBytes := caCertPEM(t, "Parity CA", time.Now().Add(time.Hour), true)

	info, err := ParseCertInfo(string(pemBytes))
	require.NoError(t, err)
	fp, notAfter, err := certMeta(string(pemBytes))
	require.NoError(t, err)

	assert.Equal(t, fp, info.Fingerprint)
	assert.Equal(t, notAfter, info.NotAfter)
}

func TestParseCertInfo_GarbageErrors(t *testing.T) {
	_, err := ParseCertInfo("not a pem at all")
	require.Error(t, err)
}

// A validation_context row can hold a multi-cert CA bundle; the info must come
// from the FIRST certificate — the same first-block semantics GetMeta has.
func TestParseCertInfo_BundleUsesFirstCert(t *testing.T) {
	first := caCertPEM(t, "First CA", time.Now().Add(time.Hour), true)
	second := caCertPEM(t, "Second CA", time.Now().Add(2*time.Hour), true)
	bundle := string(first) + string(second)

	info, err := ParseCertInfo(bundle)
	require.NoError(t, err)

	firstOnly, err := ParseCertInfo(string(first))
	require.NoError(t, err)
	assert.Equal(t, firstOnly.Fingerprint, info.Fingerprint,
		"bundle info must describe the first certificate")
	assert.Contains(t, info.Issuer, "First CA")
}
