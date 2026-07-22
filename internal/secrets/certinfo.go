package secrets

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"time"
)

// CertInfo is the parse-only view of a stored certificate — derived entirely
// from cert_pem, never key material. It is the custodian's GetMeta parse
// (certMeta) in exported, list-friendly form so the control-plane Admin API
// can serve /admin/v1/certificates without duplicating the x509 handling.
type CertInfo struct {
	Fingerprint string    // SHA-256 of the cert DER, hex (matches GetMeta)
	Issuer      string    // pkix.Name of the certificate's issuer
	NotAfter    time.Time // expiry (matches GetMeta)
}

// ParseCertInfo parses the FIRST certificate in a PEM bundle and returns its
// metadata. For kind=validation_context bundles that is the first CA cert —
// the same first-block semantics GetMeta has always had (certMeta composes
// this function, so the two can never drift).
func ParseCertInfo(certPEM string) (CertInfo, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return CertInfo{}, errors.New("no PEM block in cert")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertInfo{}, err
	}
	sum := sha256.Sum256(c.Raw)
	return CertInfo{
		Fingerprint: hex.EncodeToString(sum[:]),
		Issuer:      c.Issuer.String(),
		NotAfter:    c.NotAfter,
	}, nil
}
