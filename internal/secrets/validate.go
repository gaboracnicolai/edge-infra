package secrets

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"regexp"
	"time"
)

// Secret kinds — the SDS shape they render as.
const (
	kindTLSCertificate    = "tls_certificate"    // server cert+key
	kindValidationContext = "validation_context" // cert-only client-CA trust bundle
)

// secretNameRe is the RFC-1123-subdomain shape routes/gateways reference via SDS.
var secretNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`)

func validSecretName(name string) bool {
	return secretNameRe.MatchString(name)
}

// validateKeyPair confirms cert_pem is a valid X.509 cert, key_pem a valid
// private key, and — critically — that the key matches the cert. tls.X509KeyPair
// parses both and cross-checks the public keys, so a mismatched or malformed
// pair is rejected at this chokepoint before any write.
func validateKeyPair(certPEM, keyPEM string) error {
	_, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	return err
}

// validateCABundle confirms cert_pem is a valid, current CA certificate for a
// client-CA trust bundle — there is no key (a CA bundle is a public trust
// anchor). Fail-closed at the chokepoint, like the server-cert pair.
func validateCABundle(certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("no CERTIFICATE PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("malformed certificate")
	}
	if !c.BasicConstraintsValid || !c.IsCA {
		return errors.New("certificate is not a CA")
	}
	// If key usage is asserted at all, it must permit certificate signing.
	if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("CA certificate lacks keyCertSign usage")
	}
	now := time.Now()
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return errors.New("CA certificate is expired or not yet valid")
	}
	return nil
}
