package secrets

import (
	"crypto/tls"
	"regexp"
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
