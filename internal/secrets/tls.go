package secrets

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// buildServerTLS builds the http.Server TLS config: the server cert always, and
// — when an admin CA is configured — client-cert verification against THAT CA
// (never the data-plane CA). The ClientAuth mode depends on whether the
// admin-key fallback is enabled (see GREEN): RequireAndVerifyClientCert when
// mTLS is the only auth, VerifyClientCertIfGiven when the key fallback coexists.
func buildServerTLS(cfg *Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if cfg.AdminCAFile != "" {
		pemBytes, err := os.ReadFile(cfg.AdminCAFile)
		if err != nil {
			return nil, fmt.Errorf("read admin CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("admin CA file contained no valid certificates: %s", cfg.AdminCAFile)
		}
		// Client certs are verified ONLY against the admin CA — never the
		// data-plane edge-internal-ca — so a proxy identity can never write keys.
		tlsCfg.ClientCAs = pool
		if cfg.AdminAPIKey == "" {
			// mTLS is the only auth → mandatory client cert.
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			// Admin-key fallback coexists → verify a cert IF given, else the HTTP
			// layer requires the key. A GIVEN cert must still verify against the
			// admin CA (so a proxy cert is rejected at the handshake either way).
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	return tlsCfg, nil
}
