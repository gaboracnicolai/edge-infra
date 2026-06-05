package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// buildTLSCreds constructs gRPC transport credentials from cert-manager-issued files.
// Returns nil when certFile is empty (plaintext mode). Requires both certFile and keyFile.
// Setting caFile additionally enables mTLS (RequireAndVerifyClientCert).
func buildTLSCreds(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	if certFile == "" {
		return nil, nil
	}
	if keyFile == "" {
		return nil, fmt.Errorf("XDS_TLS_KEY must be set when XDS_TLS_CERT is set")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file contained no valid certificates: %s", caFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return credentials.NewTLS(cfg), nil
}
