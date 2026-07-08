package builders

import (
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"

	"github.com/edge-infra/control-plane/internal/store"
)

func BuildSecrets(secrets []store.Secret) []types.Resource {
	out := make([]types.Resource, 0, len(secrets))
	for _, s := range secrets {
		// A validation_context (cert-only client-CA trust bundle) is served as a
		// trusted_ca — NEVER as a tls_certificate, and with no private key.
		if s.Kind == "validation_context" {
			out = append(out, &tlsv3.Secret{
				Name: s.Name,
				Type: &tlsv3.Secret_ValidationContext{
					ValidationContext: &tlsv3.CertificateValidationContext{
						TrustedCa: &corev3.DataSource{
							Specifier: &corev3.DataSource_InlineString{InlineString: s.CertPEM},
						},
					},
				},
			})
			continue
		}
		// Default / "tls_certificate": server cert + key.
		out = append(out, &tlsv3.Secret{
			Name: s.Name,
			Type: &tlsv3.Secret_TlsCertificate{
				TlsCertificate: &tlsv3.TlsCertificate{
					CertificateChain: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineString{InlineString: s.CertPEM},
					},
					PrivateKey: &corev3.DataSource{
						Specifier: &corev3.DataSource_InlineString{InlineString: s.KeyPEM},
					},
				},
			},
		})
	}
	return out
}
