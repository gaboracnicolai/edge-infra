//! Implementation of Envoy's ext_authz Authorization service.

use std::sync::Arc;

use envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, CheckResponse, HeaderAppendAction, HttpStatusCode,
};
use envoy_types::ext_authz::v3::{
    CheckRequestExt, CheckResponseExt, DeniedHttpResponseBuilder, OkHttpResponseBuilder,
};
use jsonwebtoken::{decode, decode_header, Validation};
use serde::Deserialize;
use tonic::{Request, Response, Status};

use crate::jwks::JwksCache;
use crate::metrics::Metrics;

/// JWT claims the service inspects. `aud` is validated by jsonwebtoken.
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    /// Subject identifier (typically the user ID).
    pub sub: String,
    /// Expiration time (seconds since epoch).
    pub exp: usize,
    /// Issued-at time (seconds since epoch).
    pub iat: usize,
    /// Intended audience(s); validated against the configured audience.
    pub aud: Vec<String>,
    /// Issuer; validated against the configured issuer.
    pub iss: String,
    /// Optional team membership; forwarded as `x-user-teams`.
    pub teams: Option<Vec<String>>,
    /// Optional verified email; forwarded as `x-user-email` so backends can
    /// join the identity to their own per-workspace member records.
    pub email: Option<String>,
}

/// gRPC ext_authz service: validates a Bearer JWT and forwards identity headers.
#[derive(Debug)]
pub struct AuthService {
    /// JWKS used to resolve signing keys by `kid`.
    pub jwks: Arc<JwksCache>,
    /// Pre-built validation config (algorithm, audience, issuer).
    pub validation: Validation,
    /// Metrics handle shared with the metrics HTTP server.
    pub metrics: Arc<Metrics>,
    /// Shared transit-proof secret injected as `x-gateway-auth` so backends
    /// can verify a request actually passed through this gateway.
    pub gateway_secret: String,
}

#[tonic::async_trait]
impl Authorization for AuthService {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let req = request.into_inner();

        // jwt_or_mtls: if this route allows mTLS and Envoy forwarded a verified
        // client cert (source.certificate, populated by include_peer_certificate),
        // authorize on the cert alone — injecting a TRANSPORT marker, never a user
        // identity. A cert-less caller falls through to the JWT path below.
        if let Some(subject) = mtls_cert_subject(&req) {
            self.metrics
                .auth_requests
                .with_label_values(&["ok_mtls"])
                .inc();
            return Ok(Response::new(self.allow_mtls(&subject)));
        }

        let headers = match req.get_client_headers() {
            Some(h) => h,
            None => return Ok(Response::new(self.denied("client headers missing"))),
        };

        let auth_header = match headers
            .get("authorization")
            .or_else(|| headers.get("Authorization"))
        {
            Some(v) => v,
            None => return Ok(Response::new(self.denied("missing authorization header"))),
        };

        let token = match auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
        {
            Some(t) => t,
            None => return Ok(Response::new(self.denied("Bearer scheme required"))),
        };

        let timer = self.metrics.jwt_validation.start_timer();

        let kid = match decode_header(token) {
            Ok(h) => match h.kid {
                Some(k) => k,
                None => {
                    drop(timer);
                    return Ok(Response::new(self.denied("JWT missing kid")));
                }
            },
            Err(_) => {
                drop(timer);
                return Ok(Response::new(self.denied("malformed JWT")));
            }
        };

        let key = match self.jwks.get_key(&kid) {
            Some(k) => k,
            None => {
                drop(timer);
                return Ok(Response::new(self.denied("unknown kid")));
            }
        };

        let claims = match decode::<Claims>(token, &key, &self.validation) {
            Ok(data) => data.claims,
            Err(err) => {
                drop(timer);
                return Ok(Response::new(self.denied(&format!("invalid JWT: {err}"))));
            }
        };

        timer.observe_duration();

        let teams = claims.teams.clone().unwrap_or_default().join(",");
        let email = claims.email.clone().unwrap_or_default();

        let mut builder = OkHttpResponseBuilder::new();
        builder
            // OverwriteIfExistsOrAdd ensures a malicious client can't smuggle
            // these identity headers in alongside their own value.
            .add_header(
                "x-user-id",
                claims.sub.clone(),
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                false,
            )
            .add_header(
                "x-user-teams",
                teams,
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                true,
            )
            .add_header(
                "x-auth-iss",
                claims.iss.clone(),
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                false,
            )
            // Verified email for the backend's workspace-member join. Always
            // overwrite (keep_empty_value = true) so a missing claim still
            // strips any x-user-email a client tried to smuggle in.
            .add_header(
                "x-user-email",
                email,
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                true,
            )
            // Transit-proof: stamp the shared secret so a backend can verify
            // this request actually came through the gateway. Overwrite (not
            // append) strips any value a client tried to smuggle in.
            .add_header(
                "x-gateway-auth",
                self.gateway_secret.clone(),
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                false,
            );

        let mut response = CheckResponse::with_status(Status::ok("ok"));
        response.set_http_response(builder);

        self.metrics.auth_requests.with_label_values(&["ok"]).inc();
        Ok(Response::new(response))
    }
}

impl AuthService {
    /// Build a 401-with-body deny response and bump the denied counter.
    fn denied(&self, msg: &str) -> CheckResponse {
        self.metrics
            .auth_requests
            .with_label_values(&["denied"])
            .inc();

        let mut builder = DeniedHttpResponseBuilder::new();
        builder
            .set_http_status(HttpStatusCode::Unauthorized)
            .set_body(msg.to_string());

        let mut response = CheckResponse::with_status(Status::unauthenticated(msg));
        response.set_http_response(builder);
        response
    }

    /// Authorize a request that presented a verified client cert on a jwt_or_mtls
    /// route. Injects a TRANSPORT marker (`x-auth-method: mtls` + the cert
    /// subject) and the gateway transit-proof — deliberately NOT
    /// `x-user-id`/`x-user-teams`/`x-user-email`, so a client cert never
    /// masquerades as a user identity. The subject is informational for the
    /// backend; identity semantics differ from the JWT path by design.
    fn allow_mtls(&self, cert_subject: &str) -> CheckResponse {
        let mut builder = OkHttpResponseBuilder::new();
        for (name, value) in mtls_headers(cert_subject, &self.gateway_secret) {
            // keep_empty_value=true so a missing/unparseable subject still strips
            // any value a client tried to smuggle in under these header names.
            builder.add_header(
                name,
                value,
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                true,
            );
        }
        let mut response = CheckResponse::with_status(Status::ok("ok"));
        response.set_http_response(builder);
        response
    }
}

/// The headers injected for a cert-authorized (jwt_or_mtls) request: a transport
/// marker, the cert subject, and the gateway transit-proof. Deliberately excludes
/// every x-user-* header — a client cert authorizes transit, it does NOT
/// masquerade as a user identity (that is only the JWT path's job).
fn mtls_headers(cert_subject: &str, gateway_secret: &str) -> Vec<(&'static str, String)> {
    vec![
        ("x-auth-method", "mtls".to_string()),
        ("x-client-cert-subject", cert_subject.to_string()),
        ("x-gateway-auth", gateway_secret.to_string()),
    ]
}

/// Decide whether to authorize on a client cert: Some(subject) when this route is
/// jwt_or_mtls AND Envoy forwarded a verified peer certificate; None otherwise
/// (the caller falls back to the JWT path). Pure so it is unit-testable without a
/// full AuthService.
fn mtls_cert_subject(req: &CheckRequest) -> Option<String> {
    let attrs = req.attributes.as_ref()?;
    if attrs
        .context_extensions
        .get("auth_policy")
        .map(String::as_str)
        != Some("jwt_or_mtls")
    {
        return None;
    }
    let cert = &attrs.source.as_ref()?.certificate;
    if cert.is_empty() {
        return None;
    }
    Some(client_cert_subject(cert))
}

/// Parse the Subject DN from Envoy's URL+PEM-encoded peer certificate
/// (source.certificate). Best effort: returns "" if it can't be decoded/parsed —
/// the cert was ALREADY verified by Envoy's validation_context, so authorization
/// still proceeds; only the informational subject header is empty.
fn client_cert_subject(url_encoded_pem: &str) -> String {
    let decoded = match percent_encoding::percent_decode_str(url_encoded_pem).decode_utf8() {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    match x509_parser::pem::parse_x509_pem(decoded.as_bytes()) {
        Ok((_, pem)) => match pem.parse_x509() {
            Ok(cert) => cert.subject().to_string(),
            Err(_) => String::new(),
        },
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_types::pb::envoy::service::auth::v3::{attribute_context, AttributeContext};
    use std::collections::HashMap;

    // A self-signed test client cert, subject "CN=test-client, O=EdgeInfra".
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDNDCCAhygAwIBAgITA0zI5QMNOSftMEOJqr1g8evsNzANBgkqhkiG9w0BAQsF\n\
ADAqMRQwEgYDVQQDDAt0ZXN0LWNsaWVudDESMBAGA1UECgwJRWRnZUluZnJhMB4X\n\
DTI2MDcwODIyMjkxM1oXDTM2MDcwNTIyMjkxM1owKjEUMBIGA1UEAwwLdGVzdC1j\n\
bGllbnQxEjAQBgNVBAoMCUVkZ2VJbmZyYTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n\
ADCCAQoCggEBAJ+Nb+g57/Dpgmv2K6Q+dfQfm+8RUL8iWmIJch5ENoFHSUDG/g7n\n\
qm0ZxEXTTQriWrlerO0El2zThKSH7Z5TJ7mNT6XuTeUlf210LmW54/uAu0NpKtwi\n\
Bli6X6Wh/uOp0jjyZ7NENwoXqvJ/YAhdLGyqmvTGP2WQxJpNjywP86KqcQQ97tng\n\
TlulwGtV3zgjnALzBX2UmPK4PpTAlvM577L0u49L0/AnfWOFka3OgqvAdXbkUhbN\n\
e4ibKX/9cwYV21V4DyV5VsDZwjlrQ3dZgNK6aE+PE+LCWAWId8p/tkyMkRED6aKS\n\
OPYQEa0qDXtJkoRmApopxH/MKjueGzfct08CAwEAAaNTMFEwHQYDVR0OBBYEFDhd\n\
FZh5wqENkzpAhUXkH7PsfmfAMB8GA1UdIwQYMBaAFDhdFZh5wqENkzpAhUXkH7Ps\n\
fmfAMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJWsToocNzg2\n\
6bLDv0b53j6Q4mp69JHlhfYI7RHrF/8F8J8NY+hPtt62nnlcJT0mkfo7LirdQFtV\n\
Q+Rm+prpJyBhaTqYJS+pQcEFumAw9JSk+0URX2EtfwGNeFjfs4igD9R4pC8Bkql4\n\
+KJ+9O7/2A7GzoAhu/3UYs/es4fW2Q9FG1mksF+sIu/zEBdYwiYifRDChkxIzwBf\n\
zUExQh59l4e7Ya2Ei+gnhdmnq33W9+J1C3JfKv7U87Qk2tlXt8UCnJORsIDxNg3a\n\
hFUpfp8pVELdEiLTqryJQ/H/YbkQqKZudUOIAryeR5MIAaGvesIdaygG6QvVbM2j\n\
aMVnTHM8GoM=\n\
-----END CERTIFICATE-----\n";

    fn req_with(auth_policy: Option<&str>, cert: Option<&str>) -> CheckRequest {
        let mut ctx = HashMap::new();
        if let Some(p) = auth_policy {
            ctx.insert("auth_policy".to_string(), p.to_string());
        }
        let source = cert.map(|c| attribute_context::Peer {
            certificate: c.to_string(),
            ..Default::default()
        });
        CheckRequest {
            attributes: Some(AttributeContext {
                source,
                context_extensions: ctx,
                ..Default::default()
            }),
        }
    }

    // A jwt_or_mtls route WITH a presented cert → authorize on the cert; the
    // subject carries the cert's CN.
    #[test]
    fn cert_present_on_jwt_or_mtls_authorizes_with_subject() {
        let subject = mtls_cert_subject(&req_with(Some("jwt_or_mtls"), Some(TEST_CERT_PEM)))
            .expect("jwt_or_mtls + cert must authorize on the cert");
        assert!(
            subject.contains("test-client"),
            "subject must carry the client cert CN; got {subject:?}"
        );
    }

    // A jwt_or_mtls route with NO cert → fall back to the JWT path.
    #[test]
    fn no_cert_on_jwt_or_mtls_falls_back_to_jwt() {
        assert!(mtls_cert_subject(&req_with(Some("jwt_or_mtls"), None)).is_none());
        assert!(mtls_cert_subject(&req_with(Some("jwt_or_mtls"), Some(""))).is_none());
    }

    // A cert on a NON-jwt_or_mtls route (jwt, or no context) → JWT path, never
    // authorized on the cert (no policy confusion).
    #[test]
    fn cert_without_jwt_or_mtls_context_is_ignored() {
        assert!(mtls_cert_subject(&req_with(Some("jwt"), Some(TEST_CERT_PEM))).is_none());
        assert!(mtls_cert_subject(&req_with(None, Some(TEST_CERT_PEM))).is_none());
    }

    // The subject parser extracts the DN from a URL-encoded PEM (as Envoy sends).
    #[test]
    fn client_cert_subject_parses_dn_from_url_encoded_pem() {
        let url_encoded = TEST_CERT_PEM.replace('\n', "%0A");
        let subject = client_cert_subject(&url_encoded);
        assert!(
            subject.contains("test-client"),
            "must parse subject from a URL-encoded PEM; got {subject:?}"
        );
    }

    // The cert path injects ONLY transport markers — never a user identity. This
    // is the load-bearing security property: a client cert must not be able to
    // masquerade as a user (no x-user-id/teams/email).
    #[test]
    fn mtls_headers_are_transport_only_never_user_identity() {
        let hdrs = mtls_headers("CN=test-client", "gw-secret");
        let names: Vec<&str> = hdrs.iter().map(|(n, _)| *n).collect();
        assert!(
            names.contains(&"x-auth-method"),
            "must mark the auth method"
        );
        assert!(
            names.contains(&"x-client-cert-subject"),
            "must carry the cert subject"
        );
        for n in &names {
            assert!(
                !n.starts_with("x-user-"),
                "cert path must NOT inject a user-identity header; found {n}"
            );
        }
        let method = hdrs
            .iter()
            .find(|(n, _)| *n == "x-auth-method")
            .map(|(_, v)| v.as_str());
        assert_eq!(method, Some("mtls"));
    }
}
