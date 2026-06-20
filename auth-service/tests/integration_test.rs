//! Integration tests for the ext_authz Authorization service.
//!
//! Each test builds a fresh AuthService backed by an in-memory JWKS containing
//! a freshly generated RSA key pair, then drives `check()` directly.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use auth_service::auth::AuthService;
use auth_service::jwks::JwksCache;
use auth_service::metrics::Metrics;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, HeaderAppendAction, HeaderValueOption, HttpResponse,
};
use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
use envoy_types::pb::envoy::service::auth::v3::attribute_context::{
    HttpRequest, Request as AttrRequest,
};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
    RSAKeyParameters, RSAKeyType,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation, encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use serde::Serialize;
use tonic::Request;

const TEST_AUDIENCE: &str = "edge.example.com";
const TEST_ISSUER: &str = "https://auth.example.com";
const TEST_KID: &str = "test-kid";
const TEST_GATEWAY_SECRET: &str = "test-gateway-shared-secret";

#[derive(Debug, Serialize)]
struct TestClaims {
    sub: String,
    exp: usize,
    iat: usize,
    aud: Vec<String>,
    iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    teams: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

struct Fixture {
    private_pem: String,
    jwks: JwkSet,
}

fn make_fixture(kid: &str) -> Fixture {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate rsa key");
    let public_key = private_key.to_public_key();

    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_operations: None,
            key_algorithm: Some(KeyAlgorithm::RS256),
            key_id: Some(kid.to_string()),
            x509_url: None,
            x509_chain: None,
            x509_sha1_fingerprint: None,
            x509_sha256_fingerprint: None,
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n,
            e,
        }),
    };
    let pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .expect("encode pkcs1 pem");

    Fixture {
        private_pem: pem.to_string(),
        jwks: JwkSet { keys: vec![jwk] },
    }
}

fn now_secs() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as usize
}

fn sign_jwt(private_pem: &str, kid: &str, claims: &TestClaims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("encoding key");
    encode(&header, claims, &key).expect("encode jwt")
}

fn build_check_request(authorization: Option<&str>) -> Request<CheckRequest> {
    build_check_request_with(authorization, &[])
}

/// Like `build_check_request` but lets a test seed extra client-supplied
/// headers — used to prove the gateway overwrites smuggled identity headers.
fn build_check_request_with(
    authorization: Option<&str>,
    extra: &[(&str, &str)],
) -> Request<CheckRequest> {
    let mut headers = HashMap::new();
    if let Some(value) = authorization {
        headers.insert("authorization".to_string(), value.to_string());
    }
    for (key, value) in extra {
        headers.insert((*key).to_string(), (*value).to_string());
    }
    let req = CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(AttrRequest {
                http: Some(HttpRequest {
                    method: "GET".into(),
                    headers,
                    path: "/".into(),
                    host: "example.com".into(),
                    scheme: "http".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    Request::new(req)
}

fn build_service(jwks: JwkSet) -> (AuthService, Arc<Metrics>) {
    let metrics = Metrics::new().expect("metrics");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[TEST_AUDIENCE]);
    validation.set_issuer(&[TEST_ISSUER]);
    let service = AuthService {
        jwks: JwksCache::from_jwk_set(jwks),
        validation,
        metrics: Arc::clone(&metrics),
        gateway_secret: TEST_GATEWAY_SECRET.to_string(),
    };
    (service, metrics)
}

fn header_value<'a>(headers: &'a [HeaderValueOption], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .filter_map(|opt| opt.header.as_ref())
        .find(|h| h.key.eq_ignore_ascii_case(key))
        .map(|h| h.value.as_str())
}

/// Returns the full HeaderValueOption (not just the value) so a test can
/// assert the append action Envoy will apply.
fn header_opt<'a>(
    headers: &'a [HeaderValueOption],
    key: &str,
) -> Option<&'a HeaderValueOption> {
    headers.iter().find(|opt| {
        opt.header
            .as_ref()
            .is_some_and(|h| h.key.eq_ignore_ascii_case(key))
    })
}

fn valid_claims(sub: &str, teams: Option<Vec<String>>) -> TestClaims {
    let now = now_secs();
    TestClaims {
        sub: sub.to_string(),
        exp: now + 3600,
        iat: now,
        aud: vec![TEST_AUDIENCE.to_string()],
        iss: TEST_ISSUER.to_string(),
        teams,
        email: None,
    }
}

#[tokio::test]
async fn test_valid_jwt_returns_ok() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-1", None);
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();

    let code = response
        .status
        .as_ref()
        .expect("status present")
        .code;
    assert_eq!(code, 0, "expected OK (0), got {code}");

    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    assert_eq!(header_value(&ok.headers, "x-user-id"), Some("user-1"));
    assert_eq!(
        header_value(&ok.headers, "x-auth-iss"),
        Some(TEST_ISSUER)
    );
}

#[tokio::test]
async fn test_gateway_auth_header_injected() {
    // The transit-proof header is what lets a backend (e.g. Track) trust
    // x-user-id: without it, an exposed backend port lets anyone forge
    // identity. Every authenticated request must carry the shared secret.
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-7", None);
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();

    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    assert_eq!(
        header_value(&ok.headers, "x-gateway-auth"),
        Some(TEST_GATEWAY_SECRET),
        "gateway must inject the shared transit-proof secret"
    );
}

#[tokio::test]
async fn test_gateway_auth_overwrites_client_supplied_value() {
    // A malicious client tries to smuggle its own transit-proof header in
    // alongside the request. The gateway must overwrite it with the real
    // secret, never append, so the backend never sees the forgery.
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-8", None);
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request_with(
            Some(&auth),
            &[("x-gateway-auth", "forged-by-client")],
        ))
        .await
        .expect("rpc")
        .into_inner();

    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };

    let opt = header_opt(&ok.headers, "x-gateway-auth")
        .expect("x-gateway-auth must be present");
    assert_eq!(
        opt.header.as_ref().map(|h| h.value.as_str()),
        Some(TEST_GATEWAY_SECRET),
        "value must be the real secret, not the client's forgery"
    );
    assert_eq!(
        opt.append_action,
        HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        "transit-proof header must overwrite, never append"
    );
}

#[tokio::test]
async fn test_email_header_forwarded() {
    // The issuer puts the verified email in the JWT; the gateway forwards it
    // as x-user-email so Track can join the identity to its per-workspace
    // member (members are unique by email within a workspace).
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = TestClaims {
        email: Some("ada@example.com".into()),
        ..valid_claims("user-9", None)
    };
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    assert_eq!(
        header_value(&ok.headers, "x-user-email"),
        Some("ada@example.com"),
        "verified email must be forwarded for the workspace-member join"
    );
}

#[tokio::test]
async fn test_email_absent_overwrites_client_supplied_value() {
    // No email claim in the token: the gateway must STILL overwrite any
    // client-supplied x-user-email (to empty) so a caller cannot forge one.
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-10", None); // email: None
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request_with(
            Some(&auth),
            &[("x-user-email", "forged@evil.com")],
        ))
        .await
        .expect("rpc")
        .into_inner();
    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    let opt = header_opt(&ok.headers, "x-user-email")
        .expect("x-user-email must be present, overwriting any client value");
    assert_eq!(
        opt.header.as_ref().map(|h| h.value.as_str()),
        Some(""),
        "absent email must overwrite the client's forgery with empty"
    );
    assert_eq!(
        opt.append_action,
        HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        "x-user-email must overwrite, never append"
    );
}

#[tokio::test]
async fn test_missing_auth_header_denied() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks);

    let response = svc
        .check(build_check_request(None))
        .await
        .expect("rpc")
        .into_inner();

    let code = response.status.expect("status").code;
    assert_eq!(code, 16, "expected UNAUTHENTICATED (16), got {code}");
}

#[tokio::test]
async fn test_expired_jwt_denied() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let now = now_secs();
    let claims = TestClaims {
        sub: "user-2".into(),
        exp: now - 3600,
        iat: now - 7200,
        aud: vec![TEST_AUDIENCE.into()],
        iss: TEST_ISSUER.into(),
        teams: None,
        email: None,
    };
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(response.status.expect("status").code, 16);
}

#[tokio::test]
async fn test_wrong_audience_denied() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let now = now_secs();
    let claims = TestClaims {
        sub: "user-3".into(),
        exp: now + 3600,
        iat: now,
        aud: vec!["someone-else".into()],
        iss: TEST_ISSUER.into(),
        teams: None,
        email: None,
    };
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(response.status.expect("status").code, 16);
}

#[tokio::test]
async fn test_unknown_kid_denied() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-4", None);
    // sign with a kid that isn't in the JWKS
    let token = sign_jwt(&fix.private_pem, "rogue-kid", &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(response.status.expect("status").code, 16);
}

#[tokio::test]
async fn test_teams_header_forwarded() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-5", Some(vec!["eng".into(), "platform".into()]));
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    assert_eq!(
        header_value(&ok.headers, "x-user-teams"),
        Some("eng,platform")
    );
}

#[tokio::test]
async fn test_metrics_incremented() {
    let fix = make_fixture(TEST_KID);
    let (svc, metrics) = build_service(fix.jwks.clone());

    // One denied
    let _ = svc
        .check(build_check_request(None))
        .await
        .expect("rpc");

    // One OK
    let claims = valid_claims("user-6", None);
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");
    let _ = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc");

    let ok_count = metrics.auth_requests.with_label_values(&["ok"]).get();
    let denied_count = metrics.auth_requests.with_label_values(&["denied"]).get();
    assert_eq!(ok_count, 1, "ok counter");
    assert_eq!(denied_count, 1, "denied counter");
}
