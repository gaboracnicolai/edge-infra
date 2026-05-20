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
    Authorization, CheckRequest, HeaderValueOption, HttpResponse,
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

#[derive(Debug, Serialize)]
struct TestClaims {
    sub: String,
    exp: usize,
    iat: usize,
    aud: Vec<String>,
    iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    teams: Option<Vec<String>>,
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
    let mut headers = HashMap::new();
    if let Some(value) = authorization {
        headers.insert("authorization".to_string(), value.to_string());
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

fn valid_claims(sub: &str, teams: Option<Vec<String>>) -> TestClaims {
    let now = now_secs();
    TestClaims {
        sub: sub.to_string(),
        exp: now + 3600,
        iat: now,
        aud: vec![TEST_AUDIENCE.to_string()],
        iss: TEST_ISSUER.to_string(),
        teams,
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
