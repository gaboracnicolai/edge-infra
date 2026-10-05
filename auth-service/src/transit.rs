//! Signed transit assertion: the short-lived, single-use proof that a request
//! passed through this gateway, carried in `x-gateway-auth`.
//!
//! It replaces the static shared secret that header used to carry. A leaked
//! secret let anyone forge identity headers forever; an assertion is an EdDSA
//! JWT that expires within seconds, names one request (method + host + path),
//! vouches for one identity, and carries a `jti` a backend accepts only once.
//! Backends verify it with the gateway's PUBLIC key — published as a JWKS at
//! `/.well-known/transit-jwks.json` on the metrics port — so no backend ever
//! holds anything that could mint one.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::AppError;

/// The header the assertion travels in.
pub const HEADER: &str = "x-gateway-auth";

/// Clock skew tolerated between the gateway and a backend, in seconds.
pub const LEEWAY_S: u64 = 5;

/// The longest lifetime a verifier accepts (`exp - iat`), in seconds. Bounds
/// both the replay window and the replay cache, whatever the signer is set to.
pub const MAX_LIFETIME_S: u64 = 60;

/// Claims of a transit assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitClaims {
    /// The gateway that signed it.
    pub iss: String,
    /// The identity it vouches for: the JWT `sub`, or the client cert subject.
    pub sub: String,
    /// How `sub` was authenticated: `jwt`, `mtls`, or `agent` — a workload
    /// token on a keyless edge-egress destination, `sub` its ServiceAccount.
    pub amr: String,
    /// The identity provider (`iss` of the JWT) that vouched for `sub`. With
    /// several trusted issuers, a backend keys identity on (idp, sub).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idp: Option<String>,
    /// Verified email, when the JWT carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Team membership, when the JWT carried any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teams: Option<Vec<String>>,
    /// HTTP method of the request it was minted for.
    pub htm: String,
    /// `host` + `path` of the request it was minted for, as the gateway saw it.
    pub htu: String,
    /// Issued at (seconds since epoch).
    pub iat: u64,
    /// Expires at (seconds since epoch).
    pub exp: u64,
    /// Unique id; a verifier accepts each one once.
    pub jti: String,
}

/// What the gateway vouches for on one request.
#[derive(Debug, Clone, Default)]
pub struct Vouch<'a> {
    pub sub: &'a str,
    pub amr: &'a str,
    pub idp: Option<&'a str>,
    pub email: Option<&'a str>,
    pub teams: Option<&'a [String]>,
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
}

/// Mints transit assertions with the gateway's Ed25519 key.
pub struct TransitSigner {
    key: EncodingKey,
    kid: String,
    /// Raw 32-byte public key, base64url — the JWKS `x`.
    x: String,
    issuer: String,
    ttl_s: u64,
    rng: SystemRandom,
}

impl std::fmt::Debug for TransitSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitSigner")
            .field("kid", &self.kid)
            .field("issuer", &self.issuer)
            .field("ttl_s", &self.ttl_s)
            .finish_non_exhaustive()
    }
}

impl TransitSigner {
    /// Load the signer from a PKCS#8 Ed25519 private key in PEM
    /// (`openssl genpkey -algorithm ed25519`).
    pub fn from_pem(pem: &str, issuer: &str, ttl_s: u64) -> Result<Self, AppError> {
        let der = pem_to_der(pem).ok_or_else(|| {
            AppError::Config("TRANSIT_SIGNING_KEY is not a PEM private key".into())
        })?;
        Self::from_pkcs8(&der, issuer, ttl_s)
    }

    /// Load the signer from PKCS#8 (v1 or v2) Ed25519 DER.
    pub fn from_pkcs8(der: &[u8], issuer: &str, ttl_s: u64) -> Result<Self, AppError> {
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der).map_err(|e| {
            AppError::Config(format!("TRANSIT_SIGNING_KEY is not an Ed25519 key: {e}"))
        })?;
        if ttl_s == 0 || ttl_s > MAX_LIFETIME_S {
            return Err(AppError::Config(format!(
                "TRANSIT_TTL_S must be between 1 and {MAX_LIFETIME_S} (got {ttl_s})"
            )));
        }
        let public = pair.public_key().as_ref();
        let digest = ring::digest::digest(&ring::digest::SHA256, public);
        Ok(Self {
            key: EncodingKey::from_ed_der(der),
            kid: URL_SAFE_NO_PAD.encode(&digest.as_ref()[..12]),
            x: URL_SAFE_NO_PAD.encode(public),
            issuer: issuer.to_string(),
            ttl_s,
            rng: SystemRandom::new(),
        })
    }

    /// Key id stamped in every assertion's header and in the JWKS.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public JWKS a backend verifies assertions against.
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": self.x,
                "kid": self.kid,
                "alg": "EdDSA",
                "use": "sig",
            }]
        })
    }

    /// Mint an assertion for `vouch`, issued now.
    pub fn sign(&self, vouch: &Vouch<'_>) -> Result<String, AppError> {
        self.sign_at(vouch, now_s())
    }

    /// Mint an assertion for `vouch` as if issued at `iat`.
    pub fn sign_at(&self, vouch: &Vouch<'_>, iat: u64) -> Result<String, AppError> {
        let mut jti = [0u8; 16];
        self.rng
            .fill(&mut jti)
            .map_err(|_| AppError::Config("system RNG unavailable".into()))?;
        let claims = TransitClaims {
            iss: self.issuer.clone(),
            sub: vouch.sub.to_string(),
            amr: vouch.amr.to_string(),
            idp: vouch.idp.map(str::to_string),
            email: vouch.email.filter(|e| !e.is_empty()).map(str::to_string),
            teams: vouch
                .teams
                .filter(|t| !t.is_empty())
                .map(<[String]>::to_vec),
            htm: vouch.method.to_string(),
            htu: format!("{}{}", vouch.host, vouch.path),
            iat,
            exp: iat + self.ttl_s,
            jti: URL_SAFE_NO_PAD.encode(jti),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        encode(&header, &claims, &self.key)
            .map_err(|e| AppError::Config(format!("sign transit assertion: {e}")))
    }
}

/// Why a verifier refused an assertion.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransitError {
    #[error("malformed assertion")]
    Malformed,
    #[error("assertion signed by an unknown key")]
    UnknownKey,
    #[error("bad signature")]
    BadSignature,
    #[error("assertion expired")]
    Expired,
    #[error("assertion from the wrong issuer")]
    WrongIssuer,
    #[error("assertion lives longer than {MAX_LIFETIME_S}s")]
    TooLong,
    #[error("assertion was minted for a different request")]
    WrongRequest,
    #[error("assertion already used")]
    Replayed,
}

/// Verifies transit assertions and remembers every `jti` until it expires, so
/// a captured assertion is refused the second time it is presented.
pub struct TransitVerifier {
    keys: HashMap<String, DecodingKey>,
    validation: Validation,
    seen: Mutex<Seen>,
}

#[derive(Default)]
struct Seen {
    /// jti → the second after which it can be forgotten.
    until: HashMap<String, u64>,
    last_prune: u64,
}

impl TransitVerifier {
    /// Build a verifier from the gateway's published JWKS.
    pub fn from_jwks(jwks: &serde_json::Value, issuer: &str) -> Result<Self, AppError> {
        let mut keys = HashMap::new();
        for k in jwks["keys"].as_array().into_iter().flatten() {
            if k["kty"] != "OKP" || k["crv"] != "Ed25519" {
                continue;
            }
            let (Some(kid), Some(x)) = (k["kid"].as_str(), k["x"].as_str()) else {
                continue;
            };
            let key = DecodingKey::from_ed_components(x)
                .map_err(|e| AppError::JwksParse(format!("transit key {kid}: {e}")))?;
            keys.insert(kid.to_string(), key);
        }
        if keys.is_empty() {
            return Err(AppError::JwksParse("no Ed25519 transit key in JWKS".into()));
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[issuer]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "sub"]);
        validation.leeway = LEEWAY_S;
        validation.validate_aud = false;
        Ok(Self {
            keys,
            validation,
            seen: Mutex::new(Seen::default()),
        })
    }

    /// Verify `token` for the request `method host path`. Accepts each valid
    /// assertion exactly once.
    pub fn verify(
        &self,
        token: &str,
        method: &str,
        host: &str,
        path: &str,
    ) -> Result<TransitClaims, TransitError> {
        let kid = decode_header(token)
            .map_err(|_| TransitError::Malformed)?
            .kid
            .ok_or(TransitError::Malformed)?;
        let key = self.keys.get(&kid).ok_or(TransitError::UnknownKey)?;
        let claims = decode::<TransitClaims>(token, key, &self.validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => TransitError::Expired,
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => TransitError::WrongIssuer,
                jsonwebtoken::errors::ErrorKind::InvalidSignature => TransitError::BadSignature,
                _ => TransitError::Malformed,
            })?
            .claims;
        if claims.exp.saturating_sub(claims.iat) > MAX_LIFETIME_S {
            return Err(TransitError::TooLong);
        }
        let now = now_s();
        if claims.iat > now + LEEWAY_S {
            return Err(TransitError::Malformed);
        }
        if claims.htm != method || claims.htu != format!("{host}{path}") {
            return Err(TransitError::WrongRequest);
        }

        // Only a fully valid assertion is remembered, so garbage cannot fill
        // the cache or burn a real jti.
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if now > seen.last_prune {
            seen.until.retain(|_, until| *until >= now);
            seen.last_prune = now;
        }
        if seen.until.contains_key(&claims.jti) {
            return Err(TransitError::Replayed);
        }
        seen.until.insert(claims.jti.clone(), claims.exp + LEEWAY_S);
        Ok(claims)
    }
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decode the body of a single-block PEM file.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    if body.is_empty() || !pem.contains("PRIVATE KEY-----") {
        return None;
    }
    STANDARD.decode(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "edge-gateway";

    fn signer() -> TransitSigner {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("keygen");
        TransitSigner::from_pkcs8(pkcs8.as_ref(), ISSUER, 30).expect("signer")
    }

    fn vouch() -> Vouch<'static> {
        Vouch {
            sub: "user-1",
            amr: "jwt",
            method: "GET",
            host: "api.example.com",
            path: "/orders?id=7",
            ..Default::default()
        }
    }

    fn verifier(s: &TransitSigner) -> TransitVerifier {
        TransitVerifier::from_jwks(&s.jwks(), ISSUER).expect("verifier")
    }

    #[test]
    fn a_fresh_assertion_verifies_and_carries_the_identity() {
        let s = signer();
        let token = s.sign(&vouch()).expect("sign");
        let claims = verifier(&s)
            .verify(&token, "GET", "api.example.com", "/orders?id=7")
            .expect("fresh assertion must verify");
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.amr, "jwt");
        assert_eq!(claims.exp - claims.iat, 30);
    }

    #[test]
    fn a_replayed_assertion_is_rejected() {
        let s = signer();
        let v = verifier(&s);
        let token = s.sign(&vouch()).expect("sign");
        v.verify(&token, "GET", "api.example.com", "/orders?id=7")
            .expect("first use must verify");
        assert_eq!(
            v.verify(&token, "GET", "api.example.com", "/orders?id=7"),
            Err(TransitError::Replayed)
        );
    }

    #[test]
    fn an_expired_assertion_is_rejected() {
        let s = signer();
        let token = s.sign_at(&vouch(), now_s() - 120).expect("sign");
        assert_eq!(
            verifier(&s).verify(&token, "GET", "api.example.com", "/orders?id=7"),
            Err(TransitError::Expired)
        );
    }

    #[test]
    fn an_assertion_for_another_request_is_rejected() {
        let s = signer();
        let token = s.sign(&vouch()).expect("sign");
        assert_eq!(
            verifier(&s).verify(&token, "POST", "api.example.com", "/orders?id=7"),
            Err(TransitError::WrongRequest)
        );
    }

    #[test]
    fn an_assertion_from_another_key_is_rejected() {
        let token = signer().sign(&vouch()).expect("sign");
        assert_eq!(
            verifier(&signer()).verify(&token, "GET", "api.example.com", "/orders?id=7"),
            Err(TransitError::UnknownKey)
        );
    }

    #[test]
    fn the_old_shared_secret_is_not_an_assertion() {
        let s = signer();
        assert_eq!(
            verifier(&s).verify(
                "local-dev-gateway-auth-secret-0123456789",
                "GET",
                "api.example.com",
                "/"
            ),
            Err(TransitError::Malformed)
        );
    }
}
