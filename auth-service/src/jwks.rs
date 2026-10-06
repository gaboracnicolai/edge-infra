//! JWKS cache with lock-free reads (ArcSwap) and periodic background refresh.
//!
//! The keys come from an HTTPS endpoint or from a file in the pod. A file is a
//! JWKS held in the cluster (a mounted Secret or ConfigMap), so an identity
//! provider the cluster cannot reach is still trusted with no network call.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use tokio::task::JoinHandle;

use crate::error::AppError;
use crate::metrics::Metrics;

/// Where an issuer's signing keys are read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksSource {
    /// Fetched over HTTPS.
    Url(String),
    /// Read from a file in the pod, so nothing leaves the cluster.
    File(String),
}

impl std::fmt::Display for JwksSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwksSource::Url(url) => f.write_str(url),
            JwksSource::File(path) => write!(f, "file:{path}"),
        }
    }
}

/// In-memory JWKS cache. Reads are lock-free via [`ArcSwap`].
#[derive(Debug)]
pub struct JwksCache {
    inner: ArcSwap<JwkSet>,
    client: reqwest::Client,
}

impl JwksCache {
    /// Fetch the JWKS once and build a cache. Fails fast if the upstream is unreachable.
    pub async fn new(url: &str, ca_file: Option<&str>) -> Result<Arc<Self>, AppError> {
        Self::load(&JwksSource::Url(url.to_string()), ca_file).await
    }

    /// Load the JWKS once from `source` and build a cache. Fails fast if the
    /// upstream is unreachable or the file is missing or unparseable.
    pub async fn load(source: &JwksSource, ca_file: Option<&str>) -> Result<Arc<Self>, AppError> {
        let client = build_client(ca_file)?;
        let set = read_jwks(&client, source).await?;
        Ok(Arc::new(Self {
            inner: ArcSwap::new(Arc::new(set)),
            client,
        }))
    }

    /// Build a cache from a pre-loaded JWKS (tests and out-of-band reloads).
    pub fn from_jwk_set(set: JwkSet) -> Arc<Self> {
        Arc::new(Self {
            inner: ArcSwap::new(Arc::new(set)),
            client: reqwest::Client::new(),
        })
    }

    /// Spawn a background task that refreshes the cache every `interval_s` seconds.
    /// A file source is re-read, so updating the mounted Secret rotates the keys.
    ///
    /// A failed refresh logs a warning and increments the failure counter; the
    /// previous snapshot stays in place so the gRPC hot path keeps serving.
    pub fn start_refresh(
        self: Arc<Self>,
        source: JwksSource,
        interval_s: u64,
        metrics: Arc<Metrics>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let interval = Duration::from_secs(interval_s);
            loop {
                tokio::time::sleep(interval).await;
                self.refresh_once(&source, &metrics).await;
            }
        })
    }

    async fn refresh_once(&self, source: &JwksSource, metrics: &Metrics) {
        match read_jwks(&self.client, source).await {
            Ok(new_set) => {
                self.inner.store(Arc::new(new_set));
                metrics.jwks_refresh.with_label_values(&["success"]).inc();
                tracing::debug!(jwks = %source, "jwks refreshed");
            }
            Err(err) => {
                metrics.jwks_refresh.with_label_values(&["failure"]).inc();
                tracing::warn!(error = %err, jwks = %source, "jwks refresh failed; keeping cached set");
            }
        }
    }

    /// Look up a signing key by `kid`. Returns `None` if the key is absent or
    /// is not an RSA key (the only algorithm class this service validates).
    pub fn get_key(&self, kid: &str) -> Option<DecodingKey> {
        let set = self.inner.load();
        let jwk = set.find(kid)?;
        match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                DecodingKey::from_rsa_components(&rsa.n, &rsa.e).ok()
            }
            _ => None,
        }
    }
}

async fn read_jwks(client: &reqwest::Client, source: &JwksSource) -> Result<JwkSet, AppError> {
    let body = match source {
        JwksSource::Url(url) => client.get(url).send().await?.error_for_status()?.text().await?,
        JwksSource::File(path) => tokio::fs::read_to_string(path)
            .await
            .map_err(|e| AppError::Config(format!("read jwks_file {path}: {e}")))?,
    };
    serde_json::from_str::<JwkSet>(&body)
        .map_err(|e| AppError::JwksParse(e.to_string()))
}

/// Build the reqwest client used to fetch the JWKS. When `ca_file` is set, the
/// PEM CA is added to the trust roots so an internal-CA JWKS endpoint (the
/// token issuer) is trusted. Fails closed: a missing or unparseable CA file is
/// an error, never a silent fall back to the default roots.
fn build_client(ca_file: Option<&str>) -> Result<reqwest::Client, AppError> {
    const BEGIN_CERT: &[u8] = b"-----BEGIN CERTIFICATE-----";

    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .map_err(|e| AppError::Config(format!("read JWKS_CA_FILE {path}: {e}")))?;
        // reqwest's from_pem is lenient about input with no PEM blocks, so
        // guard explicitly — a CA file with no certificate must fail closed.
        if !pem.windows(BEGIN_CERT.len()).any(|w| w == BEGIN_CERT) {
            return Err(AppError::Config(format!(
                "JWKS_CA_FILE {path} contains no PEM certificate"
            )));
        }
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| AppError::Config(format!("parse JWKS_CA_FILE {path}: {e}")))?;
        builder = builder.add_root_certificate(cert);
    }
    builder.build().map_err(AppError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_ca_builds_client() {
        assert!(build_client(None).is_ok());
    }

    #[test]
    fn test_missing_ca_file_fails_closed() {
        let err = build_client(Some("/nonexistent/path/to/ca.pem")).unwrap_err();
        assert!(err.to_string().contains("JWKS_CA_FILE"), "error was: {err}");
    }

    const KEYS_A: &str = r#"{"keys":[{"kty":"RSA","kid":"a","use":"sig","alg":"RS256","n":"u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0_IzW7yWR7QkrmBL7jTKEn5u-qKhbwKfBstIs-bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW_VDL5AaWTg0nLVkjRo9z-40RQzuVaE8AkAFmxZzow3x-VJYKdjykkJ0iT9wCS0DRTXu269V264Vf_3jvredZiKRkgwlL9xNAwxXFg0x_XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC-9aGVd-Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw","e":"AQAB"}]}"#;

    #[tokio::test]
    async fn test_file_source_loads_and_rereads() {
        let path = std::env::temp_dir().join("auth_jwks_file_source.json");
        std::fs::write(&path, KEYS_A).unwrap();
        let source = JwksSource::File(path.to_str().unwrap().to_string());
        let cache = JwksCache::load(&source, None).await.unwrap();
        assert!(cache.get_key("a").is_some());
        assert!(cache.get_key("b").is_none());

        // The Secret is updated: the next refresh serves the new key, with no network.
        std::fs::write(&path, KEYS_A.replace(r#""kid":"a""#, r#""kid":"b""#)).unwrap();
        let metrics = Metrics::new().unwrap();
        cache.refresh_once(&source, &metrics).await;
        assert!(cache.get_key("b").is_some());
        assert!(cache.get_key("a").is_none());

        // A broken update keeps the last good set.
        std::fs::write(&path, b"not json").unwrap();
        cache.refresh_once(&source, &metrics).await;
        assert!(cache.get_key("b").is_some());
        assert_eq!(metrics.jwks_refresh.with_label_values(&["failure"]).get(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_missing_jwks_file_fails_fast() {
        let source = JwksSource::File("/nonexistent/jwks.json".to_string());
        let err = JwksCache::load(&source, None).await.unwrap_err();
        assert!(err.to_string().contains("jwks_file"), "error was: {err}");
    }

    #[test]
    fn test_garbage_ca_file_fails_closed() {
        let path = std::env::temp_dir().join("auth_jwks_ca_garbage.pem");
        std::fs::write(&path, b"this is not a certificate").unwrap();
        let err = build_client(Some(path.to_str().unwrap())).unwrap_err();
        assert!(err.to_string().contains("JWKS_CA_FILE"), "error was: {err}");
        let _ = std::fs::remove_file(&path);
    }
}
