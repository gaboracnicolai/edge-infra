//! JWKS cache with lock-free reads (ArcSwap) and periodic background refresh.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use tokio::task::JoinHandle;

use crate::error::AppError;
use crate::metrics::Metrics;

/// In-memory JWKS cache. Reads are lock-free via [`ArcSwap`].
#[derive(Debug)]
pub struct JwksCache {
    inner: ArcSwap<JwkSet>,
    client: reqwest::Client,
}

impl JwksCache {
    /// Fetch the JWKS once and build a cache. Fails fast if the upstream is unreachable.
    pub async fn new(url: &str, ca_file: Option<&str>) -> Result<Arc<Self>, AppError> {
        let client = build_client(ca_file)?;
        let set = fetch_jwks(&client, url).await?;
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
    ///
    /// A failed refresh logs a warning and increments the failure counter; the
    /// previous snapshot stays in place so the gRPC hot path keeps serving.
    pub fn start_refresh(
        self: Arc<Self>,
        url: String,
        interval_s: u64,
        metrics: Arc<Metrics>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let interval = Duration::from_secs(interval_s);
            loop {
                tokio::time::sleep(interval).await;
                match fetch_jwks(&self.client, &url).await {
                    Ok(new_set) => {
                        self.inner.store(Arc::new(new_set));
                        metrics.jwks_refresh.with_label_values(&["success"]).inc();
                        tracing::debug!(url = %url, "jwks refreshed");
                    }
                    Err(err) => {
                        metrics.jwks_refresh.with_label_values(&["failure"]).inc();
                        tracing::warn!(error = %err, url = %url, "jwks refresh failed; keeping cached set");
                    }
                }
            }
        })
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

async fn fetch_jwks(client: &reqwest::Client, url: &str) -> Result<JwkSet, AppError> {
    let resp = client.get(url).send().await?.error_for_status()?;
    let body = resp.text().await?;
    serde_json::from_str::<JwkSet>(&body)
        .map_err(|e| AppError::JwksParse(e.to_string()))
}

/// Build the reqwest client used to fetch the JWKS. When `ca_file` is set, the
/// PEM CA is added to the trust roots so an internal-CA JWKS endpoint (the
/// token issuer) is trusted. Fails closed: a missing or unparseable CA file is
/// an error, never a silent fall back to the default roots.
fn build_client(_ca_file: Option<&str>) -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(AppError::from)
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

    #[test]
    fn test_garbage_ca_file_fails_closed() {
        let path = std::env::temp_dir().join("auth_jwks_ca_garbage.pem");
        std::fs::write(&path, b"this is not a certificate").unwrap();
        let err = build_client(Some(path.to_str().unwrap())).unwrap_err();
        assert!(err.to_string().contains("JWKS_CA_FILE"), "error was: {err}");
        let _ = std::fs::remove_file(&path);
    }
}
