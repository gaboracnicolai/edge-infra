//! Env-driven configuration.

use crate::error::AppError;

/// Runtime configuration sourced from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// `host:port` the gRPC ext_authz server binds to.
    pub grpc_addr: String,
    /// `host:port` the axum metrics+health server binds to.
    pub metrics_addr: String,
    /// URL to fetch the JWKS document from. Must use https://.
    pub jwks_url: String,
    /// Background JWKS refresh interval in seconds.
    pub jwks_refresh_s: u64,
    /// Optional PEM CA file (JWKS_CA_FILE) the HTTPS JWKS fetch trusts in
    /// addition to the system roots. Needed when the JWKS endpoint (the token
    /// issuer) serves an internal-CA certificate that the default webpki root
    /// set does not trust.
    pub jwks_ca_file: Option<String>,
    /// Expected JWT audience.
    pub jwt_audience: String,
    /// Expected JWT issuer.
    pub jwt_issuer: String,
    /// Shared secret injected as the `x-gateway-auth` header on every
    /// authenticated request, proving the request transited this gateway.
    /// Backends reject any request that lacks the matching value.
    pub gateway_auth_secret: String,
    /// `RUST_LOG`-style log level.
    pub log_level: String,
    /// Path to the PEM-encoded server TLS certificate (AUTH_TLS_CERT).
    pub tls_cert_file: Option<String>,
    /// Path to the PEM-encoded server TLS private key (AUTH_TLS_KEY).
    pub tls_key_file: Option<String>,
    /// Path to the PEM-encoded CA certificate for mTLS client verification (AUTH_TLS_CA).
    pub tls_ca_file: Option<String>,
}

impl Config {
    /// Load and validate configuration from the process environment.
    pub fn from_env() -> Result<Self, AppError> {
        let required = |k: &str| {
            std::env::var(k).map_err(|_| AppError::Config(format!("missing env var {k}")))
        };
        let optional = |k: &str, default: &str| {
            std::env::var(k).unwrap_or_else(|_| default.to_string())
        };
        let optional_some = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());

        let jwks_refresh_s = optional("JWKS_REFRESH_S", "300")
            .parse::<u64>()
            .map_err(|e| AppError::Config(format!("JWKS_REFRESH_S parse: {e}")))?;

        let jwks_url = required("JWKS_URL")?;
        if !jwks_url.starts_with("https://") {
            return Err(AppError::Config(format!(
                "JWKS_URL must use https://, got: {jwks_url}"
            )));
        }

        // Transit-proof shared secret. Fail closed: refuse to start without a
        // sufficiently long secret rather than silently injecting a weak or
        // empty value that a caller could guess and forge.
        let gateway_auth_secret = required("GATEWAY_AUTH_SECRET")?;
        if gateway_auth_secret.len() < 16 {
            return Err(AppError::Config(format!(
                "GATEWAY_AUTH_SECRET must be at least 16 characters (got {})",
                gateway_auth_secret.len()
            )));
        }

        let tls_cert_file = optional_some("AUTH_TLS_CERT");
        let tls_key_file = optional_some("AUTH_TLS_KEY");
        let tls_ca_file = optional_some("AUTH_TLS_CA");

        if tls_cert_file.is_some() && tls_key_file.is_none() {
            return Err(AppError::Config(
                "AUTH_TLS_KEY must be set when AUTH_TLS_CERT is set".to_string(),
            ));
        }

        Ok(Self {
            grpc_addr: optional("GRPC_ADDR", "0.0.0.0:50051"),
            metrics_addr: optional("METRICS_ADDR", "0.0.0.0:9090"),
            jwks_url,
            jwks_refresh_s,
            jwks_ca_file: optional_some("JWKS_CA_FILE"),
            jwt_audience: required("JWT_AUDIENCE")?,
            jwt_issuer: required("JWT_ISSUER")?,
            gateway_auth_secret,
            log_level: optional("LOG_LEVEL", "info"),
            tls_cert_file,
            tls_key_file,
            tls_ca_file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env vars are global process state. Serialize all config tests to prevent
    // race conditions when tests run on parallel threads.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn base_env() {
        std::env::set_var("JWKS_URL", "https://auth.example.com/.well-known/jwks.json");
        std::env::set_var("JWT_AUDIENCE", "test-audience");
        std::env::set_var("JWT_ISSUER", "https://auth.example.com/");
        std::env::set_var("GATEWAY_AUTH_SECRET", "test-gateway-shared-secret");
        std::env::remove_var("AUTH_TLS_CERT");
        std::env::remove_var("AUTH_TLS_KEY");
        std::env::remove_var("AUTH_TLS_CA");
        std::env::remove_var("JWKS_CA_FILE");
    }

    #[test]
    fn test_jwks_ca_file_optional() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        assert!(Config::from_env().unwrap().jwks_ca_file.is_none());
        std::env::set_var("JWKS_CA_FILE", "/etc/auth-tls/ca.crt");
        assert_eq!(
            Config::from_env().unwrap().jwks_ca_file.as_deref(),
            Some("/etc/auth-tls/ca.crt")
        );
        std::env::remove_var("JWKS_CA_FILE");
    }

    #[test]
    fn test_jwks_url_must_be_https() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        std::env::set_var("JWKS_URL", "http://auth.example.com/.well-known/jwks.json");
        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("https://"), "error was: {err}");
    }

    #[test]
    fn test_jwks_url_https_accepted() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        assert!(Config::from_env().is_ok());
    }

    #[test]
    fn test_gateway_auth_secret_required() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        std::env::remove_var("GATEWAY_AUTH_SECRET");
        let err = Config::from_env().unwrap_err();
        assert!(
            err.to_string().contains("GATEWAY_AUTH_SECRET"),
            "error was: {err}"
        );
    }

    #[test]
    fn test_gateway_auth_secret_too_short_rejected() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        std::env::set_var("GATEWAY_AUTH_SECRET", "short");
        let err = Config::from_env().unwrap_err();
        assert!(
            err.to_string().contains("GATEWAY_AUTH_SECRET"),
            "error was: {err}"
        );
    }

    #[test]
    fn test_tls_cert_without_key_errors() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        std::env::set_var("AUTH_TLS_CERT", "/some/tls.crt");
        std::env::remove_var("AUTH_TLS_KEY");
        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("AUTH_TLS_KEY"), "error was: {err}");
    }

    #[test]
    fn test_tls_all_fields_accepted() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        std::env::set_var("AUTH_TLS_CERT", "/etc/tls/tls.crt");
        std::env::set_var("AUTH_TLS_KEY", "/etc/tls/tls.key");
        std::env::set_var("AUTH_TLS_CA", "/etc/tls/ca.crt");
        let cfg = Config::from_env().unwrap();
        assert_eq!(cfg.tls_cert_file.as_deref(), Some("/etc/tls/tls.crt"));
        assert_eq!(cfg.tls_ca_file.as_deref(), Some("/etc/tls/ca.crt"));
    }

    #[test]
    fn test_tls_none_when_unset() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        let cfg = Config::from_env().unwrap();
        assert!(cfg.tls_cert_file.is_none());
        assert!(cfg.tls_key_file.is_none());
        assert!(cfg.tls_ca_file.is_none());
    }
}
