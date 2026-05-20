//! Env-driven configuration.

use crate::error::AppError;

/// Runtime configuration sourced from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// `host:port` the gRPC ext_authz server binds to.
    pub grpc_addr: String,
    /// `host:port` the axum metrics+health server binds to.
    pub metrics_addr: String,
    /// URL to fetch the JWKS document from.
    pub jwks_url: String,
    /// Background JWKS refresh interval in seconds.
    pub jwks_refresh_s: u64,
    /// Expected JWT audience.
    pub jwt_audience: String,
    /// Expected JWT issuer.
    pub jwt_issuer: String,
    /// `RUST_LOG`-style log level.
    pub log_level: String,
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

        let jwks_refresh_s = optional("JWKS_REFRESH_S", "300")
            .parse::<u64>()
            .map_err(|e| AppError::Config(format!("JWKS_REFRESH_S parse: {e}")))?;

        Ok(Self {
            grpc_addr: optional("GRPC_ADDR", "0.0.0.0:50051"),
            metrics_addr: optional("METRICS_ADDR", "0.0.0.0:9090"),
            jwks_url: required("JWKS_URL")?,
            jwks_refresh_s,
            jwt_audience: required("JWT_AUDIENCE")?,
            jwt_issuer: required("JWT_ISSUER")?,
            log_level: optional("LOG_LEVEL", "info"),
        })
    }
}
