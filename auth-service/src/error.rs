//! Top-level error type. Every fallible production path returns `AppError`.

use thiserror::Error;

/// Errors that can surface from anywhere in the service.
#[derive(Debug, Error)]
pub enum AppError {
    /// Missing or malformed configuration in the environment.
    #[error("config: {0}")]
    Config(String),

    /// JWKS HTTP fetch failed.
    #[error("jwks fetch: {0}")]
    JwksFetch(#[from] reqwest::Error),

    /// JWKS body could not be parsed.
    #[error("jwks parse: {0}")]
    JwksParse(String),

    /// I/O failure (listener bind, signal handler install).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Address could not be parsed.
    #[error("addr parse: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    /// Underlying tonic transport failure.
    #[error("grpc transport: {0}")]
    Grpc(#[from] tonic::transport::Error),

    /// Prometheus registration or encoding failure.
    #[error("metrics: {0}")]
    Metrics(#[from] prometheus::Error),
}
