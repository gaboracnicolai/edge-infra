//! `auth-service` — Envoy ext_authz gRPC server with JWT/JWKS verification.
//!
//! Exposed as a library so integration tests can drive the modules directly.

pub mod auth;
pub mod config;
pub mod error;
pub mod jwks;
pub mod metrics;

/// Install a process-wide rustls `CryptoProvider` so TLS configs can be built.
///
/// This binary links **two** rustls crypto providers — `aws-lc-rs` (via reqwest's
/// `rustls-tls`) and `ring` (via `tonic`/`tokio-rustls`). With more than one
/// provider linked, rustls 0.23 refuses to auto-select a process default and
/// PANICS — "Could not automatically determine the process-level CryptoProvider" —
/// the moment a TLS config is built (e.g. when tonic constructs the gRPC server
/// TLS at serve time). Installing an explicit default up front, before any TLS is
/// built, fixes it. Idempotent: a no-op if a default is already installed.
pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
