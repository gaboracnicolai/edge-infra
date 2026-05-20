//! `auth-service` — Envoy ext_authz gRPC server with JWT/JWKS verification.
//!
//! Exposed as a library so integration tests can drive the modules directly.

pub mod auth;
pub mod config;
pub mod error;
pub mod jwks;
pub mod metrics;
