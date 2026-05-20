//! Prometheus counters and histogram for the auth service.

use std::sync::Arc;

use prometheus::{Encoder, Histogram, HistogramOpts, IntCounterVec, Opts, Registry, TextEncoder};

use crate::error::AppError;

/// Bundle of Prometheus metrics used across the service.
#[derive(Debug)]
pub struct Metrics {
    /// Registry that owns all metric handles.
    pub registry: Registry,
    /// `auth_requests_total{result}` — `ok`, `denied`, or `error`.
    pub auth_requests: IntCounterVec,
    /// `jwks_refresh_total{result}` — `success` or `failure`.
    pub jwks_refresh: IntCounterVec,
    /// `jwt_validation_duration_seconds` — wall-clock per check.
    pub jwt_validation: Histogram,
}

impl Metrics {
    /// Build the metric set and register everything with a fresh Registry.
    pub fn new() -> Result<Arc<Self>, AppError> {
        let registry = Registry::new();

        let auth_requests = IntCounterVec::new(
            Opts::new("auth_requests_total", "ext_authz check outcomes"),
            &["result"],
        )?;
        let jwks_refresh = IntCounterVec::new(
            Opts::new("jwks_refresh_total", "JWKS refresh outcomes"),
            &["result"],
        )?;
        let jwt_validation = Histogram::with_opts(
            HistogramOpts::new(
                "jwt_validation_duration_seconds",
                "JWT validation latency",
            )
            .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05]),
        )?;

        registry.register(Box::new(auth_requests.clone()))?;
        registry.register(Box::new(jwks_refresh.clone()))?;
        registry.register(Box::new(jwt_validation.clone()))?;

        Ok(Arc::new(Self {
            registry,
            auth_requests,
            jwks_refresh,
            jwt_validation,
        }))
    }

    /// Encode the current state in Prometheus text exposition format.
    pub fn render(&self) -> Result<String, AppError> {
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf)?;
        // TextEncoder produces UTF-8 by contract; lossy conversion is safe.
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}
