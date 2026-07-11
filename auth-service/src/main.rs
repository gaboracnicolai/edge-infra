//! Process entry point: wires config, JWKS, metrics, and the gRPC + axum servers.

use std::net::SocketAddr;
use std::sync::Arc;

use auth_service::auth::AuthService;
use auth_service::config::Config;
use auth_service::error::AppError;
use auth_service::jwks::JwksCache;
use auth_service::metrics::Metrics;

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use envoy_types::ext_authz::v3::pb::AuthorizationServer;
use jsonwebtoken::{Algorithm, Validation};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    init_tracing();

    // Install the rustls crypto provider before any TLS config is built. With both
    // aws-lc-rs (reqwest) and ring (tonic) linked, rustls 0.23 otherwise panics at
    // serve time. See auth_service::install_default_crypto_provider.
    auth_service::install_default_crypto_provider();

    let cfg = Config::from_env()?;
    info!(
        grpc_addr = %cfg.grpc_addr,
        metrics_addr = %cfg.metrics_addr,
        jwks_url = %cfg.jwks_url,
        tls = cfg.tls_cert_file.is_some(),
        mtls = cfg.tls_ca_file.is_some(),
        "auth-service starting"
    );

    let metrics = Metrics::new()?;
    let jwks = JwksCache::new(&cfg.jwks_url, cfg.jwks_ca_file.as_deref()).await?;
    let _refresh = Arc::clone(&jwks).start_refresh(
        cfg.jwks_url.clone(),
        cfg.jwks_refresh_s,
        Arc::clone(&metrics),
    );

    spawn_metrics_server(&cfg.metrics_addr, Arc::clone(&metrics)).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(std::slice::from_ref(&cfg.jwt_audience));
    validation.set_issuer(std::slice::from_ref(&cfg.jwt_issuer));

    let auth_service = AuthService {
        jwks: Arc::clone(&jwks),
        validation,
        metrics: Arc::clone(&metrics),
        gateway_secret: cfg.gateway_auth_secret.clone(),
    };

    let tls_cfg = build_tls_config(&cfg)?;
    if tls_cfg.is_none() {
        warn!("auth-service gRPC running WITHOUT TLS — set AUTH_TLS_CERT/AUTH_TLS_KEY to enable");
    }

    let grpc_addr: SocketAddr = cfg.grpc_addr.parse()?;
    info!(addr = %grpc_addr, tls = tls_cfg.is_some(), "grpc server listening");

    let mut builder = Server::builder();
    if let Some(tls) = tls_cfg {
        builder = builder.tls_config(tls)?;
    }
    builder
        .add_service(AuthorizationServer::new(auth_service))
        .serve_with_shutdown(grpc_addr, shutdown_signal())
        .await?;

    info!("auth-service shut down cleanly");
    Ok(())
}

/// Load TLS credentials from the paths in `cfg`.
/// Returns `None` when `AUTH_TLS_CERT` is unset (plaintext mode).
/// Returns `Some(ServerTlsConfig)` for TLS, with client CA verification
/// added when `AUTH_TLS_CA` is also set (mTLS).
fn build_tls_config(cfg: &Config) -> Result<Option<ServerTlsConfig>, AppError> {
    let cert_path = match &cfg.tls_cert_file {
        Some(p) => p,
        None => return Ok(None),
    };
    // tls_key_file presence already validated in Config::from_env
    let key_path = cfg.tls_key_file.as_ref().unwrap();

    let cert = std::fs::read(cert_path)
        .map_err(|e| AppError::Tls(format!("read cert {cert_path}: {e}")))?;
    let key = std::fs::read(key_path)
        .map_err(|e| AppError::Tls(format!("read key {key_path}: {e}")))?;

    let identity = Identity::from_pem(cert, key);
    let mut tls = ServerTlsConfig::new().identity(identity);

    if let Some(ca_path) = &cfg.tls_ca_file {
        let ca = std::fs::read(ca_path)
            .map_err(|e| AppError::Tls(format!("read CA {ca_path}: {e}")))?;
        tls = tls.client_ca_root(Certificate::from_pem(ca));
        info!(ca = %ca_path, "mTLS client verification enabled");
    }

    Ok(Some(tls))
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::from("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
}

async fn spawn_metrics_server(addr: &str, metrics: Arc<Metrics>) -> Result<(), AppError> {
    let socket_addr: SocketAddr = addr.parse()?;
    let listener = tokio::net::TcpListener::bind(socket_addr).await?;
    let router = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(healthz_handler))
        .with_state(metrics);
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router).await {
            error!(error = %err, "metrics server exited with error");
        }
    });
    info!(addr = %socket_addr, "metrics server listening");
    Ok(())
}

async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> Response {
    match metrics.render() {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            body,
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "metrics encode failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "metrics encoding failed").into_response()
        }
    }
}

async fn healthz_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => info!("received SIGINT"),
            Err(err) => error!(error = %err, "failed to listen for SIGINT"),
        }
    };

    let term = async {
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
                info!("received SIGTERM");
            }
            Err(err) => error!(error = %err, "failed to install SIGTERM handler"),
        }
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
