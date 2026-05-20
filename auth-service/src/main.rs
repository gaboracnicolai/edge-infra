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
use tonic::transport::Server;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    init_tracing();

    let cfg = Config::from_env()?;
    info!(
        grpc_addr = %cfg.grpc_addr,
        metrics_addr = %cfg.metrics_addr,
        jwks_url = %cfg.jwks_url,
        "auth-service starting"
    );

    let metrics = Metrics::new()?;
    let jwks = JwksCache::new(&cfg.jwks_url).await?;
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
    };

    let grpc_addr: SocketAddr = cfg.grpc_addr.parse()?;
    info!(addr = %grpc_addr, "grpc server listening");

    Server::builder()
        .add_service(AuthorizationServer::new(auth_service))
        .serve_with_shutdown(grpc_addr, shutdown_signal())
        .await?;

    info!("auth-service shut down cleanly");
    Ok(())
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
