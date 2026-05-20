//! Implementation of Envoy's ext_authz Authorization service.

use std::sync::Arc;

use envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, CheckResponse, HeaderAppendAction, HttpStatusCode,
};
use envoy_types::ext_authz::v3::{
    CheckRequestExt, CheckResponseExt, DeniedHttpResponseBuilder, OkHttpResponseBuilder,
};
use jsonwebtoken::{Validation, decode, decode_header};
use serde::Deserialize;
use tonic::{Request, Response, Status};

use crate::jwks::JwksCache;
use crate::metrics::Metrics;

/// JWT claims the service inspects. `aud` is validated by jsonwebtoken.
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    /// Subject identifier (typically the user ID).
    pub sub: String,
    /// Expiration time (seconds since epoch).
    pub exp: usize,
    /// Issued-at time (seconds since epoch).
    pub iat: usize,
    /// Intended audience(s); validated against the configured audience.
    pub aud: Vec<String>,
    /// Issuer; validated against the configured issuer.
    pub iss: String,
    /// Optional team membership; forwarded as `x-user-teams`.
    pub teams: Option<Vec<String>>,
}

/// gRPC ext_authz service: validates a Bearer JWT and forwards identity headers.
#[derive(Debug)]
pub struct AuthService {
    /// JWKS used to resolve signing keys by `kid`.
    pub jwks: Arc<JwksCache>,
    /// Pre-built validation config (algorithm, audience, issuer).
    pub validation: Validation,
    /// Metrics handle shared with the metrics HTTP server.
    pub metrics: Arc<Metrics>,
}

#[tonic::async_trait]
impl Authorization for AuthService {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let req = request.into_inner();

        let headers = match req.get_client_headers() {
            Some(h) => h,
            None => return Ok(Response::new(self.denied("client headers missing"))),
        };

        let auth_header = match headers.get("authorization").or_else(|| headers.get("Authorization")) {
            Some(v) => v,
            None => return Ok(Response::new(self.denied("missing authorization header"))),
        };

        let token = match auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
        {
            Some(t) => t,
            None => return Ok(Response::new(self.denied("Bearer scheme required"))),
        };

        let timer = self.metrics.jwt_validation.start_timer();

        let kid = match decode_header(token) {
            Ok(h) => match h.kid {
                Some(k) => k,
                None => {
                    drop(timer);
                    return Ok(Response::new(self.denied("JWT missing kid")));
                }
            },
            Err(_) => {
                drop(timer);
                return Ok(Response::new(self.denied("malformed JWT")));
            }
        };

        let key = match self.jwks.get_key(&kid) {
            Some(k) => k,
            None => {
                drop(timer);
                return Ok(Response::new(self.denied("unknown kid")));
            }
        };

        let claims = match decode::<Claims>(token, &key, &self.validation) {
            Ok(data) => data.claims,
            Err(err) => {
                drop(timer);
                return Ok(Response::new(
                    self.denied(&format!("invalid JWT: {err}")),
                ));
            }
        };

        timer.observe_duration();

        let teams = claims.teams.clone().unwrap_or_default().join(",");

        let mut builder = OkHttpResponseBuilder::new();
        builder
            // OverwriteIfExistsOrAdd ensures a malicious client can't smuggle
            // these identity headers in alongside their own value.
            .add_header(
                "x-user-id",
                claims.sub.clone(),
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                false,
            )
            .add_header(
                "x-user-teams",
                teams,
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                true,
            )
            .add_header(
                "x-auth-iss",
                claims.iss.clone(),
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                false,
            );

        let mut response = CheckResponse::with_status(Status::ok("ok"));
        response.set_http_response(builder);

        self.metrics.auth_requests.with_label_values(&["ok"]).inc();
        Ok(Response::new(response))
    }
}

impl AuthService {
    /// Build a 401-with-body deny response and bump the denied counter.
    fn denied(&self, msg: &str) -> CheckResponse {
        self.metrics
            .auth_requests
            .with_label_values(&["denied"])
            .inc();

        let mut builder = DeniedHttpResponseBuilder::new();
        builder
            .set_http_status(HttpStatusCode::Unauthorized)
            .set_body(msg.to_string());

        let mut response = CheckResponse::with_status(Status::unauthenticated(msg));
        response.set_http_response(builder);
        response
    }
}
