//! Env-driven configuration.

use serde::Deserialize;

use crate::error::AppError;
use crate::jwks::JwksSource;

/// One more identity provider this gateway trusts (an entry of JWT_ISSUERS):
/// tokens naming `issuer` must be signed by a key from `jwks_url`, or from
/// `jwks_file` when the provider's keys are held in the cluster instead.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    /// The `iss` claim this provider's tokens carry.
    pub issuer: String,
    /// HTTPS endpoint serving this provider's signing keys.
    #[serde(default)]
    pub jwks_url: String,
    /// A JWKS document in the pod (the chart mounts `jwksFiles.existingSecret`
    /// at /etc/auth-service/jwks), used instead of `jwks_url` so an identity
    /// provider outside an air-gapped cluster is trusted with no network call.
    /// Re-read every JWKS_REFRESH_S, so updating the Secret rotates the keys.
    #[serde(default)]
    pub jwks_file: Option<String>,
    /// Expected `aud` for this provider's tokens; JWT_AUDIENCE when absent.
    #[serde(default)]
    pub audience: Option<String>,
    /// PEM CA the JWKS fetch trusts besides the system roots; JWKS_CA_FILE
    /// when absent. The cluster's own ServiceAccount issuer needs the API
    /// server's CA (/var/run/secrets/kubernetes.io/serviceaccount/ca.crt).
    #[serde(default)]
    pub ca_file: Option<String>,
    /// A bearer token file sent with every `jwks_url` fetch, re-read each time
    /// so a rotated token is picked up. The in-cluster API server serves its
    /// JWKS only to an authenticated caller unless RBAC opens it to everyone:
    /// name the pod's own token,
    /// /var/run/secrets/kubernetes.io/serviceaccount/token.
    #[serde(default)]
    pub token_file: Option<String>,
}

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
    /// More trusted issuers (JWT_ISSUERS, a JSON array of IssuerConfig), e.g.
    /// a customer's Okta beside the cluster's ServiceAccount issuer.
    pub extra_issuers: Vec<IssuerConfig>,
    /// PEM Ed25519 private key (TRANSIT_SIGNING_KEY) that signs the transit
    /// assertion injected as `x-gateway-auth` on every authorized request.
    /// Backends verify it against the public JWKS this service publishes.
    pub transit_signing_key: String,
    /// `iss` of every transit assertion (TRANSIT_ISSUER).
    pub transit_issuer: String,
    /// Lifetime of a transit assertion in seconds (TRANSIT_TTL_S).
    pub transit_ttl_s: u64,
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

        let extra_issuers = match optional_some("JWT_ISSUERS") {
            Some(raw) => serde_json::from_str::<Vec<IssuerConfig>>(&raw)
                .map_err(|e| AppError::Config(format!("JWT_ISSUERS parse: {e}")))?,
            None => Vec::new(),
        };

        // Transit-assertion signing key. Fail closed: refuse to start without
        // one rather than forward requests a backend cannot verify.
        let transit_signing_key = required("TRANSIT_SIGNING_KEY")?;
        let transit_ttl_s = optional("TRANSIT_TTL_S", "30")
            .parse::<u64>()
            .map_err(|e| AppError::Config(format!("TRANSIT_TTL_S parse: {e}")))?;

        let tls_cert_file = optional_some("AUTH_TLS_CERT");
        let tls_key_file = optional_some("AUTH_TLS_KEY");
        let tls_ca_file = optional_some("AUTH_TLS_CA");

        if tls_cert_file.is_some() && tls_key_file.is_none() {
            return Err(AppError::Config(
                "AUTH_TLS_KEY must be set when AUTH_TLS_CERT is set".to_string(),
            ));
        }

        let cfg = Self {
            grpc_addr: optional("GRPC_ADDR", "0.0.0.0:50051"),
            metrics_addr: optional("METRICS_ADDR", "0.0.0.0:9090"),
            jwks_url,
            jwks_refresh_s,
            jwks_ca_file: optional_some("JWKS_CA_FILE"),
            jwt_audience: required("JWT_AUDIENCE")?,
            jwt_issuer: required("JWT_ISSUER")?,
            extra_issuers,
            transit_signing_key,
            transit_issuer: optional("TRANSIT_ISSUER", "edge-gateway"),
            transit_ttl_s,
            log_level: optional("LOG_LEVEL", "info"),
            tls_cert_file,
            tls_key_file,
            tls_ca_file,
        };

        let mut seen = std::collections::HashSet::new();
        for idp in cfg.issuers() {
            if idp.issuer.is_empty() {
                return Err(AppError::Config("JWT_ISSUERS: an issuer is empty".to_string()));
            }
            match &idp.jwks_file {
                Some(_) if !idp.jwks_url.is_empty() => {
                    return Err(AppError::Config(format!(
                        "issuer {} sets both jwks_url and jwks_file — keep one",
                        idp.issuer
                    )));
                }
                Some(path) if !path.starts_with('/') => {
                    return Err(AppError::Config(format!(
                        "jwks_file for {} must be an absolute path, got: {path:?}",
                        idp.issuer
                    )));
                }
                Some(_) if idp.token_file.is_some() => {
                    return Err(AppError::Config(format!(
                        "token_file for {} is sent with a jwks_url fetch; a jwks_file needs none",
                        idp.issuer
                    )));
                }
                Some(_) => {}
                None if !idp.jwks_url.starts_with("https://") => {
                    return Err(AppError::Config(format!(
                        "jwks_url for {} must use https://, got: {}",
                        idp.issuer, idp.jwks_url
                    )));
                }
                None => {}
            }
            if let Some(path) = idp.token_file.as_deref().filter(|p| !p.starts_with('/')) {
                return Err(AppError::Config(format!(
                    "token_file for {} must be an absolute path, got: {path:?}",
                    idp.issuer
                )));
            }
            if !seen.insert(idp.issuer.clone()) {
                return Err(AppError::Config(format!(
                    "issuer {} is listed twice",
                    idp.issuer
                )));
            }
        }
        Ok(cfg)
    }

    /// Every trusted issuer, JWT_ISSUER first, each with its audience and CA
    /// resolved.
    pub fn issuers(&self) -> Vec<IssuerConfig> {
        let primary = IssuerConfig {
            issuer: self.jwt_issuer.clone(),
            jwks_url: self.jwks_url.clone(),
            jwks_file: None,
            audience: None,
            ca_file: None,
            token_file: None,
        };
        std::iter::once(primary)
            .chain(self.extra_issuers.iter().cloned())
            .map(|mut idp| {
                idp.audience.get_or_insert_with(|| self.jwt_audience.clone());
                if idp.ca_file.is_none() {
                    idp.ca_file = self.jwks_ca_file.clone();
                }
                idp
            })
            .collect()
    }
}

impl IssuerConfig {
    /// Where this issuer's keys are read from.
    pub fn jwks_source(&self) -> JwksSource {
        match &self.jwks_file {
            Some(path) => JwksSource::File(path.clone()),
            None => JwksSource::Url(self.jwks_url.clone()),
        }
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
        std::env::set_var("TRANSIT_SIGNING_KEY", "-----BEGIN PRIVATE KEY-----");
        std::env::remove_var("AUTH_TLS_CERT");
        std::env::remove_var("AUTH_TLS_KEY");
        std::env::remove_var("AUTH_TLS_CA");
        std::env::remove_var("JWKS_CA_FILE");
        std::env::remove_var("JWT_ISSUERS");
    }

    #[test]
    fn test_jwt_issuers_adds_providers() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        std::env::set_var(
            "JWT_ISSUERS",
            r#"[{"issuer":"https://dev-1.okta.com/oauth2/default","jwks_url":"https://dev-1.okta.com/oauth2/default/v1/keys","audience":"api://default"},
                {"issuer":"https://kubernetes.default.svc.cluster.local","jwks_url":"https://kubernetes.default.svc/openid/v1/jwks"}]"#,
        );
        let issuers = Config::from_env().unwrap().issuers();
        std::env::remove_var("JWT_ISSUERS");
        let got: Vec<(&str, &str)> = issuers
            .iter()
            .map(|i| (i.issuer.as_str(), i.audience.as_deref().unwrap()))
            .collect();
        assert_eq!(
            got,
            [
                ("https://auth.example.com/", "test-audience"),
                ("https://dev-1.okta.com/oauth2/default", "api://default"),
                ("https://kubernetes.default.svc.cluster.local", "test-audience"),
            ]
        );
    }

    #[test]
    fn test_jwt_issuers_ca_file_defaults_to_jwks_ca_file() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        std::env::set_var("JWKS_CA_FILE", "/etc/auth-tls/ca.crt");
        std::env::set_var(
            "JWT_ISSUERS",
            r#"[{"issuer":"https://kubernetes.default.svc.cluster.local","jwks_url":"https://kubernetes.default.svc.cluster.local/openid/v1/jwks","ca_file":"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"},
                {"issuer":"https://dev-1.okta.com/oauth2/default","jwks_url":"https://dev-1.okta.com/oauth2/default/v1/keys"}]"#,
        );
        let issuers = Config::from_env().unwrap().issuers();
        std::env::remove_var("JWT_ISSUERS");
        std::env::remove_var("JWKS_CA_FILE");
        let got: Vec<&str> = issuers.iter().map(|i| i.ca_file.as_deref().unwrap()).collect();
        assert_eq!(
            got,
            [
                "/etc/auth-tls/ca.crt",
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
                "/etc/auth-tls/ca.crt",
            ]
        );
    }

    #[test]
    fn test_jwt_issuers_jwks_url_must_be_https() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        std::env::set_var(
            "JWT_ISSUERS",
            r#"[{"issuer":"https://idp.example.com","jwks_url":"http://idp.example.com/keys"}]"#,
        );
        let err = Config::from_env().unwrap_err();
        std::env::remove_var("JWT_ISSUERS");
        assert!(err.to_string().contains("https://"), "error was: {err}");
    }

    #[test]
    fn test_jwt_issuers_jwks_file_reads_keys_from_the_cluster() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        std::env::set_var(
            "JWT_ISSUERS",
            r#"[{"issuer":"https://idp.corp.example","jwks_file":"/etc/auth-service/jwks/corp.json"}]"#,
        );
        let issuers = Config::from_env().unwrap().issuers();
        std::env::remove_var("JWT_ISSUERS");
        assert_eq!(
            issuers[1].jwks_source(),
            JwksSource::File("/etc/auth-service/jwks/corp.json".to_string())
        );
        assert_eq!(
            issuers[0].jwks_source(),
            JwksSource::Url("https://auth.example.com/.well-known/jwks.json".to_string())
        );

        for (raw, want) in [
            (
                r#"[{"issuer":"https://idp.corp.example","jwks_url":"https://idp.corp.example/keys","jwks_file":"/etc/auth-service/jwks/corp.json"}]"#,
                "keep one",
            ),
            (
                r#"[{"issuer":"https://idp.corp.example","jwks_file":"corp.json"}]"#,
                "absolute path",
            ),
            (r#"[{"issuer":"https://idp.corp.example"}]"#, "https://"),
        ] {
            std::env::set_var("JWT_ISSUERS", raw);
            let err = Config::from_env().unwrap_err();
            std::env::remove_var("JWT_ISSUERS");
            assert!(err.to_string().contains(want), "{raw}: error was: {err}");
        }
    }

    #[test]
    fn test_jwt_issuers_token_file_only_with_a_jwks_url() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        let sa = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        std::env::set_var(
            "JWT_ISSUERS",
            format!(r#"[{{"issuer":"https://kubernetes.default.svc.cluster.local","jwks_url":"https://kubernetes.default.svc.cluster.local/openid/v1/jwks","token_file":"{sa}"}}]"#),
        );
        let issuers = Config::from_env().unwrap().issuers();
        std::env::remove_var("JWT_ISSUERS");
        assert_eq!(issuers[0].token_file, None);
        assert_eq!(issuers[1].token_file.as_deref(), Some(sa));

        for (raw, want) in [
            (
                r#"[{"issuer":"https://idp.corp.example","jwks_file":"/etc/auth-service/jwks/corp.json","token_file":"/var/run/secrets/kubernetes.io/serviceaccount/token"}]"#,
                "needs none",
            ),
            (
                r#"[{"issuer":"https://idp.corp.example","jwks_url":"https://idp.corp.example/keys","token_file":"token"}]"#,
                "absolute path",
            ),
        ] {
            std::env::set_var("JWT_ISSUERS", raw);
            let err = Config::from_env().unwrap_err();
            std::env::remove_var("JWT_ISSUERS");
            assert!(err.to_string().contains(want), "{raw}: error was: {err}");
        }
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
    fn test_transit_signing_key_required() {
        let _lock = ENV_LOCK.lock().unwrap();
        base_env();
        std::env::remove_var("TRANSIT_SIGNING_KEY");
        let err = Config::from_env().unwrap_err();
        assert!(
            err.to_string().contains("TRANSIT_SIGNING_KEY"),
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
