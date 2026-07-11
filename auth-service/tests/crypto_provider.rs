//! Regression test for the rustls dual-provider startup panic.
//!
//! auth-service links TWO rustls crypto providers — `aws-lc-rs` (via reqwest's
//! `rustls-tls`) and `ring` (via `tonic`/`tokio-rustls`). With more than one
//! linked, rustls 0.23 will NOT auto-select a process default, and building any
//! TLS config panics ("Could not automatically determine the process-level
//! CryptoProvider") — which crash-loops the gRPC server at serve time.
//! `install_default_crypto_provider()` is the fix.
//!
//! One test only: the crypto provider default is process-global, so proving the
//! before/after transition must happen in a single test in a single test binary
//! (each integration file is its own process, starting with clean global state).

#[test]
fn install_default_crypto_provider_prevents_the_no_default_panic() {
    // Precondition (the latent bug): two providers linked ⇒ no process default is
    // auto-installed.
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "expected NO process-default provider with two providers linked",
    );

    // RED — without a default, building a rustls server config PANICS. Catch it so
    // the test can assert the panic occurs (silence the hook: the panic is expected).
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let panicked_without_fix = std::panic::catch_unwind(|| {
        let _ = rustls::ServerConfig::builder();
    })
    .is_err();
    std::panic::set_hook(prev_hook);
    assert!(
        panicked_without_fix,
        "expected rustls to panic on config build BEFORE installing a default provider",
    );

    // Apply the production fix (the exact call main() makes).
    auth_service::install_default_crypto_provider();

    // GREEN — a default is now installed and building a TLS config no longer panics.
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "install_default_crypto_provider must install a process default",
    );
    let built_after_fix = std::panic::catch_unwind(|| {
        let _ = rustls::ServerConfig::builder();
    })
    .is_ok();
    assert!(
        built_after_fix,
        "rustls config must build without panicking AFTER the fix",
    );

    // Idempotent: a second call is a safe no-op (guards against double-invocation).
    auth_service::install_default_crypto_provider();
    assert!(rustls::crypto::CryptoProvider::get_default().is_some());
}
