"""TLS context builders for the OSB's outbound connections (ISO 27001 A.13).

Both Postgres and NATS connections are encrypted in production. The builders
here translate the env-driven settings into ``ssl.SSLContext`` objects:

* :func:`build_pg_ssl` maps ``db_ssl_mode`` onto an asyncpg-compatible value,
  enforcing certificate + hostname verification for ``verify-full``.
* :func:`build_nats_tls` builds a verifying context for the nats-py client,
  optionally loading a client cert for mutual TLS.

A misconfiguration (verify mode without a CA, unreadable cert files) raises at
startup rather than silently downgrading to plaintext.
"""

from __future__ import annotations

import ssl

import structlog

log = structlog.get_logger(__name__)

# libpq-style sslmode values, in ascending strictness.
_PG_SSL_MODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")
_PG_VERIFY_MODES = ("verify-ca", "verify-full")


def build_pg_ssl(ssl_mode: str, ca_path: str | None) -> ssl.SSLContext | bool | None:
    """Return an SSL argument for ``asyncpg.create_pool(ssl=...)``.

    * ``disable`` -> ``False`` (plaintext; only for local dev — logs a warning).
    * ``allow`` / ``prefer`` / ``require`` -> encrypted context that does **not**
      verify the server certificate (matches libpq semantics).
    * ``verify-ca`` / ``verify-full`` -> context that verifies the server cert
      against ``ca_path``; ``verify-full`` additionally checks the hostname.

    Raises ``ValueError`` for an unknown mode, or a verify mode without a CA.
    """
    mode = ssl_mode.strip().lower()
    if mode not in _PG_SSL_MODES:
        raise ValueError(
            f"invalid db_ssl_mode {ssl_mode!r}; expected one of {', '.join(_PG_SSL_MODES)}"
        )

    if mode == "disable":
        log.warning("postgres TLS disabled — set DB_SSL_MODE=verify-full for production")
        return False

    if mode in _PG_VERIFY_MODES:
        if not ca_path:
            raise ValueError(f"db_ssl_mode={mode} requires DB_TLS_CA to be set")
        ctx = ssl.create_default_context(cafile=ca_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = mode == "verify-full"
        return ctx

    # require / prefer / allow: encrypt but do not verify the peer certificate.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if not ca_path:
        log.warning(
            "postgres TLS encrypting without verification (db_ssl_mode=%s) — "
            "set DB_SSL_MODE=verify-full + DB_TLS_CA to verify the server",
            mode,
        )
    return ctx


def build_nats_tls(
    ca_path: str | None,
    cert_path: str | None = None,
    key_path: str | None = None,
) -> ssl.SSLContext | None:
    """Return an ``ssl.SSLContext`` for ``nats.connect(tls=...)``, or ``None``.

    ``None`` (no CA configured) means plaintext NATS — only acceptable for local
    dev, so it logs a warning. When ``ca_path`` is set the server certificate is
    verified; when ``cert_path`` + ``key_path`` are both set, mutual TLS is
    enabled by loading the client identity.
    """
    if not ca_path:
        log.warning("NATS TLS disabled — set NATS_TLS_CA to encrypt inter-service messaging")
        return None

    ctx = ssl.create_default_context(cafile=ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True

    if cert_path and key_path:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    elif cert_path or key_path:
        raise ValueError("NATS mutual TLS requires both NATS_TLS_CERT and NATS_TLS_KEY")

    return ctx
