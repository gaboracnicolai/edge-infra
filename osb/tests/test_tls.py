"""Unit tests for the TLS context builders in tls.py."""

from __future__ import annotations

import ssl
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

# Make the osb/ source modules importable when running tests in-place.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tls import build_nats_tls, build_pg_ssl  # noqa: E402


def _self_signed(tmp_path: Path) -> tuple[str, str]:
    """Write a throwaway self-signed cert + key, returning (cert_path, key_path).

    Skips the test if `cryptography` is unavailable. The cert doubles as a CA
    file for the verification contexts and as a client identity for mTLS.
    """
    crypto = pytest.importorskip("cryptography")  # noqa: F841
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "osb-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


# --- Postgres -------------------------------------------------------------


def test_pg_disable_returns_false():
    assert build_pg_ssl("disable", None) is False


def test_pg_require_without_ca_encrypts_without_verifying():
    ctx = build_pg_ssl("require", None)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_pg_invalid_mode_raises():
    with pytest.raises(ValueError, match="invalid db_ssl_mode"):
        build_pg_ssl("bogus", None)


@pytest.mark.parametrize("mode", ["verify-ca", "verify-full"])
def test_pg_verify_modes_require_ca(mode):
    with pytest.raises(ValueError, match="requires DB_TLS_CA"):
        build_pg_ssl(mode, None)


def test_pg_verify_full_with_ca_verifies_hostname(tmp_path):
    ca_path, _ = _self_signed(tmp_path)
    ctx = build_pg_ssl("verify-full", ca_path)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_pg_verify_ca_with_ca_skips_hostname(tmp_path):
    ca_path, _ = _self_signed(tmp_path)
    ctx = build_pg_ssl("verify-ca", ca_path)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is False


def test_pg_verify_full_bad_ca_path_raises():
    with pytest.raises((FileNotFoundError, ssl.SSLError)):
        build_pg_ssl("verify-full", "/nonexistent/ca.pem")


# --- NATS -----------------------------------------------------------------


def test_nats_no_ca_returns_none():
    assert build_nats_tls(None) is None


def test_nats_bad_ca_path_raises():
    with pytest.raises((FileNotFoundError, ssl.SSLError)):
        build_nats_tls("/nonexistent/ca.pem")


def test_nats_with_ca_verifies_server(tmp_path):
    ca_path, _ = _self_signed(tmp_path)
    ctx = build_nats_tls(ca_path)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_nats_mtls_requires_both_cert_and_key(tmp_path):
    ca_path, _ = _self_signed(tmp_path)
    with pytest.raises(ValueError, match="both NATS_TLS_CERT and NATS_TLS_KEY"):
        build_nats_tls(ca_path, cert_path=ca_path, key_path=None)


def test_nats_mtls_loads_client_identity(tmp_path):
    cert_path, key_path = _self_signed(tmp_path)
    ctx = build_nats_tls(cert_path, cert_path=cert_path, key_path=key_path)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
