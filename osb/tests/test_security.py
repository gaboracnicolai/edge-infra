"""Tests for HTTP security middleware + admin gating (Item 5)."""

from __future__ import annotations

from security import (
    REQUEST_ID_MAX_LEN,
    admin_key_ok,
    bearer_token,
    sanitize_request_id,
    secret_matches,
)

# ─── sanitize_request_id ─────────────────────────────


def test_sanitize_keeps_valid_chars():
    assert sanitize_request_id("abc-DEF_123") == "abc-DEF_123"


def test_sanitize_strips_disallowed_chars():
    # newlines/colons/spaces would be a log-injection footgun.
    assert sanitize_request_id("a b\nc:d\te") == "abcde"


def test_sanitize_uuid_passthrough():
    uid = "550e8400-e29b-41d4-a716-446655440000"
    assert sanitize_request_id(uid) == uid


def test_sanitize_truncates_to_max_len():
    out = sanitize_request_id("x" * 200)
    assert len(out) == REQUEST_ID_MAX_LEN


def test_sanitize_empty_when_all_stripped():
    assert sanitize_request_id("\n\t :;<>") == ""


def test_sanitize_empty_input():
    assert sanitize_request_id("") == ""


def test_sanitize_drops_non_ascii():
    # full-width / unicode letters are excluded even though str.isalnum() is True
    assert sanitize_request_id("héllo") == "hllo"


# ─── admin_key_ok ────────────────────────────────────


def test_admin_open_when_unconfigured():
    assert admin_key_ok(None, None) is True
    assert admin_key_ok("anything", "") is True


def test_admin_match():
    assert admin_key_ok("s3cret", "s3cret") is True


def test_admin_wrong_key():
    assert admin_key_ok("nope", "s3cret") is False


def test_admin_missing_key_when_configured():
    assert admin_key_ok(None, "s3cret") is False
    assert admin_key_ok("", "s3cret") is False


# ─── bearer_token ────────────────────────────────────


def test_bearer_extracts_token():
    assert bearer_token("Bearer abc123") == "abc123"


def test_bearer_scheme_case_insensitive():
    assert bearer_token("bearer abc123") == "abc123"
    assert bearer_token("BEARER abc123") == "abc123"


def test_bearer_strips_surrounding_whitespace():
    assert bearer_token("Bearer   abc123  ") == "abc123"


def test_bearer_none_when_absent():
    assert bearer_token(None) is None
    assert bearer_token("") is None


def test_bearer_none_for_other_scheme():
    assert bearer_token("Basic abc123") is None


def test_bearer_none_when_token_empty():
    assert bearer_token("Bearer") is None
    assert bearer_token("Bearer ") is None


def test_secret_matches_is_admin_key_ok_alias():
    # the provisioning gate reuses the same constant-time check as /metrics
    assert secret_matches is admin_key_ok


# ─── middleware integration through the ASGI app ─────


async def test_security_headers_present(app_client):
    resp = await app_client.get("/healthz")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]


async def test_request_id_minted_when_absent(app_client):
    resp = await app_client.get("/healthz")
    rid = resp.headers["X-Request-ID"]
    assert rid
    assert sanitize_request_id(rid) == rid


async def test_request_id_honoured_and_sanitised(app_client):
    resp = await app_client.get("/healthz", headers={"X-Request-ID": "trace-123\nINJECT"})
    assert resp.headers["X-Request-ID"] == "trace-123INJECT"


async def test_healthz_open_without_admin_key(app_client):
    # liveness probe must never require a credential
    resp = await app_client.get("/healthz")
    assert resp.status_code == 200


async def test_metrics_open_when_key_unset(app_client):
    # default Settings() has no admin_api_key → /metrics stays open
    resp = await app_client.get("/metrics")
    assert resp.status_code == 200


async def test_metrics_requires_key_when_configured(app_client, monkeypatch):
    import main

    monkeypatch.setattr(main.cfg, "admin_api_key", "s3cret")
    # missing → 401
    assert (await app_client.get("/metrics")).status_code == 401
    # wrong → 403
    bad = await app_client.get("/metrics", headers={"X-Admin-Key": "nope"})
    assert bad.status_code == 403
    # correct → 200
    ok = await app_client.get("/metrics", headers={"X-Admin-Key": "s3cret"})
    assert ok.status_code == 200


async def test_security_headers_on_error_response(app_client, monkeypatch):
    # headers must be stamped even on a gated 401
    import main

    monkeypatch.setattr(main.cfg, "admin_api_key", "s3cret")
    resp = await app_client.get("/metrics")
    assert resp.status_code == 401
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Request-ID"]
