"""Tests for the webhook SSRF guard (netguard)."""

from __future__ import annotations

import pytest

import netguard

# ─── validate_webhook_url (literal, non-resolving) ───

BLOCKED_LITERALS = [
    "http://127.0.0.1/x",  # loopback
    "http://10.0.0.1/x",  # private A
    "http://172.16.5.4/x",  # private B
    "http://192.168.1.10/x",  # private C
    "http://169.254.169.254/latest/meta-data/",  # link-local / cloud metadata
    "http://0.0.0.0/x",  # unspecified
    "https://[::1]/x",  # IPv6 loopback
    "http://[::ffff:10.0.0.1]/x",  # IPv4-mapped IPv6 private
    "http://[fe80::1]/x",  # IPv6 link-local
]


@pytest.mark.parametrize("url", BLOCKED_LITERALS)
def test_validate_rejects_internal_literals(url):
    with pytest.raises(ValueError):
        netguard.validate_webhook_url(url)


def test_validate_rejects_bad_scheme():
    with pytest.raises(ValueError):
        netguard.validate_webhook_url("ftp://example.com/x")
    with pytest.raises(ValueError):
        netguard.validate_webhook_url("file:///etc/passwd")


def test_validate_allows_public_literal():
    netguard.validate_webhook_url("https://93.184.216.34/hook")  # no raise


def test_validate_allows_hostname_deferred():
    # hostnames pass the literal check; they're re-checked at delivery time.
    netguard.validate_webhook_url("https://hooks.example.com/x")  # no raise


# ─── assert_public_target (resolving) ────────────────


async def test_assert_public_literal_ok():
    await netguard.assert_public_target("https://93.184.216.34/hook")  # no raise


async def test_assert_blocks_internal_literal():
    with pytest.raises(ValueError):
        await netguard.assert_public_target("http://10.1.2.3/x")


async def test_assert_blocks_hostname_resolving_internal(monkeypatch):
    async def resolve(host: str) -> list[str]:
        return ["93.184.216.34", "192.168.0.9"]  # one internal answer is enough

    monkeypatch.setattr("netguard._resolve", resolve)
    with pytest.raises(ValueError):
        await netguard.assert_public_target("https://mixed.example.com/x")


async def test_assert_allows_hostname_resolving_public(monkeypatch):
    async def resolve(host: str) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("netguard._resolve", resolve)
    await netguard.assert_public_target("https://good.example.com/x")  # no raise


async def test_assert_rejects_unresolvable(monkeypatch):
    async def resolve(host: str) -> list[str]:
        return []

    monkeypatch.setattr("netguard._resolve", resolve)
    with pytest.raises(ValueError):
        await netguard.assert_public_target("https://nope.example.com/x")
