"""Tests for the outbound webhook delivery loop."""

from __future__ import annotations

import httpx
import pytest
import respx

import metrics
import webhook


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    """Replace asyncio.sleep with a recording awaitable so tests are instantaneous."""
    calls: list[float] = []

    async def fake_sleep(delay: float) -> None:
        calls.append(delay)

    monkeypatch.setattr("asyncio.sleep", fake_sleep)
    return calls


@pytest.fixture(autouse=True)
def allow_resolution(monkeypatch):
    """Resolve every hostname to a public IP so the SSRF egress guard lets the
    delivery tests through (example.test is NXDOMAIN in the real resolver)."""

    async def fake_resolve(host: str) -> list[str]:
        return ["93.184.216.34"]  # public (example.com)

    monkeypatch.setattr("netguard._resolve", fake_resolve)


@respx.mock
async def test_webhook_success_single_attempt(cfg, fast_sleep):
    route = respx.post("https://example.test/hook").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    await webhook.deliver("https://example.test/hook", {"hello": "world"}, cfg)
    assert route.called
    assert route.call_count == 1
    assert fast_sleep == []  # no retries → no sleeps


@respx.mock
async def test_webhook_retries_on_500(cfg, fast_sleep):
    route = respx.post("https://example.test/hook").mock(
        return_value=httpx.Response(500, text="boom")
    )
    await webhook.deliver("https://example.test/hook", {}, cfg)
    assert route.call_count == cfg.webhook_max_retries
    # max_retries attempts → (max_retries - 1) sleeps
    assert len(fast_sleep) == cfg.webhook_max_retries - 1


@respx.mock
async def test_webhook_retries_on_timeout(cfg, fast_sleep):
    route = respx.post("https://example.test/hook").mock(side_effect=httpx.TimeoutException("slow"))
    await webhook.deliver("https://example.test/hook", {}, cfg)
    assert route.call_count == cfg.webhook_max_retries
    assert len(fast_sleep) == cfg.webhook_max_retries - 1


@respx.mock
async def test_webhook_backoff_sequence(cfg, fast_sleep, monkeypatch):
    # Pin jitter off so the backoff is deterministic: base 2.0 → [2, 4, 8, 16].
    monkeypatch.setattr(cfg, "webhook_retry_jitter", 0.0)
    respx.post("https://example.test/hook").mock(return_value=httpx.Response(500, text="boom"))
    await webhook.deliver("https://example.test/hook", {}, cfg)
    # 5 attempts with base 2.0 → sleeps of [2, 4, 8, 16] between them.
    assert fast_sleep == [2.0, 4.0, 8.0, 16.0]


@respx.mock
async def test_webhook_backoff_jitter_within_bounds(cfg, fast_sleep):
    # With jitter enabled each delay must sit in [base**n, base**n * (1 + jitter)].
    assert cfg.webhook_retry_jitter > 0
    respx.post("https://example.test/hook").mock(return_value=httpx.Response(500, text="boom"))
    await webhook.deliver("https://example.test/hook", {}, cfg)
    base_delays = [cfg.webhook_retry_base_s**n for n in range(1, cfg.webhook_max_retries)]
    assert len(fast_sleep) == len(base_delays)
    for delay, base in zip(fast_sleep, base_delays, strict=True):
        assert base <= delay <= base * (1 + cfg.webhook_retry_jitter)
    # Jitter is additive, so the delays must still be strictly increasing here
    # (base growth dominates the bounded jitter for base 2.0).
    assert fast_sleep == sorted(fast_sleep)


@respx.mock
async def test_webhook_treats_3xx_as_failure(cfg, fast_sleep):
    """A 3xx response is a failed delivery, not a success: the client doesn't
    follow redirects (that would be an SSRF hole), so a redirected hook never
    received the payload. It must retry to exhaustion and count as a failure."""
    route = respx.post("https://example.test/hook").mock(
        return_value=httpx.Response(302, headers={"Location": "https://elsewhere.test/"})
    )
    before = metrics.webhook_deliveries_total["failure"]
    await webhook.deliver("https://example.test/hook", {}, cfg)
    assert route.call_count == cfg.webhook_max_retries
    assert len(fast_sleep) == cfg.webhook_max_retries - 1
    assert metrics.webhook_deliveries_total["failure"] == before + 1


@respx.mock
async def test_webhook_blocked_internal_literal(cfg, fast_sleep):
    """An IP-literal target inside the cluster is dropped before any HTTP call."""
    route = respx.post("http://169.254.169.254/latest/meta-data/").mock(
        return_value=httpx.Response(200)
    )
    before = metrics.webhook_deliveries_total["blocked"]
    await webhook.deliver("http://169.254.169.254/latest/meta-data/", {}, cfg)
    assert not route.called
    assert metrics.webhook_deliveries_total["blocked"] == before + 1


@respx.mock
async def test_webhook_blocked_hostname_resolving_internal(cfg, fast_sleep, monkeypatch):
    """A hostname that resolves to an internal IP (rebinding) is dropped."""

    async def resolve_internal(host: str) -> list[str]:
        return ["10.0.0.5"]

    monkeypatch.setattr("netguard._resolve", resolve_internal)
    route = respx.post("https://hook.evil.test/x").mock(return_value=httpx.Response(200))
    before = metrics.webhook_deliveries_total["blocked"]
    await webhook.deliver("https://hook.evil.test/x", {}, cfg)
    assert not route.called
    assert metrics.webhook_deliveries_total["blocked"] == before + 1
