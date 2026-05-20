"""Tests for the outbound webhook delivery loop."""

from __future__ import annotations

import httpx
import pytest
import respx

import webhook


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    """Replace asyncio.sleep with a recording awaitable so tests are instantaneous."""
    calls: list[float] = []

    async def fake_sleep(delay: float) -> None:
        calls.append(delay)

    monkeypatch.setattr("asyncio.sleep", fake_sleep)
    return calls


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
async def test_webhook_backoff_sequence(cfg, fast_sleep):
    respx.post("https://example.test/hook").mock(return_value=httpx.Response(500, text="boom"))
    await webhook.deliver("https://example.test/hook", {}, cfg)
    # 5 attempts with base 2.0 → sleeps of [2, 4, 8, 16] between them.
    assert fast_sleep == [2.0, 4.0, 8.0, 16.0]
