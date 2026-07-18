"""Red-first: the broker-emitted JetStream consumer-depth gauge.

The worker's durable consumer lag is a real incident signal. Only the broker
process serves /metrics, so the broker samples JetStream ``consumer_info`` for
the configured durable and exposes it as ``osb_nats_consumer_pending``. The
unreachable case must NOT fabricate a healthy-looking 0 — it omits the pending
sample and flags ``osb_nats_consumer_info_up 0``.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import metrics


def _pending_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.startswith("osb_nats_consumer_pending{")]


async def test_pending_reported_from_consumer_info(cfg):
    """A live consumer_info(num_pending=42) → the gauge reports 42 and up=1."""
    js = AsyncMock()
    js.consumer_info = AsyncMock(return_value=SimpleNamespace(num_pending=42))

    await metrics.sample_consumer_pending(js, cfg.nats_stream, cfg.nats_consumer_durable)
    out = metrics.render()

    js.consumer_info.assert_awaited_once_with(cfg.nats_stream, cfg.nats_consumer_durable)
    assert (
        f'osb_nats_consumer_pending{{stream="{cfg.nats_stream}",'
        f'durable="{cfg.nats_consumer_durable}"}} 42'
    ) in out
    assert (
        f'osb_nats_consumer_info_up{{stream="{cfg.nats_stream}",'
        f'durable="{cfg.nats_consumer_durable}"}} 1'
    ) in out
    assert "# TYPE osb_nats_consumer_pending gauge" in out


async def test_genuine_zero_is_reported_not_omitted(cfg):
    """A real empty queue (num_pending=0) IS emitted as 0 — only *unknown* is omitted."""
    js = AsyncMock()
    js.consumer_info = AsyncMock(return_value=SimpleNamespace(num_pending=0))

    await metrics.sample_consumer_pending(js, cfg.nats_stream, cfg.nats_consumer_durable)
    out = metrics.render()

    assert (
        f'osb_nats_consumer_pending{{stream="{cfg.nats_stream}",'
        f'durable="{cfg.nats_consumer_durable}"}} 0'
    ) in out
    assert (
        f'osb_nats_consumer_info_up{{stream="{cfg.nats_stream}",'
        f'durable="{cfg.nats_consumer_durable}"}} 1'
    ) in out


async def test_unreachable_omits_pending_and_flags_down(cfg):
    """consumer_info failing (NATS down / consumer absent) must NOT fabricate a 0.

    The pending sample line is omitted entirely and osb_nats_consumer_info_up is 0.
    """
    js = AsyncMock()
    js.consumer_info = AsyncMock(side_effect=RuntimeError("nats unreachable / no consumer"))

    await metrics.sample_consumer_pending(js, cfg.nats_stream, cfg.nats_consumer_durable)
    out = metrics.render()

    assert _pending_lines(out) == []  # no fabricated 0, no stale value
    assert (
        f'osb_nats_consumer_info_up{{stream="{cfg.nats_stream}",'
        f'durable="{cfg.nats_consumer_durable}"}} 0'
    ) in out


async def test_failure_clears_a_prior_value(cfg):
    """A successful sample followed by a failure must drop to unknown, not keep the old count."""
    js_ok = AsyncMock()
    js_ok.consumer_info = AsyncMock(return_value=SimpleNamespace(num_pending=7))
    await metrics.sample_consumer_pending(js_ok, cfg.nats_stream, cfg.nats_consumer_durable)
    assert _pending_lines(metrics.render())  # present now

    js_bad = AsyncMock()
    js_bad.consumer_info = AsyncMock(side_effect=TimeoutError())
    await metrics.sample_consumer_pending(js_bad, cfg.nats_stream, cfg.nats_consumer_durable)
    assert _pending_lines(metrics.render()) == []  # stale 7 must be gone
