"""In-process Prometheus counters for the OSB broker process.

The worker runs in a separate process and maintains its own copy of these
dicts; only the broker process exposes /metrics, so worker counts are not
visible via HTTP (out of scope for in-process tracking).
"""

from __future__ import annotations

import asyncio
from collections import defaultdict

requests_total: dict[tuple[str, str], int] = defaultdict(int)
webhook_deliveries_total: dict[str, int] = defaultdict(int)
nats_messages_total: dict[tuple[str, str], int] = defaultdict(int)
# Data-plane fan-out outcomes, keyed by (protocol, outcome). HTTP services yield
# ("HTTP", "provisioned"); HTTPS services yield ("HTTPS", "provisioned_https")
# (R4 Stage 3b-i — per-SNI rendering, reference-only).
services_derived_total: dict[tuple[str, str], int] = defaultdict(int)

# ─ JetStream worker consumer depth (queue lag) ────────────────────────────────
# Only the broker serves /metrics, so the broker samples JetStream consumer_info
# for the worker's durable at scrape time (sample_consumer_pending, below) and
# renders it here. On any failure (NATS unreachable, consumer not created yet,
# timeout) _consumer_pending is set to None — NEVER a fabricated 0 that would look
# like a healthy drained queue — and _consumer_info_up flags the unknown as 0.
_CONSUMER_INFO_TIMEOUT_S = 3.0
_consumer_pending: int | None = None  # None = unknown this scrape (sample omitted)
_consumer_info_up: int = 0
_consumer_stream: str = ""
_consumer_durable: str = ""


async def sample_consumer_pending(js: object, stream: str, durable: str) -> None:
    """Sample num_pending for the worker's durable consumer from JetStream.

    Called by the broker's /metrics handler before ``render()``. A real value
    (including a genuine 0 for a drained queue) sets up=1; any failure sets the
    pending value to None and up=0 so an unreachable NATS / absent consumer never
    reports a healthy-looking 0 and never leaves a stale count behind.
    """
    global _consumer_pending, _consumer_info_up, _consumer_stream, _consumer_durable
    _consumer_stream, _consumer_durable = stream, durable
    try:
        info = await asyncio.wait_for(js.consumer_info(stream, durable), _CONSUMER_INFO_TIMEOUT_S)
        _consumer_pending = int(info.num_pending)
        _consumer_info_up = 1
    except Exception:
        _consumer_pending = None
        _consumer_info_up = 0


def _render_consumer_depth(lines: list[str]) -> None:
    """Append the consumer-depth gauges. No sample yet (durable unset) ⇒ skip."""
    if not _consumer_durable:
        return
    labels = f'stream="{_consumer_stream}",durable="{_consumer_durable}"'
    lines.append(
        "# HELP osb_nats_consumer_pending Messages pending for the worker durable "
        "consumer (queue depth); omitted when unknown — see osb_nats_consumer_info_up."
    )
    lines.append("# TYPE osb_nats_consumer_pending gauge")
    if _consumer_pending is not None:
        lines.append(f"osb_nats_consumer_pending{{{labels}}} {_consumer_pending}")
    lines.append(
        "# HELP osb_nats_consumer_info_up 1 if the broker read JetStream consumer "
        "info this scrape, else 0 (pending unknown, sample omitted)."
    )
    lines.append("# TYPE osb_nats_consumer_info_up gauge")
    lines.append(f"osb_nats_consumer_info_up{{{labels}}} {_consumer_info_up}")


def render() -> str:
    """Render the counters in Prometheus text exposition format."""
    lines: list[str] = []

    lines.append("# HELP osb_requests_total Provisioning requests by operation and status.")
    lines.append("# TYPE osb_requests_total counter")
    for (operation, status), count in sorted(requests_total.items()):
        lines.append(f'osb_requests_total{{operation="{operation}",status="{status}"}} {count}')

    lines.append("# HELP osb_webhook_deliveries_total Webhook delivery outcomes.")
    lines.append("# TYPE osb_webhook_deliveries_total counter")
    for result, count in sorted(webhook_deliveries_total.items()):
        lines.append(f'osb_webhook_deliveries_total{{result="{result}"}} {count}')

    lines.append("# HELP osb_nats_messages_total NATS message handling outcomes.")
    lines.append("# TYPE osb_nats_messages_total counter")
    for (operation, result), count in sorted(nats_messages_total.items()):
        lines.append(
            f'osb_nats_messages_total{{operation="{operation}",result="{result}"}} {count}'
        )

    lines.append("# HELP osb_services_derived_total Data-plane fan-out outcomes by protocol.")
    lines.append("# TYPE osb_services_derived_total counter")
    for (protocol, outcome), count in sorted(services_derived_total.items()):
        lines.append(
            f'osb_services_derived_total{{protocol="{protocol}",outcome="{outcome}"}} {count}'
        )

    _render_consumer_depth(lines)

    return "\n".join(lines) + "\n"
