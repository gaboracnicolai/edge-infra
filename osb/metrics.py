"""In-process Prometheus counters for the OSB broker process.

The worker runs in a separate process and maintains its own copy of these
dicts; only the broker process exposes /metrics, so worker counts are not
visible via HTTP (out of scope for in-process tracking).
"""

from __future__ import annotations

from collections import defaultdict

requests_total: dict[tuple[str, str], int] = defaultdict(int)
webhook_deliveries_total: dict[str, int] = defaultdict(int)
nats_messages_total: dict[tuple[str, str], int] = defaultdict(int)


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

    return "\n".join(lines) + "\n"
