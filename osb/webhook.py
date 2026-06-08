"""Outbound webhook delivery with exponential backoff."""

from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx
import structlog

import metrics
import netguard
from config import Settings

log = structlog.get_logger(__name__)


async def deliver(url: str, payload: dict[str, Any], cfg: Settings) -> None:
    """POST ``payload`` to ``url`` with exponential backoff.

    Never raises: a webhook failure must not fail the provision. Outcomes are
    surfaced via the ``osb_webhook_deliveries_total`` counter and structured
    logs.
    """
    # SSRF egress guard: refuse to call a target that resolves to an internal /
    # non-routable address (ISO 27001 A.13/A.14). This is the real boundary —
    # it runs after DNS resolution, so a hostname cannot smuggle an internal IP
    # past the ingest literal check. Never raises: a blocked target is a dropped
    # webhook, not a failed provision.
    try:
        pinned_ip = await netguard.assert_public_target(url)
    except (ValueError, OSError) as exc:
        metrics.webhook_deliveries_total["blocked"] += 1
        log.error("webhook target blocked by SSRF guard", url=url, error=str(exc))
        return

    # Pin the TCP connect to the IP we just validated. Without this, httpx would
    # re-resolve the hostname at connect time and a rebinding DNS answer could
    # still steer the socket at an internal address (TOCTOU). The URL keeps its
    # hostname, so TLS SNI / cert verification are unaffected.
    transport = netguard.pinned_async_transport(pinned_ip)
    last_error: Exception | None = None
    async with httpx.AsyncClient(transport=transport) as client:
        for attempt in range(1, cfg.webhook_max_retries + 1):
            try:
                response = await client.post(url, json=payload, timeout=cfg.webhook_timeout_s)
                # Treat anything that isn't 2xx as a failed delivery. raise_for_status()
                # only fires on 4xx/5xx, so a 3xx would otherwise count as success — but
                # the client doesn't follow redirects (following one would be an SSRF
                # hole), so a redirected hook never actually received the payload.
                if not response.is_success:
                    raise httpx.HTTPStatusError(
                        f"non-success webhook status {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                metrics.webhook_deliveries_total["success"] += 1
                log.info("webhook delivered", url=url, attempt=attempt)
                return
            except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.RequestError) as exc:
                last_error = exc
                log.warning(
                    "webhook attempt failed",
                    url=url,
                    attempt=attempt,
                    error=str(exc),
                )
                if attempt >= cfg.webhook_max_retries:
                    break
                # Exponential backoff with optional random jitter so many workers
                # retrying at once don't hammer a recovering endpoint in lockstep.
                delay = cfg.webhook_retry_base_s**attempt
                if cfg.webhook_retry_jitter > 0:
                    delay += random.uniform(0, cfg.webhook_retry_jitter * delay)
                await asyncio.sleep(delay)

    metrics.webhook_deliveries_total["failure"] += 1
    log.error(
        "webhook delivery exhausted retries",
        url=url,
        attempts=cfg.webhook_max_retries,
        error=str(last_error),
    )
