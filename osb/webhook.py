"""Outbound webhook delivery with exponential backoff."""

from __future__ import annotations

import asyncio
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
        await netguard.assert_public_target(url)
    except (ValueError, OSError) as exc:
        metrics.webhook_deliveries_total["blocked"] += 1
        log.error("webhook target blocked by SSRF guard", url=url, error=str(exc))
        return

    last_error: Exception | None = None
    async with httpx.AsyncClient() as client:
        for attempt in range(1, cfg.webhook_max_retries + 1):
            try:
                response = await client.post(url, json=payload, timeout=cfg.webhook_timeout_s)
                response.raise_for_status()
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
                delay = cfg.webhook_retry_base_s**attempt
                await asyncio.sleep(delay)

    metrics.webhook_deliveries_total["failure"] += 1
    log.error(
        "webhook delivery exhausted retries",
        url=url,
        attempts=cfg.webhook_max_retries,
        error=str(last_error),
    )
