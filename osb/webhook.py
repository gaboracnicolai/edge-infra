"""Outbound webhook delivery with exponential backoff."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import structlog

import metrics
from config import Settings

log = structlog.get_logger(__name__)


async def deliver(url: str, payload: dict[str, Any], cfg: Settings) -> None:
    """POST ``payload`` to ``url`` with exponential backoff.

    Never raises: a webhook failure must not fail the provision. Outcomes are
    surfaced via the ``osb_webhook_deliveries_total`` counter and structured
    logs.
    """
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
