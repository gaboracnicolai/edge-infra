"""Standalone async worker that consumes provisioning messages from JetStream."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import nats
import structlog
from nats.errors import TimeoutError as NatsTimeoutError
from nats.js.api import ConsumerConfig

import metrics
import webhook
from config import Settings
from db import create_pool
from models import ServiceSpec
from tls import build_nats_tls

log = structlog.get_logger(__name__)


def _operation_for(subject: str, cfg: Settings) -> str:
    if subject == cfg.nats_subject_provision:
        return "CREATE"
    if subject == cfg.nats_subject_deprovision:
        return "DELETE"
    return "UNKNOWN"


# Strong references to in-flight webhook deliveries. asyncio keeps only a weak
# reference to a bare create_task() result, so without this set a fire-and-forget
# delivery can be garbage-collected mid-flight. Each task drops itself when done.
_webhook_tasks: set[asyncio.Task[None]] = set()


def _spawn_webhook(url: str, payload: dict[str, Any], cfg: Settings) -> None:
    """Schedule a detached webhook delivery, decoupled from the ack path.

    Delivery used to be awaited inline before ``msg.ack()``; a slow or retrying
    target (worst case ~55s across retries) could exceed the consumer's
    ``ack_wait`` and make JetStream redeliver the message — re-writing the
    service row and re-firing the webhook. Running it as a background task lets
    us ack as soon as the durable state is committed. ``deliver()`` is
    best-effort and never raises, so the task needs no result handling.
    """
    task = asyncio.create_task(webhook.deliver(url, payload, cfg))
    _webhook_tasks.add(task)
    task.add_done_callback(_webhook_tasks.discard)


async def process_message(msg: Any, pool, cfg: Settings) -> None:
    """Apply a single NATS message: write services row, ack on success, nak on failure."""
    headers = msg.headers or {}
    request_id = headers.get("Nats-Msg-Id")
    operation = _operation_for(msg.subject, cfg)
    service_name: str | None = None
    pending_webhook: tuple[str, dict[str, Any]] | None = None

    try:
        if msg.subject == cfg.nats_subject_provision:
            spec = ServiceSpec.model_validate_json(msg.data)
            service_name = spec.name
            await pool.execute(
                """
                INSERT INTO services
                    (name, team, host, port, protocol, tls_secret_name, auth_policy,
                     rate_limit, health_check, node_selector)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb)
                ON CONFLICT (name) DO UPDATE SET
                    team             = EXCLUDED.team,
                    host             = EXCLUDED.host,
                    port             = EXCLUDED.port,
                    protocol         = EXCLUDED.protocol,
                    tls_secret_name  = EXCLUDED.tls_secret_name,
                    auth_policy      = EXCLUDED.auth_policy,
                    rate_limit       = EXCLUDED.rate_limit,
                    health_check     = EXCLUDED.health_check,
                    node_selector    = EXCLUDED.node_selector,
                    updated_at       = NOW(),
                    deleted_at       = NULL
                """,
                spec.name,
                spec.team,
                spec.host,
                spec.port,
                spec.protocol,
                spec.tls_secret_name,
                spec.auth_policy,
                spec.rate_limit.model_dump_json() if spec.rate_limit else None,
                spec.health_check.model_dump_json() if spec.health_check else None,
                json.dumps(spec.node_selector),
            )
        elif msg.subject == cfg.nats_subject_deprovision:
            payload = json.loads(msg.data)
            service_name = payload["name"]
            await pool.execute(
                """
                UPDATE services SET deleted_at = NOW(), updated_at = NOW()
                WHERE name = $1 AND deleted_at IS NULL
                """,
                service_name,
            )
        else:
            log.warning("unknown subject; acking to drop", subject=msg.subject)
            await msg.ack()
            return

        if request_id is not None:
            await pool.execute(
                """
                UPDATE provision_requests
                SET status = 'COMPLETED', completed_at = NOW()
                WHERE id = $1
                """,
                request_id,
            )
            row = await pool.fetchrow(
                "SELECT webhook_url FROM provision_requests WHERE id = $1",
                request_id,
            )
            if row is not None and row["webhook_url"]:
                # Capture the delivery; fire it only after the ack below so a
                # slow webhook can't hold the message past ack_wait.
                pending_webhook = (
                    row["webhook_url"],
                    {
                        "request_id": str(request_id),
                        "status": "COMPLETED",
                        "service": service_name,
                        "timestamp": datetime.now(tz=UTC).isoformat(),
                    },
                )

        await msg.ack()
        metrics.nats_messages_total[(operation, "ack")] += 1

    except Exception as exc:  # noqa: BLE001 — any failure becomes a nak + status update
        log.exception("worker processing failed", request_id=request_id, subject=msg.subject)
        if request_id is not None:
            try:
                await pool.execute(
                    """
                    UPDATE provision_requests
                    SET status = 'FAILED', error = $1
                    WHERE id = $2
                    """,
                    str(exc),
                    request_id,
                )
            except Exception:  # noqa: BLE001 — best-effort status write
                log.exception("failed to mark provision_requests FAILED", request_id=request_id)
        await msg.nak(delay=30)
        metrics.nats_messages_total[(operation, "nak")] += 1
        return

    # Reached only on the success path (the except above returns). The message
    # is already acked, so this detached delivery can never hold it past
    # ack_wait or cause a redelivery.
    if pending_webhook is not None:
        url, payload = pending_webhook
        _spawn_webhook(url, payload, cfg)


async def run_worker(cfg: Settings, pool, js) -> None:
    """Subscribe to ``edge.provision.*`` and process messages until cancelled."""
    sub = await js.subscribe(
        "edge.provision.*",
        durable=cfg.nats_consumer_durable,
        manual_ack=True,
        config=ConsumerConfig(ack_wait=30, max_deliver=6),
    )
    log.info("worker subscribed", durable=cfg.nats_consumer_durable)

    while True:
        try:
            msg = await sub.next_msg(timeout=5.0)
        except NatsTimeoutError:
            continue
        except asyncio.CancelledError:
            await sub.unsubscribe()
            raise
        await process_message(msg, pool, cfg)


async def main() -> None:
    """Wire up the pool + JetStream and run the worker loop."""
    cfg = Settings()
    pool = await create_pool(cfg.database_url, ssl_mode=cfg.db_ssl_mode, ca_path=cfg.db_tls_ca)
    nats_tls = build_nats_tls(cfg.nats_tls_ca, cfg.nats_tls_cert, cfg.nats_tls_key)
    nc = await nats.connect(cfg.nats_url, tls=nats_tls)
    js = nc.jetstream()
    try:
        await run_worker(cfg, pool, js)
    finally:
        await nc.drain()
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
