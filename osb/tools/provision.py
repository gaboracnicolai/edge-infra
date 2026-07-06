#!/usr/bin/env python3
"""Test/ops driver: run one CREATE or DELETE through the real worker path.

Exercises worker.process_message (services write + translator fan-out, in one
transaction) against DATABASE_URL. Used by the Go integration test and the
integration harness to prove OSB CREATE -> derived rows -> a snapshot the Go
reconciler serves, end to end across the language boundary.

Usage:
    DATABASE_URL=... python provision.py create '<ServiceSpec JSON>'
    DATABASE_URL=... python provision.py delete '<JSON {"team","name"}>'

Exits non-zero if the worker naks (provision failed) so the caller sees it.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import asyncpg

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import worker  # noqa: E402
from config import Settings  # noqa: E402


async def _run(action: str, arg: str) -> None:
    cfg = Settings()
    if action == "create":
        subject, data = cfg.nats_subject_provision, arg.encode()
    elif action == "delete":
        # arg is the deprovision payload JSON, e.g. {"team":"t","name":"svc"}.
        subject, data = cfg.nats_subject_deprovision, arg.encode()
    else:
        sys.exit(f"unknown action {action!r} (want create|delete)")

    acked = {"v": False}

    async def ack() -> None:
        acked["v"] = True

    async def nak(delay: int = 0) -> None:
        pass

    msg = SimpleNamespace(
        subject=subject,
        data=data,
        headers={"Nats-Msg-Id": str(uuid.uuid4())},
        ack=ack,
        nak=nak,
    )

    pool = await asyncpg.create_pool(os.environ["DATABASE_URL"], min_size=1, max_size=2)
    try:
        await worker.process_message(msg, pool, cfg)
    finally:
        await pool.close()

    if not acked["v"]:
        sys.exit("worker naked the message (provision failed)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: provision.py {create|delete} <arg>")
    asyncio.run(_run(sys.argv[1], sys.argv[2]))
