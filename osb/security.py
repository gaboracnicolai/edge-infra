"""HTTP security middleware + helpers for the OSB broker (ISO 27001 A.9, A.12, A.14).

Three concerns live here, each small and independently wired in ``main.py``:

  - ``SecurityHeadersMiddleware`` — defensive response headers on every reply.
  - ``RequestIDMiddleware``       — sanitised X-Request-ID propagation + log binding.
  - ``admin_key_ok``             — constant-time shared-secret check for admin routes.

The middlewares are plain ASGI classes (no Starlette ``BaseHTTPMiddleware``
overhead) so they can sit at the very edge of the stack and stamp headers even
on responses produced by deeper error handlers.
"""

from __future__ import annotations

import hmac
from uuid import uuid4

import structlog
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = structlog.get_logger(__name__)

# Maximum length (bytes) accepted from a client-supplied X-Request-ID. 64 is
# generous for distributed-tracing IDs (UUID = 36 chars) while preventing a
# caller from smuggling an arbitrarily large string into our structured logs
# or into the provision_requests row keyed by Nats-Msg-Id (ISO 27001 A.12.4).
REQUEST_ID_MAX_LEN = 64


def sanitize_request_id(raw: str) -> str:
    """Keep only ``[A-Za-z0-9_-]`` and cap at ``REQUEST_ID_MAX_LEN``.

    These are the characters used by UUID, ULID, and common trace-ID formats;
    anything else (newlines, colons, control chars) would be a log-injection
    footgun once the ID reaches a structured logger or a downstream header.
    Returns ``""`` when nothing survives so the caller can mint a fresh UUID.
    """
    out: list[str] = []
    for ch in raw:
        if ch.isascii() and (ch.isalnum() or ch in "-_"):
            out.append(ch)
            if len(out) >= REQUEST_ID_MAX_LEN:
                break
    return "".join(out)


def admin_key_ok(provided: str | None, configured: str | None) -> bool:
    """Whether ``provided`` satisfies the admin gate.

    When ``configured`` is falsy the gate is disabled (open) — this keeps local
    dev and an unconfigured Prometheus scraper working; production locks the
    gate by setting ``ADMIN_API_KEY`` via Helm. When configured, the comparison
    is constant-time to avoid leaking the secret through timing.
    """
    if not configured:
        return True
    if not provided:
        return False
    return hmac.compare_digest(provided, configured)


class SecurityHeadersMiddleware:
    """Stamp defensive headers on every HTTP response.

    OSB is a JSON/plain-text API with no browser UI, so the policy is maximally
    restrictive: ``default-src 'none'`` and no framing. Headers are written on
    the ``http.response.start`` message so they survive error responses too.
    """

    _CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Content-Security-Policy"] = self._CSP
            await send(message)

        await self.app(scope, receive, send_wrapper)


class RequestIDMiddleware:
    """Honour or mint an X-Request-ID and bind it to the structlog context.

    An incoming ``X-Request-ID`` is sanitised (alnum + ``-_``, max 64) and
    reused so distributed tracing works; an absent/empty-after-sanitisation
    value gets a fresh UUID. The id is echoed on the response and bound to
    structlog contextvars so every log line in the request carries it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = Headers(scope=scope).get("x-request-id", "")
        request_id = sanitize_request_id(incoming) or uuid4().hex

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        structlog.contextvars.bind_contextvars(request_id=request_id)
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
