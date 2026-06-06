"""SSRF guards for outbound webhook targets (ISO 27001 A.13 / A.14).

A ``webhook_url`` is supplied by the tenant on a provision request and later
POSTed to by the worker *from inside the cluster*. Without a guard a caller
could point it at link-local cloud metadata (169.254.169.254), loopback, or
any RFC-1918 service (NATS monitoring, the kube API, an internal DB admin) and
exfiltrate the completion payload or probe internal services — classic SSRF.

Two layers, used at two points:

  - ``validate_webhook_url`` — literal, non-resolving. Runs at *ingest* (the
    pydantic model) so an obvious ``http://10.0.0.1`` is rejected with a clean
    422 and never stored. Hostnames pass here and are re-checked at delivery.

  - ``assert_public_target`` — resolves the host and rejects if *any* resolved
    address is internal. Runs at *delivery* (webhook.deliver), which is the real
    egress boundary and the only place a hostname's true IPs are known. This
    also defends against a hostname that resolved cleanly at ingest but now
    points inward (DNS rebinding); a narrow TOCTOU window remains between this
    check and httpx's own connect — pinning the connection to the validated IP
    is a possible follow-up.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

import structlog

log = structlog.get_logger(__name__)

_ALLOWED_SCHEMES = ("http", "https")

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _ip_blocked(ip: _IPAddress) -> bool:
    """Whether ``ip`` is a non-routable / internal address we refuse to call.

    ``is_link_local`` covers 169.254.0.0/16, which includes the cloud metadata
    endpoint 169.254.169.254 (and the IPv6 fe80::/10 range).
    """
    # An IPv4-mapped IPv6 address (e.g. ::ffff:10.0.0.1) must be judged on its
    # embedded v4 address, otherwise the v4 private check is bypassed.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _parse_target(url: str) -> str:
    """Validate the scheme and return the host, or raise ValueError."""
    parts = urlsplit(url)
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValueError(f"webhook_url scheme must be http or https, got {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise ValueError("webhook_url has no host")
    return host


def validate_webhook_url(url: str) -> None:
    """Literal (non-resolving) ingest check. Raises ValueError when unsafe.

    Rejects a bad scheme and any IP-literal host in a blocked range. A hostname
    is accepted here — it is resolved and re-checked by ``assert_public_target``
    at delivery time.
    """
    host = _parse_target(url)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # hostname — deferred to delivery-time resolution
    if _ip_blocked(ip):
        raise ValueError(f"webhook_url points at a non-routable/internal address: {host}")


async def _resolve(host: str) -> list[str]:
    """Resolve ``host`` to its IP strings (seam: monkeypatched in tests)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


async def assert_public_target(url: str) -> None:
    """Delivery-time SSRF check. Raises ValueError when the target is unsafe.

    For an IP literal the address is checked directly (no DNS). For a hostname,
    *every* resolved address must be public — a single internal answer rejects
    the whole target.
    """
    host = _parse_target(url)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _ip_blocked(literal):
            raise ValueError(f"webhook_url points at a non-routable/internal address: {host}")
        return

    addresses = await _resolve(host)
    if not addresses:
        raise ValueError(f"webhook_url host did not resolve: {host}")
    for addr in addresses:
        if _ip_blocked(ipaddress.ip_address(addr)):
            raise ValueError(
                f"webhook_url host {host} resolves to a non-routable/internal address: {addr}"
            )
