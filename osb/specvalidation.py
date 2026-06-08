"""Input-validation helpers for ServiceSpec fields (ISO 27001 A.14).

The broker turns a tenant-supplied ServiceSpec into downstream Envoy/xDS config
and DB rows. Free-form strings there are a config-/log-injection surface, so the
fields that flow outward are constrained to predictable shapes here.

  - ``validate_host``      — must be an IP literal or an RFC-1123 hostname.
  - ``validate_node_selector`` — domain-agnostic bounds only (count, length,
    no control characters). NOTE: the label *semantics* belong to the xDS layer
    (Nicolai); this deliberately does not impose Kubernetes label charset rules,
    only abuse/injection guards, pending a sync on the matcher's real contract.
"""

from __future__ import annotations

import ipaddress
import re

# RFC 1123 hostname: dot-separated labels, each 1-63 chars of [A-Za-z0-9-] not
# starting/ending with a hyphen; total length <= 253.
_HOSTNAME_MAX = 253
_LABEL_MAX = 63

# node_selector abuse bounds — generous enough for real selectors, tight enough
# that a caller cannot stuff arbitrarily large/many entries into xDS config.
_NODE_SELECTOR_MAX_ENTRIES = 32
_NODE_SELECTOR_KEY_MAX = 253
_NODE_SELECTOR_VALUE_MAX = 63

# Service/team identifier: starts with a lowercase letter, then 1-62 chars of
# lowercase alnum or hyphen (2..63 total). Single source of truth shared by the
# ServiceSpec.name/team Field patterns and the deprovision path-param check, so
# the API can't accept a name shape the worker/xDS layer would later choke on.
SERVICE_NAME_PATTERN = r"^[a-z][a-z0-9-]{1,62}$"
_SERVICE_NAME_RE = re.compile(SERVICE_NAME_PATTERN)

# Health-check path bound. The path is interpolated into Envoy/xDS health-check
# config, so it must be a rooted, single-line, control-char-free string.
_HEALTH_PATH_MAX = 2048


def _is_valid_hostname(host: str) -> bool:
    if not host or len(host) > _HOSTNAME_MAX:
        return False
    labels = host.split(".")
    for label in labels:
        if not 1 <= len(label) <= _LABEL_MAX:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if not all(c.isascii() and (c.isalnum() or c == "-") for c in label):
            return False
    return True


def validate_host(host: str) -> str:
    """Return ``host`` if it is an IP literal or a valid RFC-1123 hostname.

    Raises ValueError otherwise. A bad host would otherwise be interpolated
    verbatim into Envoy/xDS cluster config.
    """
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _is_valid_hostname(host):
        raise ValueError(
            f"host must be an IP address or RFC-1123 hostname, got {host!r}"
        )
    return host


def _has_control_chars(s: str) -> bool:
    # Reject C0/C1 control chars (incl. newlines/tabs) that enable log/config
    # injection. Printable Unicode is left to the xDS layer's own contract.
    return any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in s)


def validate_node_selector(selector: dict[str, str]) -> dict[str, str]:
    """Bound the node_selector defensively (count / length / no control chars).

    Deliberately charset-agnostic on key/value contents beyond control chars —
    the label-matching semantics are owned by the xDS layer.
    """
    if len(selector) > _NODE_SELECTOR_MAX_ENTRIES:
        raise ValueError(
            f"node_selector has too many entries ({len(selector)} > {_NODE_SELECTOR_MAX_ENTRIES})"
        )
    for key, value in selector.items():
        if not key or len(key) > _NODE_SELECTOR_KEY_MAX:
            raise ValueError("node_selector key must be 1..253 chars")
        if len(value) > _NODE_SELECTOR_VALUE_MAX:
            raise ValueError(
                f"node_selector value for {key!r} exceeds {_NODE_SELECTOR_VALUE_MAX} chars"
            )
        if _has_control_chars(key) or _has_control_chars(value):
            raise ValueError(f"node_selector entry {key!r} contains control characters")
    return selector


def validate_service_name(name: str) -> str:
    """Return ``name`` if it matches :data:`SERVICE_NAME_PATTERN`, else ValueError.

    Shared by the ServiceSpec ingest validators and the DELETE path-param check
    so both reject the same shapes — the name flows into SQL params and xDS
    cluster identifiers downstream.
    """
    if not _SERVICE_NAME_RE.match(name):
        raise ValueError(
            f"name must match {SERVICE_NAME_PATTERN} (lowercase, 2..63 chars), got {name!r}"
        )
    return name


def validate_secret_name(secret_name: str) -> str:
    """Return ``secret_name`` if it is a valid lowercase RFC-1123 subdomain.

    A Kubernetes Secret name must be a DNS subdomain (lowercase alnum, '-', '.',
    no leading/trailing hyphen per label, <=253 chars). It is interpolated into
    the SDS/xDS reference, so reject anything that isn't a real Secret name
    rather than passing a config-injection vector downstream.
    """
    if secret_name != secret_name.lower():
        raise ValueError(f"tls_secret_name must be lowercase, got {secret_name!r}")
    if not _is_valid_hostname(secret_name):
        raise ValueError(
            f"tls_secret_name must be an RFC-1123 subdomain, got {secret_name!r}"
        )
    return secret_name


def validate_health_path(path: str) -> str:
    """Return ``path`` if it is a rooted, single-line, control-char-free URL path.

    The health-check path is interpolated into Envoy/xDS health-check config, so
    constrain it: must start with '/', no control chars or whitespace, bounded
    length. Charset beyond that is left to Envoy's own URL handling.
    """
    if not path.startswith("/"):
        raise ValueError(f"health_check.path must start with '/', got {path!r}")
    if len(path) > _HEALTH_PATH_MAX:
        raise ValueError(
            f"health_check.path exceeds {_HEALTH_PATH_MAX} chars ({len(path)})"
        )
    if _has_control_chars(path):
        raise ValueError("health_check.path contains control characters")
    if any(c.isspace() for c in path):
        raise ValueError("health_check.path contains whitespace")
    return path
