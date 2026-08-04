"""The chart's documented config keys must be keys the process actually reads.

WHY THIS GUARD EXISTS. ``deploy/helm/edge-osb/values.yaml`` is where an operator
learns what to put in ``config.existingSecret``. Its access-control section
documented an ``API_KEY`` that "gates the provisioning API (POST/DELETE
/v1/services, GET /v1/requests)" — and ``Settings`` has no such field. Because
``Settings`` is configured ``extra="ignore"``, an operator who followed the chart
and set ``API_KEY`` in the secret got NO error, NO warning, and NO gate: the
value was read by nothing.

The provisioning API was never actually unprotected — it is gated by per-tenant
bearer keys in ``tenant_api_keys`` with a fail-closed startup check
(``startup_tenancy_check``). That is the sharper end of the problem: the chart
described a *second, weaker* lock that did not exist, so an operator's mental
model of their own access control was wrong in the direction of "I have
configured a control" when they had not. That is the sentence that gets read
aloud in a security review.

``extra="ignore"`` is right for a process whose env carries unrelated
Kubernetes/runtime variables — so the silence is not a bug to fix in pydantic.
The fix is to make the DOCUMENT true, and this test is what keeps it true: every
env var the chart tells an operator to set must be a field the process reads.
"""

from __future__ import annotations

import re
from pathlib import Path

from config import Settings

# values.yaml lives outside the osb package; resolve from this file so the test
# works from any working directory.
VALUES_YAML = (
    Path(__file__).resolve().parents[2] / "deploy" / "helm" / "edge-osb" / "values.yaml"
)

# Bullet lines of the shape `  #   - SOME_ENV_VAR  <prose>` inside the config
# comment block — the chart's list of secret keys an operator is told to supply.
# re.MULTILINE is load-bearing: without it `^` anchors to the start of the whole
# file, the match set comes back EMPTY, and the phantom-key assertion below
# passes vacuously. That is precisely the failure the premise check catches.
DOCUMENTED_KEY_RE = re.compile(r"^\s*#\s+-\s+([A-Z][A-Z0-9_]{2,})\b", re.MULTILINE)


def documented_secret_keys() -> set[str]:
    """Env-var names the chart documents as settable in config.existingSecret."""
    text = VALUES_YAML.read_text(encoding="utf-8")
    return {m.group(1) for m in DOCUMENTED_KEY_RE.finditer(text)}


def test_values_yaml_is_present_and_documents_something():
    """Premise check: without this, an empty match set would pass vacuously and
    this whole guard would be decoration."""
    assert VALUES_YAML.is_file(), f"chart values not found at {VALUES_YAML}"
    assert documented_secret_keys(), (
        "parsed ZERO documented secret keys out of values.yaml — the comment "
        "format changed and this guard silently stopped guarding anything"
    )


def test_every_documented_secret_key_is_read_by_settings():
    """Each documented key must map to a real Settings field.

    pydantic-settings lowercases env names onto field names, so ADMIN_API_KEY
    maps to Settings.admin_api_key. A documented key with no field is read by
    nothing: extra="ignore" swallows it silently.
    """
    fields = set(Settings.model_fields)
    phantom = {k for k in documented_secret_keys() if k.lower() not in fields}
    assert not phantom, (
        f"values.yaml documents {sorted(phantom)} as settable in the OSB config "
        f"secret, but Settings has no such field — extra='ignore' means setting "
        f"it does nothing, silently. Either implement the field or stop "
        f"documenting a control that does not exist. Known Settings fields: "
        f"{sorted(fields)}"
    )
