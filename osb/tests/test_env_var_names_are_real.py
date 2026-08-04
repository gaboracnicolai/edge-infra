"""An operator-facing message must name an env var that actually works.

WHAT THIS CAUGHT. ``startup_tenancy_check`` refuses to start when
``tenant_api_keys`` is empty, and its RuntimeError told the operator:

    "... populate tenant_api_keys or set OSB_ALLOW_UNTENANTED=true for dev"

``Settings`` declares ``allow_untenanted`` with NO ``env_prefix``, so the
variable pydantic-settings actually reads is ``ALLOW_UNTENANTED``. Setting
``OSB_ALLOW_UNTENANTED=true`` changes nothing: the process still refuses to
start, still prints the same instruction, and the operator has no way to tell
that they followed it correctly.

DIRECTION OF FAILURE — worth being precise, because it decides the severity.
This fails CLOSED: the escape hatch cannot be opened by the documented name, so
tenant isolation stays ON. Nobody was ever exposed by it. What it costs is a dev
who cannot start the broker while doing exactly what the error told them to.

The quieter half is the audit story. ``require_tenant``'s docstring named
``OSB_ALLOW_UNTENANTED`` as "explicit open mode". An operator confirming their
isolation is on would grep their manifests for that string, find nothing, and
conclude they are safe — while the switch that really opens it,
``ALLOW_UNTENANTED``, is a string they were never told to look for. The
verification query most people would run looks for the wrong name.

So this guard is not about spelling. It is that every env var we NAME to an
operator must be one the process reads.
"""

from __future__ import annotations

import re

import pytest

from config import Settings

# Env-var-shaped tokens: SCREAMING_SNAKE, at least two segments so ordinary
# capitalised prose ("NOT", "ONLY") cannot be mistaken for a variable name.
ENV_TOKEN_RE = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b")

# Tokens that are legitimately not settings: table names, SQL, header names.
NOT_SETTINGS = {"NOT_NULL", "X_TENANT"}


def settings_env_names() -> set[str]:
    """The env-var names pydantic-settings will actually read.

    No env_prefix is configured, so each field maps to its own uppercased name.
    Asserting that here rather than assuming it keeps the guard honest if a
    prefix is ever introduced.
    """
    prefix = Settings.model_config.get("env_prefix") or ""
    return {f"{prefix}{name}".upper() for name in Settings.model_fields}


def test_no_env_prefix_assumption_holds():
    """Premise check. If a prefix is added later, the expected names change and
    this guard must be updated deliberately rather than silently passing."""
    assert Settings.model_config.get("env_prefix") in (None, ""), (
        "Settings gained an env_prefix — every operator-facing env var name in "
        "the codebase now needs the prefix, and this guard needs updating"
    )
    assert "ALLOW_UNTENANTED" in settings_env_names()


@pytest.mark.asyncio
async def test_startup_refusal_names_a_variable_that_exists():
    """The refuse-to-start error is the single most operator-facing string in
    this service — it is read at 3am by someone whose broker will not boot. Every
    env var it names must be one the process reads."""
    import main as osb_main

    class _EmptyPool:
        async def fetchval(self, *_args, **_kwargs):
            return 0

    settings = Settings(allow_untenanted=False)
    with pytest.raises(RuntimeError) as excinfo:
        await osb_main.startup_tenancy_check(_EmptyPool(), settings)

    message = str(excinfo.value)
    named = {t for t in ENV_TOKEN_RE.findall(message)} - NOT_SETTINGS
    assert named, (
        "the refusal message names no env var at all — if it stopped telling the "
        "operator how to proceed, this guard is checking nothing"
    )
    real = settings_env_names()
    phantom = named - real
    assert not phantom, (
        f"the refuse-to-start message tells the operator to set {sorted(phantom)}, "
        f"but pydantic-settings reads {sorted(real & {'ALLOW_UNTENANTED'})} — setting "
        f"the named variable does NOTHING and the process still refuses to start, "
        f"printing this same message again. Message was: {message!r}"
    )
