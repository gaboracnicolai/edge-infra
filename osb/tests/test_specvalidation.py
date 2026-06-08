"""Tests for ServiceSpec field validation helpers."""

from __future__ import annotations

import pytest

import specvalidation

# ─── validate_host ───────────────────────────────────

VALID_HOSTS = [
    "10.0.0.1",
    "192.168.1.1",
    "::1",
    "2001:db8::1",
    "edge-osb",
    "my-svc.namespace.svc.cluster.local",
    "api.example.com",
    "a" * 63,  # max label length
]

INVALID_HOSTS = [
    "",
    "-leading.example.com",
    "trailing-.example.com",
    "has space.com",
    "under_score.com",  # underscore not valid in RFC-1123 hostnames
    "bad..double.dot",
    "a" * 64,  # label too long
    ("x" * 250 + ".com"),  # over 253 total
    "host;rm -rf",  # injection attempt
    "host\nLog-Inject",
]


@pytest.mark.parametrize("host", VALID_HOSTS)
def test_validate_host_accepts(host):
    assert specvalidation.validate_host(host) == host


@pytest.mark.parametrize("host", INVALID_HOSTS)
def test_validate_host_rejects(host):
    with pytest.raises(ValueError):
        specvalidation.validate_host(host)


# ─── validate_node_selector ──────────────────────────


def test_node_selector_accepts_normal():
    sel = {"kubernetes.io/hostname": "node-1", "topology.kubernetes.io/zone": "eu-west-1a"}
    assert specvalidation.validate_node_selector(sel) == sel


def test_node_selector_accepts_empty():
    assert specvalidation.validate_node_selector({}) == {}


def test_node_selector_rejects_too_many_entries():
    sel = {f"k{i}": "v" for i in range(33)}
    with pytest.raises(ValueError):
        specvalidation.validate_node_selector(sel)


def test_node_selector_rejects_empty_key():
    with pytest.raises(ValueError):
        specvalidation.validate_node_selector({"": "v"})


def test_node_selector_rejects_overlong_value():
    with pytest.raises(ValueError):
        specvalidation.validate_node_selector({"k": "v" * 64})


def test_node_selector_rejects_control_chars():
    with pytest.raises(ValueError):
        specvalidation.validate_node_selector({"k": "v\ninjected"})
    with pytest.raises(ValueError):
        specvalidation.validate_node_selector({"k\t": "v"})


# ─── validate_service_name ───────────────────────────

VALID_SERVICE_NAMES = [
    "api-svc",
    "ab",  # minimum 2 chars
    "a" + "b" * 62,  # maximum 63 chars
    "edge-osb-worker-1",
]

INVALID_SERVICE_NAMES = [
    "",
    "a",  # too short (1 char)
    "a" + "b" * 63,  # too long (64 chars)
    "1svc",  # must start with a letter
    "-svc",  # must start with a letter
    "API-SVC",  # uppercase not allowed
    "api_svc",  # underscore not allowed
    "api.svc",  # dot not allowed
    "api svc",  # whitespace
    "api/../etc",  # path traversal
    "api\nsvc",  # newline injection
]


@pytest.mark.parametrize("name", VALID_SERVICE_NAMES)
def test_validate_service_name_accepts(name):
    assert specvalidation.validate_service_name(name) == name


@pytest.mark.parametrize("name", INVALID_SERVICE_NAMES)
def test_validate_service_name_rejects(name):
    with pytest.raises(ValueError):
        specvalidation.validate_service_name(name)


# ─── validate_secret_name ────────────────────────────

VALID_SECRET_NAMES = [
    "tls-cert",
    "api-svc.tls",
    "my-secret-1",
    "a" * 63,
]

INVALID_SECRET_NAMES = [
    "",
    "TLS-Cert",  # must be lowercase
    "-leading",
    "trailing-",
    "has space",
    "under_score",
    "secret\ninject",
    "a" * 254,  # over 253
]


@pytest.mark.parametrize("secret", VALID_SECRET_NAMES)
def test_validate_secret_name_accepts(secret):
    assert specvalidation.validate_secret_name(secret) == secret


@pytest.mark.parametrize("secret", INVALID_SECRET_NAMES)
def test_validate_secret_name_rejects(secret):
    with pytest.raises(ValueError):
        specvalidation.validate_secret_name(secret)


# ─── validate_health_path ────────────────────────────

VALID_HEALTH_PATHS = [
    "/healthz",
    "/",
    "/api/v1/health",
    "/health?ready=1",
]

INVALID_HEALTH_PATHS = [
    "",
    "healthz",  # not rooted
    "//evil\nLog-Inject",  # control char
    "/has space",  # whitespace
    "/tab\there",
    "/" + "a" * 2048,  # over max length
]


@pytest.mark.parametrize("path", VALID_HEALTH_PATHS)
def test_validate_health_path_accepts(path):
    assert specvalidation.validate_health_path(path) == path


@pytest.mark.parametrize("path", INVALID_HEALTH_PATHS)
def test_validate_health_path_rejects(path):
    with pytest.raises(ValueError):
        specvalidation.validate_health_path(path)
