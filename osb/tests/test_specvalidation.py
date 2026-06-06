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
