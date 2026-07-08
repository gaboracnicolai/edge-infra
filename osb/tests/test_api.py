"""FastAPI surface tests — drive endpoints through the ASGI transport."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import asyncpg
import nats.errors
import pytest


@pytest.fixture
def valid_spec() -> dict:
    return {
        "name": "my-service",
        "team": "platform",
        "host": "10.0.0.1",
        "port": 8080,
        "protocol": "HTTP",
        "auth_policy": "jwt",
    }


async def test_provision_valid(app_client, valid_spec):
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "PENDING"
    UUID(body["request_id"])
    assert "my-service" in body["message"]


async def test_provision_https_missing_tls_secret(app_client, valid_spec):
    valid_spec["protocol"] = "HTTPS"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_invalid_name_uppercase(app_client, valid_spec):
    valid_spec["name"] = "MyService"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_invalid_port(app_client, valid_spec):
    valid_spec["port"] = 99999
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_db_error(app_client, mock_pool, valid_spec):
    mock_pool.execute.side_effect = asyncpg.PostgresError("simulated db failure")
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 500


async def test_provision_nats_error(app_client, mock_pool, mock_js, valid_spec):
    mock_js.publish.side_effect = nats.errors.TimeoutError()
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 500
    # broker.provision must INSERT then, on publish failure, DELETE the row.
    assert mock_pool.execute.call_count == 2


async def test_provision_rejects_invalid_host(app_client, valid_spec):
    valid_spec["host"] = "bad host;rm -rf /"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_accepts_hostname(app_client, valid_spec):
    valid_spec["host"] = "edge-svc.prod.svc.cluster.local"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 202


async def test_provision_rejects_invalid_team(app_client, valid_spec):
    valid_spec["team"] = "Platform Team!"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_rejects_mtls_on_http(app_client, valid_spec):
    # mtls/jwt_or_mtls are transport-level (HTTPS-only, deferred to 3b); an HTTP
    # service must be rejected at the API boundary before enqueue.
    valid_spec["auth_policy"] = "mtls"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_rejects_jwt_or_mtls_on_http(app_client, valid_spec):
    valid_spec["auth_policy"] = "jwt_or_mtls"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_accepts_mtls_with_client_ca(app_client, valid_spec):
    # HTTPS + mtls + a client-CA is a complete, valid mtls spec → accepted.
    valid_spec["protocol"] = "HTTPS"
    valid_spec["tls_secret_name"] = "edge-cert"
    valid_spec["auth_policy"] = "mtls"
    valid_spec["client_ca_secret_name"] = "edge-client-ca"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 202


async def test_provision_rejects_mtls_without_client_ca(app_client, valid_spec):
    # mtls with NO client-CA is a misconfiguration (can't require a client cert
    # with no CA to verify against) — rejected at the API boundary (Slice 2).
    valid_spec["protocol"] = "HTTPS"
    valid_spec["tls_secret_name"] = "edge-cert"
    valid_spec["auth_policy"] = "mtls"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_rejects_control_char_node_selector(app_client, valid_spec):
    valid_spec["node_selector"] = {"zone": "eu-west\n1a"}
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_rejects_invalid_tls_secret_name(app_client, valid_spec):
    valid_spec["protocol"] = "HTTPS"
    valid_spec["tls_secret_name"] = "Bad_Secret Name"  # uppercase + underscore + space
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_accepts_valid_tls_secret_name(app_client, valid_spec):
    valid_spec["protocol"] = "HTTPS"
    valid_spec["tls_secret_name"] = "edge-tls.cert"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 202


async def test_provision_rejects_invalid_health_path(app_client, valid_spec):
    valid_spec["health_check"] = {"path": "not-rooted", "interval_seconds": 5}
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_rejects_control_char_health_path(app_client, valid_spec):
    valid_spec["health_check"] = {"path": "/health\ninject", "interval_seconds": 5}
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_accepts_valid_health_path(app_client, valid_spec):
    valid_spec["health_check"] = {"path": "/api/healthz", "interval_seconds": 5}
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 202


async def test_provision_rejects_internal_webhook(app_client, valid_spec):
    valid_spec["webhook_url"] = "http://169.254.169.254/latest/meta-data/"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 422


async def test_provision_accepts_public_webhook(app_client, valid_spec):
    valid_spec["webhook_url"] = "https://hooks.example.com/edge"
    response = await app_client.post("/v1/services", json=valid_spec)
    assert response.status_code == 202


async def test_deprovision(app_client, mock_pool):
    # The endpoint verifies the caller's tenant owns the service before enqueue;
    # make that ownership lookup succeed.
    mock_pool.fetchrow = AsyncMock(return_value={"exists": 1})
    response = await app_client.delete("/v1/services/my-service")
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "PENDING"
    assert "DELETE" in body["message"]
    assert "my-service" in body["message"]


async def test_deprovision_rejects_invalid_name(app_client):
    # The {name} path param skips ServiceSpec validation, so the endpoint must
    # reject a malformed name (injection vector) before queueing anything.
    response = await app_client.delete("/v1/services/Bad_Name!")
    assert response.status_code == 422


async def test_get_request_found(app_client, mock_pool):
    request_id = uuid4()
    mock_pool.fetchrow = AsyncMock(
        return_value={
            "id": request_id,
            "operation": "CREATE",
            "status": "PENDING",
            "payload": "{}",
            "webhook_url": None,
            "error": None,
            "completed_at": None,
            "created_at": datetime.now(tz=UTC),
        }
    )
    response = await app_client.get(f"/v1/requests/{request_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "PENDING"
    assert body["id"] == str(request_id)


async def test_get_request_not_found(app_client, mock_pool):
    mock_pool.fetchrow = AsyncMock(return_value=None)
    response = await app_client.get(f"/v1/requests/{uuid4()}")
    assert response.status_code == 404


async def test_healthz(app_client):
    response = await app_client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


# Per-tenant auth (bearer -> tenant_api_keys) and cross-tenant isolation are
# covered end-to-end against a real DB in test_tenancy.py; these surface tests
# run in open mode via the app_client fixture.
