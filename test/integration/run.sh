#!/usr/bin/env bash
# Integration harness for the OSB -> data-plane translator (R4 Stage 1).
#
# Stands up a throwaway Postgres, applies BOTH schemas to the ONE shared database
# (control-plane migrations/*.sql + osb/migrations/*.sql), then proves the
# translator end to end across the language boundary:
#   - the Python translator suite (worker.process_message writes the derived
#     gateway/cluster/endpoint/route in one transaction), and
#   - the Go cross-language E2E (the real Python translator provisions a service;
#     the Go reconciler's LoadSnapshot serves it, then drops it after delete).
#
# Requires: docker, go, python3 (>=3.11). Run: make test-integration
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"

PG=edge-it-pg
PORT="${IT_PG_PORT:-5433}"
DSN="postgresql://postgres:itpass@localhost:${PORT}/edge"
VENV="${IT_VENV:-$REPO/.venv-integration}"

cleanup() { docker rm -f "$PG" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> starting throwaway Postgres ($PG on :$PORT)"
docker rm -f "$PG" >/dev/null 2>&1 || true
docker run -d --name "$PG" \
  -e POSTGRES_PASSWORD=itpass -e POSTGRES_DB=edge \
  -p "${PORT}:5432" postgres:16-alpine >/dev/null
for _ in $(seq 1 30); do
  docker exec "$PG" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done

echo "==> applying BOTH migration sets to the one shared database"
for f in migrations/0001_init.sql migrations/0002_controller_fields.sql \
         migrations/0003_service_policy.sql migrations/0004_auth_policy.sql \
         migrations/0005_route_tls_secret.sql migrations/0006_secret_kind.sql \
         migrations/0007_route_client_ca.sql \
         osb/migrations/0001_osb.sql osb/migrations/0002_tenancy.sql; do
  docker exec -i "$PG" psql -U postgres -d edge -q -f - <"$f"
done

echo "==> python venv + deps (mirrors osb/pyproject.toml)"
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" -q install --upgrade pip >/dev/null
# Concrete deps (not `-e ./osb` — its requires-python is >=3.12; the tests import
# via sys.path so no package install is needed).
"$VENV/bin/pip" -q install \
  asyncpg "pytest>=8" pytest-asyncio respx cryptography \
  "pydantic>=2.7" pydantic-settings structlog httpx nats-py fastapi >/dev/null

export TEST_DATABASE_URL="$DSN"
export OSB_PROVISION="$VENV/bin/python $REPO/osb/tools/provision.py"

echo "==> python translator + tenancy integration suites"
(cd osb && "$VENV/bin/pytest" tests/test_translator.py tests/test_tenancy.py -q)

echo "==> go cross-language E2E (Python translator writes -> Go LoadSnapshot serves)"
go test -count=1 -tags integration ./internal/store/ -run TestLoadSnapshot_OSB

echo "==> go edge-secrets custodian E2E (component write -> LoadSnapshot renders per-SNI)"
go test -count=1 -tags integration ./internal/secrets/ -run TestE2E

echo "==> PASS: OSB -> data-plane translator proven against one shared DB"
