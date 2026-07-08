# OSB → data-plane translator (R4 Stage 1)

The OSB broker used to be a write-only registry: a self-service `CREATE` wrote a
`services` row that **no** data-plane component read, so provisioning produced
zero Envoy config. Stage 1 closes that gap for **HTTP** services: the worker now
fans a registered service out into control-plane rows the Go reconciler already
serves — a shared gateway, a per-service cluster + endpoint, and a route — all in
the **same transaction** as the `services` row.

## What a CREATE produces (HTTP only)

| row | identity |
|-----|----------|
| gateway | `osb-shared-http` (port 80, HTTP) — ensured once, idempotently, never per-service |
| cluster | `osb-{team}-{name}` (EDS, ROUND_ROBIN, 5s connect timeout) |
| endpoint | `{spec.host}:{spec.port}` on that cluster |
| route | `osb-{team}-{name}` on the shared gateway → the cluster, `hosts=[{spec.host}]`, `path_prefix=/` |

`DELETE` soft-deletes the route (so it drops from the next snapshot) and
hard-deletes the cluster (cascading its endpoints; clusters have no soft-delete).
The shared gateway persists.

- **HTTPS is deferred** to Stage 3 (per-SNI TLS + builder work): the `services`
  row is still written, but **no** data-plane rows are produced, and the deferral
  is recorded on the `osb_services_derived_total{protocol="HTTPS",outcome="deferred_https"}`
  counter — not silent.
- `auth_policy` / `rate_limit` / `health_check` / `node_selector` are stored on
  `services` as before but not yet rendered (Stage 3).
- Disjointness from controller-written rows is by the `osb-{team}-` name prefix.
  A formal owner column + `UNIQUE(team, name)` is Stage 2.

## Deploy precondition — CO-LOCATION (must confirm at stand-up)

Stage 1 requires the OSB broker and the control plane to share **one** Postgres
database, because the translator writes the control-plane rows in the OSB
worker's own transaction. The DSN values live in out-of-band Secrets, so the
charts cannot set them — the operator must ensure:

1. **Same database.** `edge-osb`'s `DATABASE_URL` (Secret `edge-osb-secrets`) and
   `edge-control-plane`'s `POSTGRES_DSN` (Secret `edge-control-plane-postgres`,
   key `dsn`) point at the **same** Postgres database on the same instance.
2. **Both schemas applied there.** Apply both migration sets to that database
   (idempotent; `CREATE ... IF NOT EXISTS`):

   ```sh
   psql "$DSN" -f migrations/0001_init.sql
   psql "$DSN" -f migrations/0002_controller_fields.sql
   psql "$DSN" -f osb/migrations/0001_osb.sql
   ```

   There is no automated migrate Job for the control-plane / OSB `.sql` sets yet
   (only `edge-issuer` self-migrates); apply them as a one-time step.
3. **Verify at first stand-up** (deferred, like R1's live handshake): an OSB
   provision must surface in a snapshot within the reconcile interval —
   `POST /v1/services` an HTTP service, then confirm within ~5s that the Envoy
   config-dump (or the control-plane `/readyz` snapshot) contains
   `osb-{team}-{name}`.

## Proving it locally

`make test-integration` stands up a throwaway Postgres, applies both schemas, and
runs the Python translator suite plus the Go cross-language E2E (the real Python
translator provisions a service; `LoadSnapshot` serves it, then drops it after
delete). Requires `docker`, `go`, and `python3`.
