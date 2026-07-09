# Stand-up runbook

Bringing edge-infra up for real traffic needs a few **out-of-band** steps that
can't live in the repo — secret material (never committed) and commands that run
against **your** cluster/DB. This is the ordered runbook; §1 and §3 are tooled.

## 0. Preconditions
- A shared Postgres database reachable by **both** the control-plane and OSB — the
  R4 co-location invariant. Both **fail-closed at startup** if they don't share
  one DB (`store.VerifyColocation` / `db.verify_colocation`).
- `kubectl` access to the target namespace; `helm`; `openssl`.

## 1. Generate the admin-plane PKI + KEK  (`scripts/bootstrap-pki.sh`)
Generates the **edge-admin-ca** (the operator trust domain — SEPARATE from the
data-plane `edge-internal-ca`), the custodian TLS server cert, an operator client
cert, and a 256-bit **SECRET_KEK** — into a gitignored `.pki-bootstrap/` dir — and
prints the `kubectl` commands to load them. It runs no `kubectl` and commits
nothing.

```
EDGE_NAMESPACE=edge-infra scripts/bootstrap-pki.sh
```

Store `.pki-bootstrap/` securely. `admin-ca.key` stays **offline** (it only signs
new operator certs); `operator.crt`/`operator.key` stay local for the CLI.

## 2. Load the secrets
Run the printed `kubectl create secret` commands:
- `edge-admin-ca` — the operator client CA (custodian verifies operator certs
  against **only** this, so a data-plane proxy cert can never write key material);
- `edge-secrets-tls` — the custodian server cert;
- **SECRET_KEK** into **both** `edge-secrets-config` and
  `edge-control-plane-postgres` — the **same value** both sides, so the
  control-plane can decrypt what the custodian sealed. The custodian **refuses to
  start** without SECRET_KEK (encryption at rest is mandatory).

## 3. Migrate the shared DB
Apply both schemas (control-plane + OSB) **before** the services start — the
`edge-migrate` runner also ships as a Helm pre-install/pre-upgrade hook:

```
DATABASE_URL='postgres://…/edge?sslmode=require' edge-migrate
```

Adopting the runner on a DB that already has the schema (a pre-runner deploy)? Run
the one-time baseline first (see [migrations.md](migrations.md)):

```
DATABASE_URL='…' edge-migrate baseline
```

## 4. Deploy
`helm install` the charts. On startup: the control-plane and OSB each verify
co-location and refuse to start otherwise; the custodian requires SECRET_KEK and
seals key material at rest; the operator writes TLS secrets via the CLI,
authenticating with the operator client cert against `edge-admin-ca`.

## What remains the operator's to do
Two irreducible deploy-time actions run against **your** cluster/DB, not the repo —
both now tooled and documented, but performed by you:
1. run `bootstrap-pki` + load the secrets (§1–2);
2. run `edge-migrate` (+ `baseline` once, if adopting an existing DB) (§3).
