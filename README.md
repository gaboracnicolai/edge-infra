# edge-infra

Envoy xDS control plane, Rust `ext_authz` auth-service, OSB broker, and token issuer for a
multi-tenant edge.

---

# ⚠ THIS REPOSITORY IS PARKED

**It is not deployed anywhere, and nothing in the running product depends on it.**

The live stack is docker-compose: `lens`, `postgres`, `redis`, `nats`, `pgbouncer`, `caddy`,
`autoheal`. There is no Kubernetes in it. edge-infra is not in that topology, in any environment.

Parked means: **the code is kept, CI keeps running, and no one is expected to deploy it.** It was
parked deliberately, after an audit, rather than drifting into disuse. If you are here to turn it on,
read [§ Reviving it](#reviving-it) first — several things that look ready are not.

### What is parked, specifically

| | |
|---|---|
| Deployed | **Nothing.** No cluster, no ArgoCD instance in the serving path. |
| `ext_authz` (gateway authentication) | Built. **Off** in base and all four overlays. |
| Identity-keyed rate limiting (RLS) | Built. **Off** everywhere — though the `edge-ratelimit` chart *would* deploy (2 replicas + Redis in prod overlays), the control plane never routes to it. |
| Admin READ API | Built. **Off everywhere** — `adminApi.existingSecret` is unset in dev, staging, and both prod regions, so the listener never starts and the Service exposes no port. |
| Local rate limiting | Built and **on** by default. |
| Consuming UI | None. The suite's `/admin` area was **deleted** (`AdminRemoved.test.tsx` pins that it stays gone) because it rendered invented node identities, IPs, cert fingerprints and an issuer string for a service that is not deployed. |

---

## ⚠ Before you trust "16 of 17 done"

**That register is not in this repository.** It could not be found here. Only three item IDs appear
anywhere in-tree — `SEC-3`, `CFG-1`, `XDS-1` — and all of them in `deploy/local/README.md` and code
comments. So nothing in this repo, and nothing in CI, can contradict the tally. It lives where no
code can check it.

Audited independently against the code, the register is **accurate about code merged and silent about
arming**. Every item claimed done has its code present; some are better than claimed (SEC-9's Envoy
admin exposure is fully fixed — admin on `127.0.0.1:9901`, a dedicated `/ready` listener, probes and
scrape repointed — even though the PR that raised it was closed unfixed).

**But for this repository, arming is the entire remaining distance.** The three headline security
controls — gateway authentication, identity-keyed rate limiting, and the admin API — are all shipped
**off**. A green register describes merged code, not controls in force. Read it that way.

To this repo's credit, the off-state is deliberate and documented rather than hidden:
`deploy/helm/edge-control-plane/values.yaml:53-59` explicitly warns against flipping `extAuthz` in
base because ArgoCD auto-syncs. That is honest inertness. It is still inertness.

---

## ⚠ The first thing that will burn you: the defaults contradict each other

Three individually-defensible decisions compose into a system that publishes nothing:

- `auth_policy` defaults to **`'jwt'`** — deliberately, so a route can only become unauthenticated
  via an explicit `'none'` (`migrations/0004_auth_policy.sql:9`, `osb/models.py:46`).
- `ext_authz` is **off** in every environment (`values.yaml:62-63`; no overlay sets it).
- The reconciler **refuses to publish any snapshot** when a route wants auth while ext_authz is off
  (`internal/xds/reconciler.go:261-267`) — correct on its own: an identity-bearing listener must
  never serve open.

Compose them: **a normally-provisioned service makes the control plane publish nothing at all.**
Envoy holds its last-good snapshot, or on first boot has none.

This is not theoretical. The local standup works around it by seeding routes with `auth_policy='none'`
and marking it **"MANDATORY"** (`deploy/local/up.sh:460-464`, `deploy/local/README.md:90-91`). **That
workaround exists only in the local scripts** — nothing in the OSB provisioning path, the charts, or
the prod overlays applies it.

Nothing here has been changed to "fix" this, because every available fix moves a default that governs
a security control, and this repo is parked. It is flagged, not fixed. Whoever revives this must
decide deliberately:

- keep `'jwt'` as the default and arm `ext_authz` **first**, so the guard never fires; **or**
- add an explicit "serve open" kill-switch the reconciler honours ahead of the fail-close, so the
  open state is a deliberate, logged choice rather than an accident of defaults.

The same contradiction is what makes rollback a fleet-wide database mutation — see
[docs/ext-authz-cutover-and-rollback.md](docs/ext-authz-cutover-and-rollback.md).

---

## Reviving it

Ordered, because the order matters:

1. **Bump the control-plane image and verify the binary reads the flag.**
   `values.yaml:5` pins `447ceb18` — a **2026-05-20** build, **120 commits behind `main`**, whose
   source has **no `ExtAuthz` config fields at all**. Nothing automates this bump. Flipping ext_authz
   against this pin sets an env var the binary ignores: ArgoCD reports success and **the gateway stays
   open and unauthenticated**. See the runbook — this is the sharpest trap in the repo.
2. **Enable the Admin READ API** (`adminApi.existingSecret`). It is off everywhere, so today there is
   no way to observe what the control plane actually believes. Turning auth on with no observability
   is not a cutover.
3. **Decide the `auth_policy` question** above, before provisioning anything.
4. **Then** work the cutover prereqs and rollback in
   [docs/ext-authz-cutover-and-rollback.md](docs/ext-authz-cutover-and-rollback.md).

Standing the stack up at all is a Kubernetes adoption, not a service addition: kind/k8s with the
default CNI replaced by **Calico** (which must be `CrossSubnet`, or SEC-3's node-CIDR ipBlock drops
the gateway), **cert-manager**, **Kyverno** (installed server-side), **Postgres**, **NATS**, **seven
Helm charts**, and **ArgoCD** for the GitOps model the deploy tree assumes. The local standup is 9
phases and ~1090 lines (`deploy/local/up.sh`), and wants 6–8 GiB and host ports 80/443. Budget a week
to "it runs" and longer to "I trust it".

Also unfinished: **`edge-secrets` has a Helm chart but no ArgoCD application**, so it is not in the
GitOps deploy at all.

### What it buys you

Per-service edge authentication (JWT/mTLS) with fail-closed enforcement and trusted identity-header
injection; per-route rate limiting keyed on identity; tenant isolation enforced at admission (Kyverno)
and in the data plane (Calico); an internal PKI with automated rotation; and OSB-driven multi-tenant
service provisioning.

**What it does not buy you today:** TLS termination, API authentication, rate limiting, spend caps and
metering all already exist in Lens and Caddy. For a single tenant the marginal security gain is close
to zero. The value appears with many mutually-untrusting tenants needing edge-enforced identity, or a
self-host lane where the customer runs the data plane.

---

## CI

CI is deliberately kept running while parked — it is the only thing preventing decay (pinned upstream
manifests, Kubernetes API deprecations, dependency CVEs).

| Workflow | Gate |
|---|---|
| `test.yaml` | `go test ./...`, Rust `cargo test --locked`, real-Envoy xDS TLS integration |
| `osb-test.yaml` | OSB Python suite; DB-backed cross-language E2E, secrets custodian, admin read API, migration-safety, co-location |
| `issuer-test.yaml` | issuer suite against a real DB |
| `deploy-test.yaml` | Helm lint + xDS mTLS render proof for base and every overlay |
| `policy-test.yaml` | Kyverno policy tests |

### Integration tests are opted into CI by name — and that is guarded now

Build-tagged tests are invisible to `go test ./...`, so each is named explicitly in a workflow with a
`-run` filter. That is opt-in **by name**: a new integration test whose name does not match an
existing prefix compiles, is reviewed, and then silently never runs.

This repo lost that bet twice — `internal/migrate`'s four schema-safety tests were executed by no
workflow, and `TestVerifyColocation` was matched by neither `-run` filter aimed at its package. That
last one is the invariant `cmd/server/admin.go:22-23` cites as the reason the Admin API may share the
control-plane process: **a justification resting on a test that had never run.**

`internal/ciguard` now fails the build if it recurs. It enumerates every integration-tagged test and
every workflow invocation and reports any test no invocation would reach — and, in reverse, any
invocation matching no test. It is untagged, so it runs in the ordinary `go test ./...` gate.

Because `go test` exits **0** on a skip, and several of these suites skip themselves when their DSN is
unset, the workflow steps additionally reject `--- SKIP` output. *Wired into CI* and *actually
executed* are different claims; both are now checked.

`test/integration/run.sh` is a local convenience harness (`make test-integration`) and is **not** run
by CI; `osb-test.yaml` covers the same ground.

---

## Layout

| Path | What |
|---|---|
| `cmd/server` | xDS control plane; health, metrics and the read-only Admin API listeners |
| `cmd/issuer`, `internal/issuer` | token issuer — login, RS256 minting, JWKS |
| `auth-service/` | Rust `ext_authz` gRPC authorizer |
| `osb/` | Open Service Broker: provisioning API, worker, translator |
| `internal/xds` | reconciler, snapshot versioning, fail-static guards, builders |
| `internal/store`, `internal/migrate`, `migrations/` | Postgres store, migration runner, schemas |
| `deploy/helm`, `deploy/envs`, `deploy/argocd` | charts, per-environment overlays, GitOps applications |
| `deploy/local` | scripted kind standup (9 phases) and the security proofs |
| `k8s/policies`, `k8s/certs` | Kyverno policies (GitOps-managed); cert-manager Certificates (**not** GitOps-managed) |

---

## License

[Business Source License 1.1](LICENSE) (BUSL-1.1). **Not an open-source licence today.**

You may read, modify and self-host Talyvor Edge Infrastructure, including in production, for your own
organisation's purposes. You may **not** offer Talyvor Edge Infrastructure to third parties as a hosted or
managed service. See the `Additional Use Grant` in [LICENSE](LICENSE) for the exact boundary,
and the `Change Date`, on which this converts to Apache License 2.0.
