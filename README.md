<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/talyvor-logo-dark-notag.svg">
    <img alt="Talyvor" src="docs/brand/talyvor-logo-light-notag.svg" width="360">
  </picture>
</p>

<p align="center">Talyvor — money and markets for AI agents.</p>

# Talyvor Edge

**The agent firewall and wallet-enforcement point, running in your own cluster.**

Talyvor gives every AI agent a wallet: a budget, spending rules, approvals, a card and a live
statement. Lens enforces those rules before the agent's model call or payment. Talyvor Edge makes
the rules unbypassable inside a customer's own cluster. Every request an agent sends goes out through
a gateway the customer runs, and that gateway refuses any request the agent's identity is not
allowed to make.

This repository is Talyvor Edge: the Envoy xDS control plane, the Rust `ext_authz` auth-service,
the Open Service Broker (OSB), and the token issuer for a multi-tenant edge.

---

## Status: kind-only today

**Talyvor Edge runs end to end on a kind cluster and nowhere else yet.** `make kind-e2e` creates a
cluster on your machine, installs all seven charts and sends requests through Envoy and `ext_authz`
to stub upstreams. It then has the OSB broker provision a route that Envoy serves, and deletes the
cluster at the end. CI runs it whenever a chart changes, and `make kind-cutover` and
`make kind-rollback` rehearse the launch-day steps the same way.

It is not deployed to any real cluster or cloud account, and nothing in the hosted product depends on
it. The live stack is docker-compose: `lens`, `postgres`, `redis`, `nats`, `pgbouncer`, `caddy`,
`autoheal`.

**Which self-host claims are proven, and which are not:
[docs/self-host-claims.md](docs/self-host-claims.md).** It maps every self-hosting claim on the
landing page to the `make kind-e2e` phase that runs it. The gateway, identity, isolation and
provisioning claims run. The Lens-side claims are marked **not run**, because no chart here installs
Lens yet: provider keys, spend records, budgets that block at the limit, the ledger, and the audit
export. **Wallet enforcement at the edge is therefore not yet exercised in a running cluster.** The
self-host extras have their own pages: per-node TLS keys, NetworkPolicies, SCIM and OIDC sign-in are
in [docs/self-host-network-and-identity.md](docs/self-host-network-and-identity.md), and the
confidential-node option is in
[docs/self-host-confidential-compute.md](docs/self-host-confidential-compute.md).
Every image is signed and carries an SBOM and SLSA provenance. To check all three before you install,
run `make verify-images TAG=<release>` or see
[docs/self-host-supply-chain.md](docs/self-host-supply-chain.md). Nothing is signed if trivy finds a
fixable HIGH or CRITICAL vulnerability in it (`make scan-images TAG=<release>`).

If you are here to run it on a real cluster, read [§ Taking it past kind](#taking-it-past-kind)
first. Several things that look ready are not.

### What is on, and where

| | |
|---|---|
| Deployed | **Only on kind**, in a cluster `make kind-e2e` creates and deletes. No real cluster, no ArgoCD instance in the serving path. |
| `ext_authz` (gateway authentication) | Built. **On by default** in the `edge-control-plane` chart, so in base and all four overlays, and in the kind run from install (Phase 25 proves a default `jwt` OSB service answers 401 / 200; Phase 12 switches it off and on live). |
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

**But for this repository, arming is most of the remaining distance.** Of the three headline
security controls, gateway authentication (`ext_authz`) is now **on by default**; identity-keyed rate
limiting and the admin API are still shipped **off**. A green register describes merged code, not
controls in force. Read it that way.

---

## The defaults publish safely now (B28.206)

Three decisions used to compose into a system that published nothing:

- `auth_policy` defaults to **`'jwt'`** — deliberately, so a route can only become unauthenticated
  via an explicit `'none'` (`migrations/0004_auth_policy.sql:9`, `osb/models.py:46`).
- `ext_authz` was **off** in every environment.
- The reconciler **refuses to publish any snapshot** when a route wants auth while ext_authz is off
  (`internal/xds/reconciler.go`, CFG-1) — correct on its own: an identity-bearing listener must
  never serve open.

So the first normally-provisioned service froze the whole gateway. `ext_authz` is now **on by
default** (`deploy/helm/edge-control-plane/values.yaml`, `extAuthz.enabled: true`), so the guard
does not fire: a `jwt` service is published and gated, answering 401 without a token and 200 with
one, and `none` routes keep serving without a token, even while the auth-service is down. `make
kind-e2e` Phase 25 provisions such a service through the OSB broker on the fresh install and checks
exactly that.

What on-by-default needs on the same install: the `auth-service` and `edge-issuer` charts, and the
`envoy-authz-client-tls-secret` that `edge-proxy` mounts (`k8s/certs/envoy-authz-client-cert.yaml`).
Turning ext_authz **off** again while a `jwt` route exists still freezes the fleet on last-good —
that is the guard working, and it is why rollback is a database mutation; see
[docs/ext-authz-cutover-and-rollback.md](docs/ext-authz-cutover-and-rollback.md).

---

## Taking it past kind

Ordered, because the order matters:

1. **Bump the control-plane image and verify the binary reads the flag.**
   `values.yaml:5` pins `447ceb18` — a **2026-05-20** build, **120 commits behind `main`**, whose
   source has **no `ExtAuthz` config fields at all**. Nothing automates this bump. Flipping ext_authz
   against this pin sets an env var the binary ignores: ArgoCD reports success and **the gateway stays
   open and unauthenticated**. See the runbook — this is the sharpest trap in the repo.
2. **Enable the Admin READ API** (`adminApi.existingSecret`). It is off everywhere, so today there is
   no way to observe what the control plane actually believes. Turning auth on with no observability
   is not a cutover.
3. **Install the auth-service, the issuer and the ext_authz client certificate** before
   provisioning anything — ext_authz is on by default, so `jwt` routes deny until they are up.
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

CI runs whether or not anything is deployed — it is the only thing preventing decay (pinned upstream
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
organisation's purposes without limit, and an integrator may run it for up to **three clients
at a time**, each on its own deployment. You may **not** run one deployment serving two or more
unrelated organisations. Beyond three concurrent client engagements, or for multi-tenant use,
that is a commercial licence rather than a refusal — `hello@talyvor.com`. See the `Additional Use Grant` in [LICENSE](LICENSE)
for the exact boundary, and the `Change Date`, on which this converts to Apache License 2.0.
