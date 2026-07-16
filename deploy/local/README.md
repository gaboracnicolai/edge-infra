# Local standup (`deploy/local/`)

Reproducible, scripted standup of the **full edge-infra stack** on a local
[kind](https://kind.sigs.k8s.io/) cluster, ending at a **routable gateway serving
two tenant backends** with `ext_authz` **OFF**. This is the infra foundation the
security proofs build on.

Goal: `git clone → deploy/local/up.sh → a routed request per tenant`.

```bash
deploy/local/up.sh      # stand everything up (idempotent, re-runnable)
deploy/local/down.sh    # tear the cluster down
```

## Prerequisites (host toolchain)

`docker` (Docker Desktop with ≥ ~6–8 GiB free — this stack is heavy), `kind`,
`kubectl`, `helm` (v3+), `jq`, `openssl`, `go`, and a Rust toolchain (`cargo`)
for the auth-service image. `up.sh` checks for these and stops with a precise
message if one is missing.

Host ports **80** and **443** must be free — the routable worker publishes them.

## What `up.sh` does (phases)

Each phase is guarded and idempotent; a re-run resumes cleanly.

1. **Cluster + Calico** — creates a multi-node kind cluster with the **default CNI
   disabled** and installs **Calico** (kindnet does not enforce NetworkPolicy;
   Calico is mandatory for the SEC-3 enforcement proofs later).

_(Phases 2–9 are added incrementally as the standup is built out.)_

## Configuration

Everything is overridable via environment variables (see `lib.sh`): `CLUSTER_NAME`,
`INFRA_NS` (default `infra`), `IMAGE_TAG` (default `local`), and pinned dependency
versions `CALICO_VERSION`, `CERT_MANAGER_VERSION`, `KYVERNO_VERSION`.

## Files

| File | Purpose |
|------|---------|
| `lib.sh` | Shared config + helpers (sourced; no side effects). |
| `kind-config.yaml` | Multi-node kind cluster, default CNI disabled, publishes 80/443. |
| `up.sh` | Phase-by-phase standup orchestrator. |
| `down.sh` | Deletes the kind cluster. |
