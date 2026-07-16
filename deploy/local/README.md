# Local standup (`deploy/local/`)

Reproducible, scripted standup of the **full edge-infra stack** on a local
[kind](https://kind.sigs.k8s.io/) cluster, ending at a **routable gateway serving
two tenant backends** with `ext_authz` **OFF**. This is the infra foundation the
security proofs build on.

```
git clone … && cd edge-infra
deploy/local/up.sh        # stand everything up (idempotent, re-runnable)
deploy/local/down.sh      # tear the cluster down
```

The end state: a request to the node's published **:443** for each tenant's host
reaches **that tenant's** backend.

```
curl -H 'Host: tenant-a.local' http://localhost:443/    # -> 200 TENANT-A-BACKEND
curl -H 'Host: tenant-b.local' http://localhost:443/    # -> 200 TENANT-B-BACKEND
curl -H 'Host: nope.local'     http://localhost:443/    # -> 404 (no route)
```

## Prerequisites (host toolchain)

`docker` (Docker Desktop, **≥ ~6–8 GiB** free — this stack is heavy: Calico +
cert-manager + Kyverno + Postgres + NATS + 7 app charts), `kind`, `kubectl`,
`helm` **v3+**, `jq`, `openssl`, `go`, and a Rust toolchain is **not** required on
the host (auth-service builds in-container). `up.sh` checks for the required
binaries and stops with a precise message if one is missing.

Host ports **80** and **443** must be free — a worker publishes them.

Dependency manifests (Calico, cert-manager, Kyverno) are fetched from pinned
upstream URLs at run time, so the first run needs network access.

## Usage

```bash
deploy/local/up.sh                    # all 9 phases, in order (idempotent)
deploy/local/up.sh phase8_seed        # re-run a single phase function
CLUSTER_NAME=foo deploy/local/up.sh   # override any knob (see lib.sh)
deploy/local/down.sh                  # delete the kind cluster
```

Re-running `up.sh` is safe: an existing cluster is reused, manifests re-apply as
no-ops, secrets/certs/PKI are not duplicated, and a prior stuck/failed helm
release is cleared before re-install.

## What it does (phases)

| # | Phase | Result |
|---|-------|--------|
| 1 | **Cluster + Calico** | Multi-node kind (1 cp + 2 workers), **default CNI disabled**, Calico installed (kindnet does not enforce NetworkPolicy). Sets `ipipMode=CrossSubnet` — kind nodes share one subnet, so native routing preserves the node IP as the source of the hostNetwork gateway (required for the SEC-3 gateway-allow; see adaptations). |
| 2 | **Cluster deps** | cert-manager + Kyverno (server-side apply; its CRDs exceed the client-side limit) + dev Postgres (shared `edge` DB + issuer's `issuer` DB) + NATS (JetStream). |
| 3 | **Images** | Builds **all 7** images (5 control-plane Go targets, edge-osb, auth-service in-container) and `kind load`s them. Extends `make docker-build-local` (which builds only 3). |
| 4 | **Data-plane PKI** | Applies `k8s/certs/*` in order (selfsigned root → `edge-internal-ca` ClusterIssuer → 7 leaves); waits for the 7 tls secrets. |
| 5 | **Admin PKI + secrets** | Runs `scripts/bootstrap-pki.sh` (admin CA, custodian cert, KEK) + issuer RSA signing key, and creates every app secret (DSNs `sslmode=disable`). |
| 6 | **Migrate** | Runs `edge-migrate` as a Job against the shared DB (both schema sets, idempotent). |
| 7 | **Deploy** | `helm upgrade --install` for all 7 charts with dev + local overlays, `--wait`, **extAuthz OFF**. Envoy connects to the control-plane over mTLS xDS. |
| 8 | **Seed** | Two tenant backends + the missing route source: a gateway on **:443** and a host-route per tenant (via direct SQL). |
| 9 | **Prove** | A request per tenant through the node **:443** hostPort → 200 from the correct backend. |
| 10 | **SEC-3 Property 1** (admission) | Applies the Kyverno guardrails (Enforce), then proves red-first: a NetworkPolicy allowing from an empty podSelector `{}` is **DENIED**; a NodePort backend Service is **DENIED**. |
| 11 | **SEC-3 Property 2** (data-plane) | A pod-network attacker (IP outside NODE_CIDR) reaches each backend's ClusterIP with no policy (RED), then — after the resolved backend policy — is **dropped** while the node-`:443` gateway path stays **200** (two separate assertions). |

## Topology

Two edge-infra namespaces (plus `tenant-a` / `tenant-b` for the backends):

- **`infra`** — edge-control-plane, edge-issuer, auth-service, edge-osb,
  edge-ratelimit, edge-secrets + the dev datastores (postgres, nats). Services
  address each other at `*.infra.svc.cluster.local`.
- **`edge`** — edge-proxy only. Its three envoy certs are issued in `edge`, and a
  pod can mount secrets only from its own namespace, so the proxy runs here and
  dials the control-plane at `…infra.svc…`. It's a **DaemonSet** with
  `hostNetwork` + hostPort 80/443; the routable worker publishes those to the host.

## Local adaptations (why the overlays exist)

The charts target a GitOps (ArgoCD) deploy; a few things need dev-overlay **values**
(never template changes) for a raw local `helm install`:

- **ServiceAccount for hooks** (control-plane, issuer): the pre-install migrate
  **hook** references the chart SA, which is a regular post-hook resource — so
  under `helm install` the hook runs before the SA exists and `FailedCreate`s.
  The overlays point both at the `default` SA (they need no special RBAC).
- **edge-osb TLS off**: the chart forces `verify-full` Postgres TLS + mutual NATS
  TLS whenever `tls` is set; the dev datastores are plaintext. `tls: null` removes
  the block; `DB_SSL_MODE=disable` comes via the secret.
- **auth_policy=none on seeded routes**: the xDS reconciler is **fail-closed** — it
  withholds the entire snapshot if any route wants auth while `ext_authz` is off.
- **:443 plaintext**: the seed gateway is protocol HTTP on port 443 (no TLS
  termination) so the routing proof is a clean plaintext request to the hostPort.
- **Calico `CrossSubnet`** (SEC-3): with the manifest default `ipipMode=Always`,
  cross-node hostNetwork traffic (the gateway) egresses via `tunl0` and takes the
  tunnel's pod-CIDR IP as source — which would NOT match a node-CIDR ipBlock allow,
  so the gateway would be dropped. kind nodes share one subnet, so `CrossSubnet`
  uses native routing and preserves the node IP as source.

## Configuration (env knobs, see `lib.sh`)

`CLUSTER_NAME` (default `edge-local`), `INFRA_NS` (`infra`), `IMAGE_TAG` (`local`),
`GATEWAY_HOST_PORT` (`443`), and pinned versions `CALICO_VERSION`,
`CERT_MANAGER_VERSION`, `KYVERNO_VERSION`, `KIND_NODE_IMAGE`.

## Files

| File | Purpose |
|------|---------|
| `lib.sh` | Shared config + helpers (sourced; no side effects). |
| `kind-config.yaml` | Multi-node cluster, default CNI disabled, publishes 80/443. |
| `up.sh` / `down.sh` | Phase-by-phase standup / teardown. |
| `manifests/` | namespaces, postgres, nats, migrate Job, tenant backends, SEC-3 attacker. |
| `values/` | Per-chart local overlays (images + the adaptations above). |
| `.pki-bootstrap/` | Generated admin PKI + KEK + signing key (gitignored). |

## SEC-3 live enforcement (phases 10-11)

Two properties, proven **red-first and separately**:

1. **Admission (Kyverno)** — the guardrails reject rules that would re-open the
   bypass/lateral-movement hole: a NetworkPolicy allowing from an empty
   podSelector `{}`, and a LoadBalancer/NodePort backend Service. The resolved
   ipBlock allow-from-gateway (no empty podSelector) is admitted.
2. **Data-plane (Calico)** — a compromised **pod-network** foothold (attacker pod,
   IP outside NODE_CIDR) can hit a backend's ClusterIP directly with no policy;
   after the backend policy it is dropped, while the gateway path stays 200.

### Honesty — the precision ceiling under hostNetwork

The gateway (edge-proxy) runs `hostNetwork`, so its traffic to a backend carries
the **node** IP, and the allow rule is therefore an `ipBlock` of the node CIDR.
This means the control **drops pod-network footholds** — a compromised app pod,
SSRF from a workload, a malicious sidecar (the realistic lateral-movement threat)
— but it does **not** make the gateway the only possible source: **any** hostNetwork
pod on a node would also match the node-CIDR allow. App-layer `x-gateway-auth`
(ext_authz, a later run) is the backstop for gateway *identity*. What is proven
here is exactly: pod-network → backend is dropped; node-network (the gateway) →
backend on the echo port is allowed.

`ext_authz` stays OFF this run — its cutover (the edge-proxy→auth-service mTLS leg)
is a separate run.
