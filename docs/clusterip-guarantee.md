# ClusterIP deployment guarantee

**Goal:** backends (Track, Lens, Docs, Code) are reachable **only through the
gateway**, never on a directly-routable port. This is the assumption the
transit-proof header (`x-gateway-auth`) rests on: the shared secret is only
meaningful if a caller cannot reach a backend without passing through the
gateway in the first place. If a backend port were publicly routable, an
attacker could skip the gateway and forge `x-user-id` / `x-user-email`.

The gateway itself (`edge-proxy`, namespace `edge`) is the one public surface:
it runs as a DaemonSet with `hostNetwork: true` binding node ports 80/443.
Everything else is ClusterIP.

## Two enforced layers

### 1. Admission policy — no public Service types

`k8s/policies/disallow-public-backend-services.yaml` is a Kyverno
`ClusterPolicy` (Enforce) that **denies any Service of type `LoadBalancer` or
`NodePort`** cluster-wide. A backend therefore cannot be made publicly routable
even by accident — the API server rejects the Service at admission.

Opt-out (rare, e.g. an external ingress controller): label the namespace
`talyvor.io/allow-public-services=true`.

This is verified offline in CI with the Kyverno CLI
(`.github/workflows/policy-test.yaml` runs `kyverno test k8s/policies/tests`):
a ClusterIP Service is admitted; LoadBalancer and NodePort Services are denied.

### 2. NetworkPolicy — backends accept ingress only from the gateway

`k8s/policies/backend-network-policies.yaml` is a per-namespace template:
a `default-deny-ingress` policy plus an `allow-from-gateway` policy.

> **hostNetwork caveat:** because `edge-proxy` uses `hostNetwork: true`, its
> traffic to a backend pod has the **node IP** as source, not the Envoy pod IP.
> A `podSelector`-based allow does **not** match it — the allow rule must use an
> `ipBlock` for the node CIDR. The template documents this; set `<NODE_CIDR>`
> per environment.

## Operator checklist (per backend namespace)

1. Ensure the admission policy is installed cluster-wide (Kyverno running).
2. Deploy the backend with a **ClusterIP** Service only.
3. **Run [`scripts/sec3-preflight.sh`](../scripts/sec3-preflight.sh) first** — it
   confirms the cluster preserves the node IP as source, so the `ipBlock` allow
   won't drop the gateway. See [`docs/sec3-preflight.md`](./sec3-preflight.md).
   Then apply `backend-network-policies.yaml` with `<backend-ns>` and `<NODE_CIDR>`
   filled in (and the real backend container port, not the template's `8080`).
4. Confirm the backend has no Ingress/Gateway resource exposing it outside the
   `edge-proxy` route table.

## Status / what this gives Nicolai

With both layers in place, a Track (or other backend) pod is unreachable except
via the gateway, so it can trust the gateway-injected identity headers behind
the `x-gateway-auth` check. The admission policy is the hard guarantee (enforced
at the API server, tested in CI); the NetworkPolicy is defense-in-depth.
