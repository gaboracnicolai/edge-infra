# SEC-3 prod preflight — will the gateway-allow work, or drop my own gateway?

SEC-3 (`k8s/policies/backend-network-policies.yaml`) isolates a backend namespace
with `default-deny-ingress` plus an `allow-from-gateway` NetworkPolicy. The whole
design turns on **one precondition**. This doc states it plainly, records exactly
what the local kind run did and did **not** prove, and explains why SEC-3 stays
out of ArgoCD until [`scripts/sec3-preflight.sh`](../scripts/sec3-preflight.sh)
passes on the target cluster.

## The precondition

The `allow-from-gateway` policy's only gateway rule is an **`ipBlock` of the node
CIDR**, not a `podSelector`:

```yaml
ingress:
  - from:
      - ipBlock: { cidr: <NODE_CIDR> }   # the nodes running edge-proxy
    ports:
      - { protocol: TCP, port: <backend container port> }
```

Why an `ipBlock` and not "allow from the gateway pod": the gateway (`edge-proxy`,
namespace `edge`) is a **`hostNetwork: true` DaemonSet**. Its traffic to a backend
leaves the node's host network namespace, so the source the backend sees should be
a **node IP**, not the Envoy pod IP. A `podSelector` never matches; the node-CIDR
`ipBlock` is the only allow that can. (Same caveat as
[`docs/clusterip-guarantee.md`](./clusterip-guarantee.md) §2.)

**That holds only if the cluster's CNI/topology preserves the node IP as source.**
It does not, in two cases:

1. **Encapsulating overlay across nodes.** With IPIP/VXLAN `Always` (or Calico
   `CrossSubnet` **when nodes span multiple subnets**, or flannel's default vxlan,
   or a Cilium tunnel), cross-node traffic is tunnelled and the source is rewritten
   to a **tunnel/pod IP**. That is *not* in `<NODE_CIDR>` → the allow does not match.
2. **Nodes span multiple subnets.** A single `<NODE_CIDR>` `ipBlock` cannot cover
   node IPs from more than one subnet, so some gateway nodes fall outside it.

In either case `default-deny-ingress` then drops the gateway's own traffic:
**SEC-3 becomes a self-inflicted backend outage.** The failure is silent until you
apply it, which is exactly why this is gated behind a preflight.

## What the local kind proof did — and did NOT — prove

`deploy/local/up.sh` phase 11 proves SEC-3 end-to-end **on kind**: with the
resolved policy applied (`ipBlock` = the kind docker-network CIDR, port = the real
backend port), the pod-network attacker is dropped while the gateway path stays
`200`. But it only proves it **because the local topology satisfies the
precondition** — and it had to be forced to:

- kind's nodes share **one** docker subnet, and
- `up.sh` patches Calico to **`ipipMode=CrossSubnet`** before any workload
  (`deploy/local/up.sh`, the `install_calico` step). With the default
  `ipipMode=Always`, cross-node hostNetwork traffic egresses via `tunl0` and takes
  the **pod-CIDR** tunnel IP as source — which would *not* match a node-CIDR
  `ipBlock`, and SEC-3 would drop the gateway even on kind.

So the kind run proves **the policy is correct when the node IP is preserved**. It
does **not** prove anything about a real target cluster, whose CNI, encapsulation
mode, and node subnet layout are unknown. A production cluster with
`ipipMode=Always`, a multi-subnet node pool, flannel-vxlan, or a Cilium tunnel
would **fail the precondition** and drop its own gateway.

## The preflight

Run [`scripts/sec3-preflight.sh`](../scripts/sec3-preflight.sh) against the target
cluster **before** enabling SEC-3. It is **strictly read-only** (`kubectl
get/describe`, and an exec-to-`curl` from an existing pod where possible) — it
never applies, patches, or deletes anything.

```
scripts/sec3-preflight.sh [--context KUBE_CONTEXT] [--backend-namespace NS] [--node-cidr CIDR]
```

It reports, and decides from:

- node `InternalIP`s and whether they fall in **one** subnet or several;
- the CNI, and for Calico the IPPool **`ipipMode`/`vxlanMode`** (encapsulation);
- the pod CIDR (to recognise a pod/tunnel source if it appears);
- whether `edge-proxy` is `hostNetwork` and that its node IPs sit inside the
  candidate `<NODE_CIDR>`;
- the **real backend container port** SEC-3 must allow — the template hard-codes
  `8080`, which is almost never right (pass `--backend-namespace` to surface it);
- **the decisive empirical check where it can run read-only:** the source IP a
  hostNetwork gateway presents to a *cross-node* header-reflecting backend. If no
  reflector/HTTP-client is reachable read-only, it prints a clearly-labelled
  **MANUAL VERIFICATION** step instead of guessing.

Verdict and exit code (so a cutover can gate on it):

| Exit | Verdict | Meaning |
|------|---------|---------|
| `0`  | PASS | node IP preserved → the `ipBlock` will match the gateway |
| `1`  | FAIL | encapsulated and/or multi-subnet → SEC-3 would drop the gateway |
| `2`  | INCONCLUSIVE | could not determine read-only → do the MANUAL VERIFICATION first |

A topology that is deterministically sound (e.g. Calico `CrossSubnet` + a single
node subnet — the kind case) reports **PASS** even when the empirical probe cannot
run read-only; it also prints the manual step so you can confirm.

## Until it passes: SEC-3 stays out of ArgoCD

The ArgoCD `edge-policies` Application syncs **only** the cluster admission policy
and explicitly excludes the NetworkPolicy template
(`deploy/argocd/applications/edge-policies.yaml`: `exclude:
backend-network-policies.yaml`, mirrored in `applications-dev/`). Leave it that
way. SEC-3 must not be added to GitOps sync for a target cluster until
`scripts/sec3-preflight.sh` returns **PASS** there — otherwise ArgoCD would
faithfully roll out a policy that drops the gateway.
