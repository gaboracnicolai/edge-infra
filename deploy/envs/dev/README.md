# Dev / single-node environment (F9)

The default ArgoCD Applications in `deploy/argocd/applications/` hardcode the
`envs/prod/eu-west-1` overlay (3 replicas + pod anti-affinity across 3 nodes), so
the stack cannot be stood up on a single node via its own GitOps. This directory
plus `deploy/argocd/applications-dev/` provide a single-node lane.

## What differs from prod
- **1 replica**, **no anti-affinity** (`affinity: {}`) — fits one node.
- **`imagePullSecrets: [{name: ghcr}]`** wired via chart values (create the secret
  once: `kubectl -n <ns> create secret docker-registry ghcr --docker-server=ghcr.io
  --docker-username=<user> --docker-password=<token>`), so no manual `kubectl patch sa`.

## Prerequisites the overlay can't set (operator-provided)
- **cert-manager** installed, plus `k8s/certs/root-ca-bootstrap.yaml` + `cluster-issuer.yaml`
  applied (the root CA and issuer).
- **Postgres** + a DSN secret `edge-control-plane-postgres` (key `dsn`); for local dev use
  `sslmode=disable`. Prod uses `verify-full`.
- **NATS** for edge-osb.
- A **NetworkPolicy-enforcing CNI** (e.g. Calico) if you want the SEC-3 policies to be live —
  kind's default CNI does not enforce NetworkPolicy.

## Use
Point ArgoCD at `deploy/argocd/applications-dev/` instead of `applications/` (they carry the
same Application names, so use one set or the other, not both). Or install a chart directly:
`helm install edge-control-plane deploy/helm/edge-control-plane -n infra
  -f deploy/helm/edge-control-plane/values.yaml -f deploy/envs/dev/values-control-plane.yaml`.
