# Sizing and high availability

What each part of Talyvor Edge asks the cluster for, and what keeps serving when a part fails. The
figures are the charts' defaults (`values.yaml`); every one is a value you can change.

## What it needs

An install as [the install guide](install.md) makes it, on a cluster with two workers:

| Part | Copies | CPU request (limit) each | Memory request (limit) each | Storage |
|---|---|---|---|---|
| `edge-proxy` — the gateway | one per worker | 500m (2) | 256Mi (1Gi) | |
| `edge-control-plane` | 2 | 200m (1) | 128Mi (512Mi) | |
| `auth-service` | 2 | 200m (1) | 64Mi (256Mi) | |
| `edge-issuer` | 2 | 100m (500m) | 64Mi (256Mi) | |
| `edge-osb` broker | 2 API + 1 worker | 100m (500m) | 128Mi (256Mi) | |
| `edge-secrets` | 2 | 50m (250m) | 32Mi (128Mi) | |
| Postgres (bundled) | 1 | 100m | 256Mi (1Gi) | 8Gi |
| Redis (bundled) | 1 | 50m | 64Mi (512Mi) | 1Gi |
| NATS (bundled) | 1 | 50m | 64Mi (512Mi) | 1Gi |
| **Total, two workers** | | **2.6 CPU** | **about 2 GiB** | **10Gi** |

Add cert-manager's own three pods, and a short-lived Job for each schema step at install and
upgrade. The optional parts, when you turn them on:

| Part | Copies | CPU request each | Memory request each |
|---|---|---|---|
| `edge-egress` — the gateway agents call out through | 2 | 100m | 128Mi |
| `edge-ratelimit` | 2 | 100m | 64Mi |
| `edge-observability` (Prometheus, Loki, Tempo, collector, Grafana) | 1 each | see its `values.yaml` | |

`make kind-install-guide` runs the whole install on one machine with 6 to 8 GiB given to Docker.

### What grows with traffic

- **The gateway** carries every request. It runs on every worker, so it grows with the workers you
  add. Raise `resources` on `edge-proxy` before you raise anything else.
- **`auth-service`** checks the token on every request to a route that needs one. Scale it with
  `autoscaling.enabled=true` and `autoscaling.maxReplicas` (it needs metrics-server); it scales on
  CPU, at 80% unless you set `autoscaling.targetCPUUtilizationPercentage`. The control plane,
  issuer, broker, custodian, egress gateway and rate limiter take the same three values.
- **The control plane, issuer, broker and custodian** do work when configuration changes or someone
  signs in, not per request. Two copies each is enough for most installs.
- **Postgres** holds routes, services, the egress decision log and the issuer's users. 8Gi is many
  thousands of routes; the decision log is what grows. Watch the volume.

## What keeps serving when a part fails

| When this is down | What happens |
|---|---|
| **The control plane** (every copy) | The gateway keeps serving the last configuration it received. Nothing new is published until a copy is back, and a new copy reports Ready only after its first publish. |
| **`auth-service`** | Routes that need a token answer **403**: the gateway fails closed, never open. Routes with `auth_policy: none` keep serving. |
| **The issuer** | Nobody can sign in or get a new token. Tokens already issued keep working until they expire (`config.tokenTTL`, one hour by default): `auth-service` keeps the issuer's keys it holds, and refreshes them every five minutes. |
| **Postgres** | The control plane cannot read changes, so it publishes nothing new, and the gateway keeps what it has. The broker cannot accept a change, and nobody can sign in. |
| **NATS** | The broker cannot accept a new service or a deletion. Everything already published keeps serving. |
| **`edge-secrets`** | Keys already delivered to the gateway keep serving. No key can be added or changed. |
| **A gateway node** | That node stops answering. Put your load balancer in front of every worker and health-check `http://<node>:9902/ready`, which answers only while that node's gateway is ready. |

The control plane also refuses to publish a configuration that would break what is serving — an
empty one, one that points at something missing, or two gateways colliding on a port — and keeps
the last good one instead. `make kind-e2e` shows the last two on a live gateway (phases 13 and 22).

## High availability

**As shipped:**

- Every service runs **two copies** with a PodDisruptionBudget of one, so a node drain or upgrade
  takes at most one copy away at a time. The exception is the broker's worker, which runs one copy
  for now: a second cannot share its queue. While it is down, changes wait in NATS and are applied
  when it is back.
- The **gateway runs on every worker**, and rolls 10% of the nodes at a time.
- The **control plane** asks to run its copies on different nodes.

**What you add for more:**

- **Your own datastores.** The bundled Postgres, Redis and NATS are **one copy each**: when one is
  down, the table above applies until it is back. For a highly available install, run a replicated
  Postgres (a managed service, or an operator such as CloudNativePG), Redis and a NATS cluster with
  JetStream, and point `edge-datastores` at them ([install § Your own datastores](install.md#your-own-datastores)).
  Everything else is unchanged.
- **More copies** of `auth-service` first, then the others: `replicaCount`, or autoscaling as above.
- **A load balancer** across the workers' ports 80 and 443, health-checking `:9902/ready`.

**Not yet in the charts:** apart from the control plane, the charts do not take an `affinity` or
topology spread value, so the scheduler decides where the two copies of each service go. Most
schedulers spread copies of one Deployment across nodes when they can, but nothing in the charts
requires it, and nothing spreads them across zones.
