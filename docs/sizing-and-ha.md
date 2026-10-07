# Sizing and high availability

What each part of Talyvor Edge asks the cluster for, and what keeps serving when a part fails. The
copies are the profile's ([install § Choose a profile](install.md#choose-a-profile)); the rest are
the charts' defaults (`values.yaml`). Every one is a value you can change.

## What it needs

An install as [the install guide](install.md) makes it, `lite` on one node and `ha` on two workers
(`airgap` is the same as `ha`):

| Part | Copies, `lite` | Copies, `ha` | CPU request (limit) each | Memory request (limit) each | Storage |
|---|---|---|---|---|---|
| `edge-proxy` — the gateway | one per node | one per worker | 500m (2) | 256Mi (1Gi) | |
| `edge-control-plane` | 1 | 3 | 200m (1) | 128Mi (512Mi) | |
| `auth-service` | 1 | 3 | 200m (1) | 64Mi (256Mi) | |
| `edge-issuer` | 1 | 2 | 100m (500m) | 64Mi (256Mi) | |
| `edge-osb` broker | 1 API + 1 worker | 3 API + 1 worker | 100m (500m) | 128Mi (256Mi) | |
| `edge-secrets` | 1 | 2 | 50m (250m) | 32Mi (128Mi) | |
| Postgres (bundled) | 1 | 1 | 100m | 256Mi (1Gi) | 8Gi |
| Redis (bundled) | 1 | 1 | 50m | 64Mi (512Mi) | 1Gi |
| NATS (bundled) | 1 | 1 | 50m | 64Mi (512Mi) | 1Gi |
| **Total** | **1.5 CPU, about 1.2 GiB** | **3.1 CPU, about 2.1 GiB** | | | **10Gi** |

Each worker you add to an `ha` install adds one gateway.

Add cert-manager's own three pods, and a short-lived Job for each schema step at install and
upgrade. The optional parts, when you turn them on:

| Part | Copies | CPU request each | Memory request each |
|---|---|---|---|
| `edge-egress` — the gateway agents call out through | 2 (1 in `lite`) | 100m | 128Mi |
| `edge-ratelimit` | 2 (1 in `lite`) | 100m | 64Mi |
| `edge-observability` (Prometheus, Loki, Tempo, collector, Grafana) | 1 each | see its `values.yaml` | |

`make kind-install-guide` runs the whole install, `ha` profile, on one machine with 6 to 8 GiB
given to Docker.

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

**With the `ha` profile** (and `airgap`):

- The control plane, `auth-service` and the broker's API run **three copies**; the issuer,
  `edge-secrets`, the egress gateway and the rate limiter **two**. Each has a PodDisruptionBudget of
  one, so a node drain or upgrade takes at most one copy away at a time. The exception is the
  broker's worker, which runs one copy for now: a second cannot share its queue. While it is down,
  changes wait in NATS and are applied when it is back.
- **The copies are spread.** No node holds more than one copy of a service more than any other, so
  losing a node loses at most one copy of each. A copy that cannot be placed without breaking that
  waits, Pending, rather than doubling up. Where your nodes carry a `topology.kubernetes.io/zone`
  label, the copies spread across zones as well, as far as the nodes allow.
- The rate limiter's copies share their counts through the `edge-datastores` Redis.
- The **gateway runs on every worker**, and rolls 10% of the nodes at a time.

**With `lite`,** every service runs one copy: a restart or a node drain takes it away until it is
back, and the table above applies meanwhile.

**What you add for more:**

- **Your own datastores.** The bundled Postgres, Redis and NATS are **one copy each**: when one is
  down, the table above applies until it is back. For a highly available install, run a replicated
  Postgres (a managed service, or an operator such as CloudNativePG), Redis and a NATS cluster with
  JetStream, and point `edge-datastores` at them ([install § Your own datastores](install.md#your-own-datastores)).
  Everything else is unchanged.
- **More copies** of `auth-service` first, then the others: `replicaCount`, or autoscaling as above.
- **A load balancer** across the workers' ports 80 and 443, health-checking `:9902/ready`.

**Your own spread:** every chart with a Deployment takes `topologySpreadConstraints` (the
broker's under `api`), written as Kubernetes takes them; `deploy/profiles/ha` shows how. The
control plane also takes `affinity`.
