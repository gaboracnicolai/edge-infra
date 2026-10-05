# The egress gateway for agents

`edge-egress` is the way out of your cluster for your agents. It is an Envoy
Deployment the agents use as their proxy, and it reaches only the outside hosts
you list in the `egress_destinations` table. Any other host gets a 403 from it.

`make kind-e2e` runs it (Phase 28 of `deploy/local/up.sh`). An agent calls a
mock TLS provider: directly it gets no answer, and through `edge-egress` it is
served. A host not on the list is refused, and so is a listed host whose
certificate does not name it. To make `edge-egress` the only way out of a
namespace, see [Locking agents in](#locking-agents-in).

## Two ways through

Point the agent at it with the usual proxy variables:

    http_proxy=http://edge-egress.edge.svc.cluster.local:3128
    https_proxy=http://edge-egress.edge.svc.cluster.local:3128

- **`https://` URLs** go as `CONNECT host:port`. `edge-egress` opens a TCP tunnel
  to the host, and the agent's own TLS runs through it end to end. The port must
  be the one in the host's row.
- **`http://` URLs** go as plain HTTP to `edge-egress`, which opens the TLS
  connection to the host itself. It sends the host as SNI and accepts the
  server only if its certificate names the host and chains to the CA you gave.
  The agent never handles the provider's TLS, which is what lets later steps
  change the request on its way out.

Either way, a host with no row gets `403 edge-egress: destination not allowed`.

## Listing a destination

One row per host:

```sql
INSERT INTO egress_destinations (id, name, host, port, ca_secret_name)
VALUES ('openai', 'openai', 'api.openai.com', 443, NULL);
```

| Column | Meaning |
|---|---|
| `name` | Lower case, letters, digits and `-`. Names the host's clusters (`egress_<name>`, `egress_<name>_tunnel`). |
| `host` | The DNS name, lower case, with no port and no wildcard. One row per host. |
| `port` | The host's TLS port. Default 443. |
| `ca_secret_name` | A `validation_context` secret (written through `edge-secrets`) that the host's certificate must chain to. Empty means the system trust store in the Envoy image, which is right for a public provider. |
| `connect_timeout_ms` | Default 5000. |

The control plane picks a change up on its next reconcile, within a few seconds.
Removing a row closes that host.

`edge-egress` is sent only the CA bundles its rows name and never a private key.
It receives no gateway listener or route either. The control plane recognises it
by its xDS node id, `edge-egress/<pod name>`, which the chart sets.

## Install

In the namespace where `edge-proxy` runs. It uses the same xDS client
certificate, and the control plane's NetworkPolicy admits xDS from there:

```bash
helm upgrade --install edge-egress deploy/helm/edge-egress -n edge
```

The proxy port is 3128. To change it, set `proxy.port` on this chart and
`EGRESS_LISTENER_PORT` on the control plane to the same value.

## Locking agents in

Without a lock, an agent can skip `edge-egress` and call a provider directly.
The Kyverno policy `k8s/policies/agent-egress-lockdown.yaml` closes that. Apply
it once:

```bash
kubectl apply -f k8s/policies/agent-egress-lockdown.yaml
```

then label each namespace your agents run in:

```bash
kubectl label namespace <agents-namespace> talyvor.io/agents=true
```

Kyverno writes a NetworkPolicy named `agent-egress-lockdown` into that
namespace. Its pods can then send traffic to two places: cluster DNS
(`kube-dns`, port 53), and `edge-egress` in the `edge` namespace on port 3128.
Every other connection they open is dropped, so a direct call to a provider
times out and the same call through `edge-egress` is served. Ingress to the
namespace is not changed.

Kyverno keeps the NetworkPolicy in place. If someone deletes or edits it, Kyverno
writes it back. A namespace that already exists is locked as soon as it gets the
label.

If you installed `edge-egress` in another namespace, or set a different
`proxy.port`, change the namespace name and the port in the policy to match.

NetworkPolicies add up: another policy in the namespace that allows more egress
opens that path again. Give agents no right to create NetworkPolicies in their
namespaces (they have none by default), and keep them off `hostNetwork`, which
NetworkPolicy does not cover.

`make kind-e2e` runs this as Phase 29. It removes the mock provider's own
NetworkPolicy, so the provider answers any pod, as a real one on the internet
does. An agent in a new namespace calls it directly and is served. Once the
namespace is labelled, the same call times out, and the same call through
`edge-egress` is served. When the lockdown NetworkPolicy is deleted, Kyverno
writes it back and the direct call is dropped again.

## What this does not do yet

Wallet rules, approvals and metering are not applied here yet.
