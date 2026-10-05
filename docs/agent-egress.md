# The egress gateway for agents

`edge-egress` is the way out of your cluster for your agents. It is an Envoy
Deployment the agents use as their proxy, and it reaches only the outside hosts
you list in the `egress_destinations` table. Any other host gets a 403 from it.

`make kind-e2e` runs it (Phase 28 of `deploy/local/up.sh`). An agent calls a
mock TLS provider: directly it gets no answer, and through `edge-egress` it is
served. A host not on the list is refused, and so is a listed host whose
certificate does not name it.

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

## What this does not do yet

Nothing stops an agent from skipping `edge-egress` and calling a provider
directly. In Phase 28 the mock provider's own NetworkPolicy does that, but a
real provider is outside your cluster. Default-deny egress in agent namespaces
comes next. Wallet rules, approvals and metering are not applied here yet
either.
