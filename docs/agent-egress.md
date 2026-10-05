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

## Keyless agents

A keyless destination takes no credential from the agent. The agent proves who
it is with its own ServiceAccount token, `edge-egress` removes every credential
it sent, and the request leaves with the gateway's signed assertion instead. A
provider key that leaks into an agent, or that someone plants there, never
reaches the provider.

Mark a destination keyless:

```sql
UPDATE egress_destinations SET keyless = true WHERE name = 'openai';
```

For that host:

- **Plain `http://` requests** go to the auth-service before they leave. The
  agent sends its ServiceAccount token as `Proxy-Authorization: Bearer <token>`.
  Without a valid one it gets `407` from `edge-egress`. With one, these are
  removed from the request: `Authorization`, `Proxy-Authorization`, cookies, any
  header whose name holds `api-key`, `apikey`, `access-key`, `subscription-key`,
  `token`, `secret`, `password`, `credential`, `signature` or `x-auth`, and URL
  parameters named the same way or `key` or `sig`. The auth-service then adds
  `x-gateway-auth`, an EdDSA assertion that lives 30 seconds, names this request
  (method, host, path as sent) and carries `amr: agent`, the ServiceAccount as
  `sub` (`system:serviceaccount:<namespace>:<name>`) and the cluster's issuer as
  `idp`. The upstream checks it against the key auth-service publishes at
  `/.well-known/transit-jwks.json` on its metrics port.
- **`CONNECT`** to the host gets `403`. Inside a tunnel the agent's own TLS would
  carry its credentials past the gateway unseen.

If ext_authz is off on the control plane, a keyless host answers `503`: nothing
could remove the agent's credentials, so the host is closed rather than open.

### The agent's token

Project a ServiceAccount token with the audience the auth-service expects for
your cluster's issuer, and send it from the file (the kubelet rotates it):

```yaml
volumes:
  - name: edge-token
    projected:
      sources:
        - serviceAccountToken: {audience: edge-egress, expirationSeconds: 600, path: token}
```

```bash
curl -x http://edge-egress.edge.svc.cluster.local:3128 \
  --proxy-header "Proxy-Authorization: Bearer $(cat /var/run/secrets/talyvor/token)" \
  http://api.openai.com/v1/models
```

### Trusting the cluster's issuer

Add the cluster's ServiceAccount issuer to `JWT_ISSUERS` in the
`auth-service-secrets` Secret, with the API server's CA for the key fetch:

```json
[{"issuer": "https://kubernetes.default.svc.cluster.local",
  "jwks_url": "https://kubernetes.default.svc.cluster.local/openid/v1/jwks",
  "audience": "edge-egress",
  "ca_file": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"}]
```

`issuer` must be what `kubectl get --raw /.well-known/openid-configuration`
reports. The API server serves its keys only to callers allowed to read them;
let anyone read them, as with any OIDC provider:

```bash
kubectl create clusterrolebinding edge-sa-issuer-discovery \
  --clusterrole=system:service-account-issuer-discovery --group=system:unauthenticated
```

`edge-egress` calls the auth-service with the same client certificate
`edge-proxy` uses (`envoy-authz-client-tls-secret`, mounted at
`/etc/authz-client-tls`, set by `extAuthz.clientTLS` on this chart).

`make kind-e2e` runs this as Phase 30. An agent in the locked namespace has a
provider key planted in its environment. Before the provider is keyless, the
provider echoes the key back. After, the key alone gets 407; with the agent's
token the call is served, the provider sees no key and no token, and the
assertion it receives names the agent and verifies with the published key.
CONNECT gets 403 and the direct call is dropped.

## What this does not do yet

Wallet rules, approvals and metering are not applied here yet.
