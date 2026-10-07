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
  parameters named the same way or `key` or `sig` (percent-encoded names
  included). Identity headers only the gateway sets (`x-user-*`,
  `x-client-cert-subject`) are removed too. The auth-service then adds
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
reports. The API server serves its keys only to callers allowed to read them.
Either have auth-service fetch them as itself — add
`"token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"`, the
pod's own token, re-read on every fetch; Kubernetes lets every ServiceAccount
read the keys — or let anyone read them, as with any OIDC provider:

```bash
kubectl create clusterrolebinding edge-sa-issuer-discovery \
  --clusterrole=system:service-account-issuer-discovery --group=system:unauthenticated
```

The same entry with `"audience": "edge-gateway"` (the gateway's
`JWT_AUDIENCE`) lets an agent call a jwt route on the gateway with a token
projected for that audience; `make kind-e2e` runs it as Phase 36.

`edge-egress` calls the auth-service with the same client certificate
`edge-proxy` uses (`envoy-authz-client-tls-secret`, mounted at
`/etc/authz-client-tls`, set by `extAuthz.clientTLS` on this chart).

`make kind-e2e` runs this as Phase 30. An agent in the locked namespace has a
provider key planted in its environment. Before the provider is keyless, the
provider echoes the key back. After, the key alone gets 407; with the agent's
token the call is served, the provider sees no key and no token, and the
assertion it receives names the agent and verifies with the published key.
CONNECT gets 403 and the direct call is dropped.

## Rate limits per agent

Each agent can be held to a number of requests a minute through `edge-egress`.
Set it on the control-plane chart (the default, `0`, is no limit):

```bash
helm upgrade edge-control-plane deploy/helm/edge-control-plane -n infra --reuse-values \
  --set egress.agentRequestsPerMinute=60
```

Every request counts against two buckets, and gets `429` when either is empty:

- **the agent's**: the ServiceAccount it proved with its token on a keyless
  destination. All of an agent's pods share it.
- **its pod's**: the address its connection comes from, never one it claims in
  `X-Forwarded-For`. This is what limits an agent on a destination that is not
  keyless, and on CONNECT, where it proves no identity.

Each bucket holds the limit and is refilled to it once a minute. A refused
request gets `Retry-After: 60` and `X-RateLimit-Limit`, `X-RateLimit-Remaining`
and `X-RateLimit-Reset`. A request `edge-egress` refuses for another reason (an
unlisted host, a missing token) is refused before it is counted.

Each `edge-egress` Envoy counts on its own, so with N replicas an agent can send
up to N times the limit. One Envoy keeps buckets for 4096 agents and as many pod
addresses; past that, the one seen least recently is dropped and starts full.

## The decision log

`edge-egress` writes one access-log line per request to its stdout, as every
Envoy here does. On `edge-egress` it also names the agent — `agent`, the
ServiceAccount, or `null` when it proved none — and `response_flags` tells the
decision: `RL` for the agent's rate limit, `UAEX` for a refused token, `-` for a
request sent on.

Every decision is also kept in the control plane's decision log, the
`edge_decisions` table: one record per request `edge-egress` sent on (`allowed`,
whatever the destination answered), refused (`denied`) or refused for the rate
limit (`rate_limited`). The Envoys send them to the control plane over the mTLS
connection they already use for their configuration, once a second, and the
control plane appends them in the order it receives them. It is on by default;
`egress.decisionLog=false` on the control-plane chart turns it off.

Each record names the hash of the record before it:

```json
{"seq":42,"prev":"9f2c…","time":"2026-10-06T09:14:03.118Z","node":"edge-egress/edge-egress-7d9…","agent":"system:serviceaccount:agents:billing-bot","client":"10.244.1.7","decision":"rate_limited","status":429,"reason":"local_rate_limited","method":"GET","authority":"api.openai.com","path":"/v1/models","destination":"openai","request_id":"1ad6…"}
```

`prev` is the sha256 of the previous line, exactly as exported (64 zeros for the
first record). Changing, removing or reordering a record breaks the link after
it. The path is recorded without its query string.

### Exporting and checking it

The control plane's admin API serves the log as NDJSON. Turn the admin API on
with a Secret holding its key:

```bash
kubectl -n infra create secret generic edge-cp-admin --from-literal=admin-api-key="$(openssl rand -hex 24)"
helm upgrade edge-control-plane deploy/helm/edge-control-plane -n infra --reuse-values \
  --set adminApi.existingSecret=edge-cp-admin
```

then export it and check every link:

```bash
kubectl -n infra port-forward deploy/edge-control-plane 18002 &
curl -s -H "X-Admin-Key: $KEY" http://127.0.0.1:18002/admin/v1/decisions > decisions.ndjson
scripts/verify-decisions.sh decisions.ndjson
# verified: 1873 records, seq 1..1873, chained to 0000…0000, head 5be1…
```

`?after=<seq>` exports only the records after that one; the first line it
returns names record `<seq>`'s hash as its prev. Keep the `head` the check
prints. A later export that verifies and still holds a line with that hash shows
that nothing up to it has changed.

What the log cannot show: a decision an Envoy could not deliver — the control
plane was unreachable for longer than Envoy buffers — was never written, so it is
missing without a broken link.

`make kind-e2e` runs this as Phase 31. With a limit of 5 a minute, one agent's
burst is served 5 times and then gets 429, the same agent from a second pod
gets 429 at once, and another agent is served. The exported log holds those
decisions, `scripts/verify-decisions.sh` verifies it, and it stops verifying
when one `rate_limited` record is rewritten as `allowed`.

## What this does not do yet

Wallet rules, approvals and metering are not applied here yet.
