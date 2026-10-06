# No internet at run time

Once Talyvor Edge is installed, it needs no route to the internet. Every
service it runs boots, serves and refreshes its keys from inside your cluster:

| Service | What it reaches at run time |
|---|---|
| `edge-control-plane` | Postgres, NATS and the Envoys it configures, all in the cluster |
| `edge-issuer` | Postgres, in the cluster |
| `auth-service` | each trusted issuer's signing keys, from a URL in the cluster or a file in the pod (below) |
| `edge-osb` | Postgres and the control plane, in the cluster |
| `edge-proxy` (Envoy) | the control plane and the routes' backends, in the cluster |
| `edge-egress` | the control plane, and the outside hosts **you** list in `egress_destinations` |

Edge makes no call to Talyvor: nothing phones home, and the licence check
([licence.md](licence.md)) needs no network. The only outside names Edge ever looks up are the
`egress_destinations` rows you add for your agents.

Installing still needs the images: pull them from your own registry with
`--set global.imageRegistry=<registry>` on every chart
([self-host-supply-chain.md](self-host-supply-chain.md)).

## Trusting an identity provider outside the cluster

`auth-service` checks every token against the keys of the issuer it names. For
the `edge-issuer` and the cluster's ServiceAccount issuer those keys are served
inside the cluster. An IdP outside it (Okta, Entra ID, your own) publishes its
keys on the internet, so in a cluster with no route out, hold a copy of them in
a Secret instead:

```sh
# On a machine that can reach the IdP:
curl -s https://idp.corp.example/oauth2/v1/keys > corp.json
# In the cluster:
kubectl -n infra create secret generic idp-jwks --from-file=corp.json
```

Mount it into `auth-service`:

```sh
helm upgrade auth-service deploy/helm/auth-service -n infra --reuse-values \
  --set jwksFiles.existingSecret=idp-jwks
```

and point the IdP's `JWT_ISSUERS` entry at the file instead of a URL:

```json
[{"issuer": "https://idp.corp.example", "jwks_file": "/etc/auth-service/jwks/corp.json", "audience": "api://default"}]
```

An entry has `jwks_url` or `jwks_file`, never both. `auth-service` refuses to
start if the file is missing or is not a JWKS document.

**Rotating the IdP's keys is a Secret update.** `auth-service` re-reads the file
every `config.jwksRefreshSeconds` (default 300). Replace the Secret's contents
with the IdP's new key set, keeping the old key in it until the IdP has stopped
signing with it, and new tokens are accepted with no restart. A file that does
not parse keeps the last good keys and counts
`jwks_refresh_total{result="failure"}`.

## How it is proven

`make kind-e2e` Phase 32 (`phase32_no_internet` in `deploy/local/up.sh`) cuts
the kind cluster off and checks the stack still works:

1. On every node, every public address is made unreachable (two
   `unreachable` /1 routes; the private ranges still go via the gateway), so no
   pod, no node and no hostNetwork Envoy can send a packet to the internet.
   CoreDNS loses its upstream: a name outside the cluster gets NXDOMAIN, as from
   an internal resolver with no internet, and every query is logged.
2. Every Edge workload is restarted from cold and must become Ready.
3. `auth-service` must load all three issuers' keys from inside the cluster: the
   `edge-issuer`, the API server's ServiceAccount keys, and an outside IdP's keys
   from a Secret.
4. The OSB broker provisions a `jwt` service. Without a token it answers 401;
   with an `edge-issuer` token or the outside IdP's, 200.
5. The IdP's key is rotated by updating the Secret alone: the new key's token
   gets 200 and the old one's 401, and every key refresh since the cold start
   succeeded.
6. **The verdict:** CoreDNS logged no query for a name outside the cluster.
   A pod's resolver also tries each `cluster.local` name with the node's own
   search domain appended before the name as written; those are counted and
   shown apart, since they name nothing outside the cluster.
7. Two controls show the instruments work. A pod's lookup of `api.openai.com`
   shows up in the log as outside the cluster, and a pod's request to `1.1.1.1`
   finds no way out.

Then the routes and the Corefile are put back.
