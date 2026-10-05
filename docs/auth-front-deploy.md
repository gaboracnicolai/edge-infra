# Deploying the gateway auth front

Brings up the issuer + auth-service + ClusterIP guarantee end to end. The
manifests are GitOps-managed (argocd); the **Secrets are created out of band**
(never committed). Nothing here has been applied to a cluster — this is the
runbook to do so.

## Prerequisites

- A cluster, with argocd installed (`make argocd-apply`) and the AppProject +
  Applications registered.
- **Kyverno installed** (the admission controller). Without it the
  `disallow-public-backend-services` ClusterPolicy is inert — the ClusterIP
  guarantee is **not enforced** until Kyverno is running and the `edge-policies`
  Application is synced.
- cert-manager with the `edge-internal-ca` ClusterIssuer (issues the issuer's
  serving cert via `k8s/certs/issuer-cert.yaml`).
- An external Postgres for the issuer (its **own** database, separate from the
  control-plane DB).

## ⚠️ Config-consistency invariant (read this first)

The issuer mints `iss`/`aud`; the auth-service validates them. **If they don't
match exactly, every token is rejected.** Keep these equal:

| auth-service (`auth-service-secrets`) | issuer (`issuer-secrets`) | must equal |
| --- | --- | --- |
| `JWT_ISSUER` | `ISSUER_URL` | the `iss` claim |
| `JWT_AUDIENCE` | `ISSUER_AUDIENCE` | the `aud` claim |
| `JWKS_URL` | — | the issuer's JWKS endpoint |

Canonical values used below (adjust per environment, but keep both sides equal):

```
ISSUER_URL       = https://edge-issuer.infra.svc.cluster.local:8081
ISSUER_AUDIENCE  = edge.gateway
JWKS_URL         = https://edge-issuer.infra.svc.cluster.local:8081/.well-known/jwks.json
JWKS_CA_FILE     = /etc/auth-tls/ca.crt   # set by the auth-service chart when TLS is configured
```

### More identity providers

The edge-issuer above is one provider. To also accept tokens from your own
IdP, or from the cluster's ServiceAccounts, add `JWT_ISSUERS` to
`auth-service-secrets` — a JSON array, one entry per provider:

```json
[
  {"issuer": "https://dev-1.okta.com/oauth2/default",
   "jwks_url": "https://dev-1.okta.com/oauth2/default/v1/keys",
   "audience": "api://default"},
  {"issuer": "https://oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLE",
   "jwks_url": "https://oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLE/keys"}
]
```

Each token is verified only with the keys of the issuer named in its `iss`, so
one provider's key can never vouch for another. Every listed provider can still
assert any `sub`, `email` and `teams`, so list only providers whose claims you
trust. The signed `x-gateway-auth` assertion carries the provider as `idp`, so
a backend can key identity on (idp, sub). `audience` defaults to
`JWT_AUDIENCE`; a token's `aud` may be a string (Okta) or an array
(ServiceAccount tokens). Every `jwks_url` must be https, and every JWKS must be
reachable when auth-service starts.

## 1. Provision the issuer database

Create an empty Postgres database and a user the issuer owns, e.g.
`postgres://issuer:<pw>@<host>:5432/issuer?sslmode=require`. Migrations run
automatically on deploy (Helm `pre-install`/`pre-upgrade` hook → `issuer
migrate`), so no manual schema step is needed.

## 2. Create the Secrets (out of band)

```sh
# Issuer config + DB DSN
kubectl -n infra create secret generic issuer-secrets \
  --from-literal=ISSUER_URL='https://edge-issuer.infra.svc.cluster.local:8081' \
  --from-literal=ISSUER_AUDIENCE='edge.gateway' \
  --from-literal=ISSUER_DATABASE_URL='postgres://issuer:<pw>@<host>:5432/issuer?sslmode=require'

# Signing key(s): one <kid>.pem per data entry. The kid here ("2026-06") must
# match config.activeKid in deploy/envs/.../values-issuer.yaml.
openssl genrsa -out 2026-06.pem 2048
kubectl -n infra create secret generic issuer-signing-keys --from-file=2026-06.pem

# Gateway transit-assertion signing key added to the auth-service Secret,
# plus point JWKS at the issuer and keep iss/aud consistent.
openssl genpkey -algorithm ed25519 -out transit.pem
kubectl -n infra patch secret auth-service-secrets --type merge -p "$(cat <<JSON
{"stringData":{
  "TRANSIT_SIGNING_KEY":$(jq -Rs . transit.pem),
  "JWKS_URL":"https://edge-issuer.infra.svc.cluster.local:8081/.well-known/jwks.json",
  "JWT_ISSUER":"https://edge-issuer.infra.svc.cluster.local:8081",
  "JWT_AUDIENCE":"edge.gateway"
}}
JSON
)"
```

> `x-gateway-auth` now carries a signed transit assertion, not a shared secret:
> an EdDSA JWT that names the request (`htm` method, `htu` host+path) and the
> identity (`sub`, `amr`, `email`, `teams`), expires in `TRANSIT_TTL_S` (30s)
> and carries a `jti` a backend accepts once. Backends verify it with the
> public key at `http://auth-service.infra:9090/.well-known/transit-jwks.json`;
> `auth_service::transit::TransitVerifier` is the reference verifier, and it
> refuses an expired, replayed, re-targeted or foreign-key assertion.

## 3. Deploy

```sh
kubectl apply -f deploy/argocd/applications/edge-issuer.yaml
kubectl apply -f deploy/argocd/applications/edge-policies.yaml
# argocd syncs the chart; the migrate Job runs before the Deployment.
```

## 4. Seed a user

```sh
kubectl -n infra exec deploy/edge-issuer -- \
  issuer adduser --email you@example.com --password '<pw>' --team eng
```

## 5. Preflight verification (before trusting the front)

```sh
# (a) auth-service can fetch the issuer JWKS over the internal CA
kubectl -n infra exec deploy/auth-service -- \
  sh -c 'wget -qO- --ca-certificate=/etc/auth-tls/ca.crt "$JWKS_URL"'

# (b) a minted token is accepted: log in, call a gateway-fronted route, expect 200
TOKEN=$(curl -sk https://edge-issuer.infra.svc.cluster.local:8081/login \
  -d '{"email":"you@example.com","password":"<pw>"}' | jq -r .access_token)
# decode and confirm iss/aud match auth-service config
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{iss,aud,sub,email,teams}'
```

Confirm `iss` == `JWT_ISSUER` and `aud` == `JWT_AUDIENCE`. If they differ, the
auth-service will 401 every request — fix the Secrets in step 2.

## Enforcement status

- **Issuer / identity headers / transit-proof:** live once steps 1–3 are applied.
- **ClusterIP guarantee:** enforced only once **Kyverno is installed** and the
  `edge-policies` Application is synced. Until then the policy exists in git but
  is not blocking anything. Verify with:
  `kubectl get clusterpolicy disallow-public-backend-services`.

## Key rotation

Add the next key to `issuer-signing-keys` (`<newkid>.pem`), wait one JWKS
refresh interval (so auth-service has fetched it via the JWKS endpoint), then
bump `config.activeKid` to `<newkid>` and sync. Remove the old key later.
