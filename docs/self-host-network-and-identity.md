# Self-host: network policy, SSO and SCIM

Three things a self-hosted install can switch on. `make kind-e2e` runs all three
(Phases 17 and 18 of `deploy/local/up.sh`).

## NetworkPolicy — default deny, only the flows the charts need

Each chart ships a NetworkPolicy, enforced by Calico (or any CNI that enforces
NetworkPolicy). When it is on, every connection to that chart's pods is dropped
except these:

| Chart | Allowed in | From |
|---|---|---|
| auth-service | ext_authz gRPC (`grpc`) | the gateway |
| edge-control-plane | xDS gRPC (`grpc`) | the gateway |
| edge-issuer | `https` (`/login`, `/sso`, `/scim/v2`, JWKS) | the gateway; the auth-service pods |
| edge-osb | broker API (`http`) | the gateway |
| edge-osb worker | nothing | — |
| edge-ratelimit | rate-limit gRPC (`grpc`) | the gateway |
| edge-secrets | nothing | — (operators use `kubectl port-forward`, which is not network traffic) |

"The gateway" is `networkPolicy.gatewayCIDRs`, plus the pods in
`networkPolicy.gatewayNamespace` (default `edge`). Envoy runs `hostNetwork`, so
its traffic carries the **node** IP, which no pod or namespace selector matches:
set `gatewayCIDRs` to the CIDR of the nodes running edge-proxy. Kubelet probes
always pass. edge-proxy itself has no policy — NetworkPolicy does not apply to a
`hostNetwork` pod.

It is off in the base values (ArgoCD syncs those, and a wrong CIDR would cut the
gateway off). Switch it on per chart in your overlay:

```yaml
networkPolicy:
  enabled: true
  gatewayCIDRs: ["10.0.0.0/16"]   # your node network; the chart will not render without it
  extraIngress:                   # optional: anything else that must reach this chart
    - from: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: monitoring}}}]
      ports: [{port: metrics}]
```

## SSO — sign in through your own OIDC identity provider

`edge-issuer` becomes an OIDC client of your IdP (Okta, Entra ID, Google,
Keycloak, Dex, ...). A user opens `/sso/login`, signs in at the IdP, and the
issuer's `/sso/callback` answers with the same gateway token `/login` returns
(`{"access_token": ..., "token_type": "Bearer", "expires_in": ...}`). The
auth-service keeps trusting one issuer — this one.

Register a client at your IdP with redirect URI `https://<issuer>/sso/callback`
and scopes `openid email profile`, then add to the issuer's
`config.existingSecret`:

| Key | Value |
|---|---|
| `ISSUER_OIDC_ISSUER` | your IdP's issuer URL (https) |
| `ISSUER_OIDC_CLIENT_ID` / `ISSUER_OIDC_CLIENT_SECRET` | the client you registered |
| `ISSUER_OIDC_REDIRECT_URL` | `https://<issuer>/sso/callback`, as browsers reach it |

If the IdP's certificate is from a private CA, mount it and set `sso.caFile`.

The IdP proves who someone is; the issuer's user store decides whether they may
enter. Only a user that already exists and is active signs in — the IdP's email
claim (if it says `email_verified: false`, refused) is matched to a user,
case-insensitively. There is no sign-up on first login: provision with SCIM.

## SCIM — your IdP creates and removes the users

Set `ISSUER_SCIM_TOKEN` (32+ characters) in the same secret, and point your IdP's
SCIM provisioning at:

- Base URL: `https://<issuer>/scim/v2`
- Auth: bearer token = `ISSUER_SCIM_TOKEN`

Supported: `Users` create, read, list (filter `userName eq "..."` or
`externalId eq "..."`), replace (PUT), patch (PATCH — `active`, `userName`,
`displayName`, `externalId`; other attributes are accepted and ignored) and
delete; `ServiceProviderConfig`. A SCIM user's `userName` is their email and they
have no password, so they sign in through SSO only. Deactivating a user
(`active: false`) or deleting them stops their next sign-in at once; a token
already issued lives out its TTL (`config.tokenTTL`, default 1h).

Groups are not provisioned, so a SCIM user's token carries no `teams` claim.
