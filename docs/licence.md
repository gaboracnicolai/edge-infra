# The Talyvor Edge licence

Talyvor Edge comes with the Enterprise plan. Talyvor gives you a licence: one
line of text naming your company, the plan and the date it expires, signed by
Talyvor. You install it in your cluster, and Edge checks it there.

**A licence never changes what Edge serves.** Edge checks it offline — no call
to Talyvor, no network at all ([no-internet-at-run-time.md](no-internet-at-run-time.md))
— and reports what it finds. Missing, unverifiable or expired, every route,
listener and certificate is served exactly as before. Kind Phase 35 proves it:
with an expired licence the licence metric reads 0 and both tenants still return
200, through a cold restart of the control plane and a fresh Envoy.

## Installing it

Put the licence in a Secret in the control plane's namespace and name it in the
`edge-control-plane` chart:

```sh
kubectl -n infra create secret generic edge-licence --from-file=licence=licence.txt
helm upgrade edge-control-plane deploy/helm/edge-control-plane -n infra --reuse-values \
  --set licence.existingSecret=edge-licence
```

The control plane logs what it found when it starts, and again whenever that
changes:

```json
{"level":"INFO","msg":"Talyvor Edge licence valid","licensee":"Acme Ltd","plan":"enterprise","id":"lic_…","expires_at":"2027-10-06T00:00:00Z"}
```

## When it expires

Nothing stops. Within a minute of the expiry the control plane logs a warning:

```json
{"level":"WARN","msg":"Talyvor Edge licence EXPIRED — traffic is not affected; ask Talyvor to renew it","licensee":"Acme Ltd",…}
```

and its metrics (`:2112/metrics`, which the chart already scrapes) read:

| Metric | |
|---|---|
| `edge_licence_valid` | 1 while the licence is signed by Talyvor and unexpired, otherwise 0 |
| `edge_licence_expiry_timestamp_seconds` | when the licence expires (Unix time); 0 when none can be read |

The `edge-observability` chart raises `EdgeLicenceNotValid` (severity warning)
while `edge_licence_valid` is 0. To be told before the date, alert on
`edge_licence_expiry_timestamp_seconds - time()` with the notice you want.

## Renewing it

Update the Secret with the new licence. Kubernetes refreshes the mounted file
within a minute or two and the next check reads it; nothing restarts.

```sh
kubectl -n infra create secret generic edge-licence --from-file=licence=licence.txt \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Checking a licence by hand

```sh
go run ./cmd/licence verify < licence.txt
# valid: lic_…, licensee "Acme Ltd", plan enterprise, expires 2027-10-06T00:00:00Z
```

It exits non-zero unless the licence is valid now.

## The format

```
talyvor-edge-licence-v1.<payload>.<signature>
```

`payload` is the unpadded base64url of a JSON object — `id`, `licensee`, `plan`,
`issued_at`, `expires_at` (RFC 3339) — and `signature` is the unpadded base64url
Ed25519 signature over everything before the last dot. Edge trusts the public
keys built into it (`internal/licence`), and any listed in the chart's
`licence.publicKeys`.

## Issuing licences (Talyvor)

Once, on the machine that will issue licences:

```sh
go run ./cmd/licence keygen -out talyvor-licence.key
```

It writes the private key (readable by you only) and prints the public key: add
that to `TalyvorKeys` in `internal/licence/licence.go`. The private key never
goes into this repository. Then, for each customer:

```sh
go run ./cmd/licence issue -key talyvor-licence.key -licensee "Acme Ltd" -expires 2027-10-06 > licence.txt
```
