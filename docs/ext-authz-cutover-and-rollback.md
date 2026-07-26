# ext_authz cutover and rollback (CFG-1)

**Status: this repo is PARKED and not deployed — see the root [README](../README.md). Nothing here is
scheduled. This document exists so that whoever revives the cutover finds a rollback that works,
rather than one that reads as if it would.**

Everything below was verified against the code at `7e721f4`. File:line references are given so a
future reader can re-check rather than trust.

---

## 1. Read this before you flip anything

### ⚠ The committed image pin cannot honour the flip

`deploy/helm/edge-control-plane/values.yaml:5` pins the control-plane image to
`447ceb18980fc02fdc7e28db16354c62e3018850` — a **2026-05-20** build, **120 commits behind `main`**.
No environment overlay overrides it (`deploy/envs/**` pins no tag), and nothing automates the bump:
`images.yaml` pushes SHA-tagged images but never writes back to `values.yaml`.

That commit's `internal/config/config.go` contains **no `ExtAuthz` fields at all** — it predates
ext_authz support entirely. `deployment.yaml:85-86` renders `EXT_AUTHZ_ENABLED` unconditionally.

**So flipping the flag against the committed pin sets an environment variable the running binary
never reads.** ArgoCD reports a successful sync. The PR reads "the prod cutover". The gateway stays
**open and unauthenticated**.

Everyone was guarding against a deny-all trap. The real risk is the inverse: a cutover that fails
**open** while every signal says it succeeded. A failure that announces itself is survivable; this one
does not.

**Before any flip:** bump the image to a build containing the fail-close reconciler
(`internal/xds/reconciler.go:261`), deploy it, then prove the binary reads the flag:

```bash
# With the admin API enabled, ask the control plane what it thinks its own config is.
curl -sS -H "X-Admin-Key: $ADMIN_KEY" http://<cp>:18002/admin/v1/config | jq .ext_authz
# Expect: {"enabled": true, "address": "...", "tls": true, "mtls": true}
# `enabled:false` after the flip ⇒ the binary is not reading the flag. STOP.
```

If the admin API is not enabled (it is off in every overlay — `values.yaml:36-39`, unset in all four
environments), enable it first. Flipping auth on with no way to observe the result is not a cutover.

### The other prereqs (from PR #39, still correct, still unenforced)

1. Control-plane image carries the fail-close reconciler — **see above; this is the one that bites.**
2. `auth-service` deployed and reachable on `:50051`, JWKS + mTLS verified.
3. `envoy-authz-client-cert` applied. **No ArgoCD application covers `k8s/certs/`** (only
   `k8s/policies`, via `edge-policies`), so this is a manual `kubectl apply`. Without the mounted
   client cert the ext_authz cluster renders plaintext, the fail-closed auth-service rejects it, and
   the gateway denies everything.

One prereq has **become moot**: #47 made the snapshot version a pure function of the config hash
(`reconciler.go:399-440`), so the roll-edge-proxy workaround for version collisions is no longer
needed — `reconciler.go:413` says so. Note `deploy/local/README.md:99-104` still documents the old
per-process counter; that text is stale against `main` — but accidentally still correct for the
**pinned** image, which predates #47. Two staleness bugs cancelling out is not a safety property.

---

## 2. ⚠ The rollback

### What does NOT work, and why

**Flipping `extAuthz.enabled` back to `false` does not roll anything back.** It makes things worse.

`internal/xds/reconciler.go:261-267`:

```go
if !r.extAuthz.Enabled && builders.AnyRouteWantsAuth(domain.Routes) {
    return fmt.Errorf("refusing to build snapshot: ...")
}
```

`AnyRouteWantsAuth` is true for any route whose `auth_policy != "none"`
(`internal/xds/builders/lds.go:175-182`), and **every route defaults to `'jwt'`**
(`migrations/0004_auth_policy.sql:9`, `osb/models.py:46`).

So flipping the flag off makes the reconciler **refuse to publish any snapshot**. Envoy keeps its
last-good snapshot — the one with ext_authz **on**, pointed at the auth-service you are rolling back
because it is broken. **The deny-all continues, and the flip appears to do nothing.**

The previously-recorded rollback (`deploy/local/README.md:172-175`) is correct in substance — "flag
off **AND** remove the jwt route" — but it is written for the local demo, in `helm --set` terms, for
one seeded route. In production "remove the jwt route" means every tenant's route, because they all
default to `jwt`. That is not executable under pressure, and PR #39 carried no rollback section at all.

### ✅ What actually works — one SQL statement

**`auth_policy='none'` disables ext_authz per-route, even while the global filter is on.**
`internal/xds/builders/rds.go:116-120` emits `ExtAuthzPerRoute{Disabled: true}` for `none` (and
`mtls`). So you do **not** need to touch the flag, Helm, ArgoCD, or the image — and because ext_authz
stays globally enabled, the CFG-1 guard above never fires.

**THE ROLLBACK — run this against the control-plane database:**

```sql
-- Restores service on every route. Takes effect on the next reconcile (default 5s,
-- config.go:75 / values.yaml:27). ext_authz stays globally ON; each route opts out.
UPDATE routes SET auth_policy = 'none', updated_at = now() WHERE deleted_at IS NULL;
```

**Verify it took (do not assume):**

```bash
# 1. The rows changed.
psql "$DSN" -c "SELECT auth_policy, count(*) FROM routes WHERE deleted_at IS NULL GROUP BY 1;"
#    Expect a single row: none | <n>

# 2. Traffic actually flows without a token.
curl -si -H "Host: <a-real-route-host>" http://<gateway>/ | head -1
#    Expect 200, not 401/403.

# 3. The control plane is publishing again (not stuck on last-good).
curl -sS -H "X-Admin-Key: $ADMIN_KEY" http://<cp>:18002/admin/v1/nodes \
  | jq '{published_version, nodes_behind}'
#    nodes_behind should fall to 0 within a few reconciles.
```

### ⚠ The rollback un-does itself unless you freeze OSB

OSB re-provisioning **restores `auth_policy` from the service spec** — `osb/translator.py:150` and
`osb/worker.py:147` both carry `auth_policy = EXCLUDED.auth_policy`, and the spec default is `jwt`
(`osb/models.py:46`). So any tenant service that is created or updated after your `UPDATE` comes back
**authenticated**, silently, one service at a time.

**Freeze provisioning for the duration of the incident:**

```bash
kubectl -n infra scale deploy/edge-osb-worker --replicas=0
# …roll back, stabilise, fix the cause…
kubectl -n infra scale deploy/edge-osb-worker --replicas=<original>
```

### Then, once stable (not during the incident)

1. Revert the `extAuthz.enabled: true` overlay (revert the PR). Safe **now**, because no route wants
   auth, so the CFG-1 guard does not fire.
2. Restore each route's intended `auth_policy` deliberately, per tenant, once the cause is fixed.

### If you want a rollback that is one lever instead of two

The root cause of this awkwardness is that the *safe* default (`auth_policy='jwt'`, so a route can
only become unauthenticated explicitly) is also what makes rollback a fleet-wide mutation. Options,
none of which should be chosen during an incident:

- Add a global kill-switch the reconciler honours *ahead of* the fail-close check — an explicit
  "serve open, I know what I am doing" flag. This is the honest shape: it makes failing open a
  deliberate, logged, single action rather than a database migration.
- Or accept the SQL rollback above as the procedure, and rehearse it before the cutover.

**Do not adopt a rollback you have not run at least once against a real database.**
