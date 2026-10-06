# ext_authz cutover and rollback (CFG-1)

**Status: Talyvor Edge is kind-only and not deployed — see the root [README](../README.md). Nothing
here is scheduled. This document exists so that whoever runs the cutover finds a rollback that works,
rather than one that reads as if it would.**

Everything below was verified against the code at `7e721f4`. File:line references are given so a
future reader can re-check rather than trust.

---

## 1. Read this before you flip anything

**The launch-day order, one checked step at a time, is now
[ext-authz-launch-runbook.md](ext-authz-launch-runbook.md), rehearsed by `make kind-cutover`.**
Note what it measured about the advice below: deploying the bumped image with ext_authz still off
is safe only while no route has `auth_policy != 'none'`. A single such route freezes the whole
fleet on last-good, so provisioning stays frozen from the bump until the enable.

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
3. `envoy-authz-client-cert` issued. The edge-proxy chart issues it while
   `extAuthz.clientTLS.enabled` is on (the default), with the `edge-pki` chart's CA. Without the mounted
   client cert the ext_authz cluster renders plaintext, the fail-closed auth-service rejects it, and
   the gateway denies everything.

One prereq has **become moot**: #47 made the snapshot version a pure function of the config hash
(`reconciler.go:399-440`), so the roll-edge-proxy workaround for version collisions is no longer
needed — `reconciler.go:413` says so. Note `deploy/local/README.md:99-104` still documents the old
per-process counter; that text is stale against `main` — but accidentally still correct for the
**pinned** image, which predates #47. Two staleness bugs cancelling out is not a safety property.

---

## 2. ⚠ The rollback

**Rehearsed: `make kind-rollback`** (`deploy/local/rollback.sh`, CI: Kind Rollback). From the
cutover state, with the auth-service taken down, it measures both halves of this section on kind:

- **Flipping `extAuthz.enabled` back alone**, with a jwt route present: the flipped control-plane
  pod refuses every snapshot and never turns Ready (its `/readyz` needs a published snapshot), so
  the rolling update never progresses and the old pods keep serving ext_authz **on**. Every gated
  request stays denied: no token, a garbage token and a **valid** JWT all get 403.
- **The full revert**: first remove the jwt routes while ext_authz is still on, then roll the
  control-plane release back to its pre-enable revision (image + `extAuthz.enabled=false`). The
  gateway then serves exactly what it served before the enable: the same release values and image,
  the same xDS version acked by every edge-proxy, and the same answer for every request class. No
  tenant request is refused along the way. Reversing the two steps is the flip-alone case.

It does not rehearse the SQL rollback below. That one ends with the routes served open, which is not
the same as before.

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

**THE ROLLBACK — run this against the control-plane database** (the one shared database, so the
OSB freeze flag lives there too):

```sql
-- 1. Freeze OSB FIRST (see the next section for why it must come first and why it is
--    a row, not a replica count). From this commit on, the API answers 503 and the
--    worker applies no queued spec.
UPDATE osb_freeze SET frozen = true, reason = '<incident id>', updated_at = now();

-- 2. Restores service on every route. Takes effect on the next reconcile (default 5s,
--    config.go:75 / values.yaml:27). ext_authz stays globally ON; each route opts out.
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
`osb/worker.py` both carry `auth_policy = EXCLUDED.auth_policy`, and the spec default is `jwt`
(`osb/models.py:46`). So any tenant service that is created or updated after your `UPDATE` comes back
**authenticated**, silently, one service at a time — including specs that were already queued in
JetStream before the incident started.

**Do not freeze by scaling the worker to 0.** `kubectl scale deploy/edge-osb-worker --replicas=0`
is reverted within minutes: the `edge-osb` Application has `selfHeal: true`
(`deploy/argocd/applications/edge-osb.yaml`), so ArgoCD puts the replicas back and the worker drains
the queue mid-incident. The freeze is a database row instead, `osb_freeze`
(`osb/migrations/0004_freeze.sql`), which nothing in git reconciles:

- **The API refuses.** While `frozen` is true, `POST /v1/services` and `DELETE /v1/services/{name}`
  return **503** (`Retry-After: 60`) and queue nothing.
- **The worker holds.** A spec already in JetStream is delivered but **not applied**: the worker
  keeps it un-acked and touches it with `in_progress` so it spends none of its six deliveries (a
  freeze of any length dead-letters nothing). It logs `provisioning frozen; holding queued specs`
  with the count every few seconds.
- **It holds at the commit.** Each apply reads the row `FOR SHARE` inside its transaction, so once
  your `UPDATE osb_freeze` returns, no spec can land after it. Freeze **before** step 2 above, or a
  spec applied between the two statements puts `jwt` back on its route.

**Verify the freeze held:**

```bash
psql "$DSN" -c "SELECT frozen, reason, updated_at FROM osb_freeze;"            # frozen = t
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TENANT_KEY" \
  -H 'Content-Type: application/json' -d '{}' http://<osb-api>/v1/services       # 503
psql "$DSN" -c "SELECT count(*) FROM provision_requests WHERE status = 'PENDING';"  # held specs
```

**Unfreeze** only when a route coming back as `jwt` is what you want — the auth-service is healthy
and ext_authz is on. Every held spec applies within seconds, in order, with its spec's `auth_policy`;
while ext_authz is globally **off**, one held `jwt` spec freezes the fleet on last-good (§1).

```sql
UPDATE osb_freeze SET frozen = false, reason = NULL, updated_at = now();
```

Proven end to end against a real Postgres and a real JetStream by `osb/tests/test_freeze.py`
(CI: `osb-test.yaml`, integration job): while frozen a POST is refused and a queued spec stays
unapplied for longer than its whole redelivery budget; unfreezing applies it.

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
