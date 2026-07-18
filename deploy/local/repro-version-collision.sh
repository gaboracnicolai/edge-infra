#!/usr/bin/env bash
# repro-version-collision.sh — RED→GREEN check for the xDS version-collision fix.
#
# THE BUG (pre-fix): the control-plane stamped the xDS snapshot version from a
# per-process counter that RESET to "v1" on restart. go-control-plane's SnapshotCache
# only pushes when the node's request version_info STRING differs from the snapshot
# version (pkg/cache/v3/simple.go:439), so a config change landing in a restarted
# process's first snapshot (also "v1") collided with the "v1" a still-connected Envoy
# already held → the changed CDS/LDS (wildcard) were WITHHELD (Envoy cds/lds
# update_failure, update_rejected 0 — not a NACK). Rolling edge-proxy was the only fix.
#
# THE FIX: the version is now a pure function of the config hash, so a changed config
# ALWAYS carries a new version and reaches the still-connected Envoy WITHOUT rolling
# edge-proxy. This script forces the collision scenario (change the DB while the
# control-plane is down, then restart it) and asserts the changed cluster is delivered
# to the SAME, still-connected edge-proxy pods. Run against an up cluster whose
# control-plane carries the fix.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$DIR/lib.sh"
INFRA_NS="${INFRA_NS:-infra}"

pg() { k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}'; }
psql_e() { k exec -i -n "$INFRA_NS" "$(pg)" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 "$@"; }
ep_names() { k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | sort | tr '\n' ',' ; }

# cds_clusters — sorted CDS cluster names in the first edge-proxy's Envoy.
cds_clusters() {
  local ep lp d; ep="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[0].metadata.name}')"
  lp=$((19900 + RANDOM % 80))
  k -n edge port-forward "pod/$ep" "${lp}:9901" >/dev/null 2>&1 & local pf=$!; sleep 3
  d="$(curl -s --max-time 8 "http://127.0.0.1:${lp}/config_dump" 2>/dev/null || true)"
  kill "$pf" >/dev/null 2>&1 || true; wait "$pf" 2>/dev/null || true
  printf '%s' "$d" | jq -r '[.configs[]|select(.["@type"]|test("Clusters")).dynamic_active_clusters[]?.cluster.name]|sort|join(",")'
}

cleanup() {
  psql_e -c "DELETE FROM routes WHERE name='collide'; DELETE FROM clusters WHERE name='collide-cluster';" >/dev/null 2>&1 || true
}
trap cleanup EXIT

section "REPRO — version-hash fix: changed config reaches a STILL-CONNECTED Envoy across a CP restart"
cleanup
BACKEND="$(psql_e -tAc "SELECT address FROM endpoints e JOIN clusters c ON c.id=e.cluster_id WHERE c.name='tenant-a' LIMIT 1" | tr -d '[:space:]')"
[ -n "$BACKEND" ] || die "could not resolve a tenant-a backend address to point collide-cluster at"
log "collide-cluster will target the tenant-a backend $BACKEND:5678 (so collide.local serves 200 iff CDS delivered)"

# Baseline: fresh proxies hold the current config. SELF-GUARD: collide.local must NOT
# resolve and collide-cluster must be ABSENT before we seed — otherwise a later 200
# would be meaningless.
k -n edge rollout restart ds/edge-proxy >/dev/null 2>&1
k -n edge rollout status ds/edge-proxy --timeout=90s >/dev/null 2>&1 || true
sleep 6
[ "$(gw_code tenant-a.local)" = 200 ] || die "baseline broken: tenant-a.local not 200"
[ "$(gw_code collide.local)" != 200 ] || die "SELF-GUARD failed: collide.local already served before seeding"
cds_clusters | grep -q 'collide-cluster' && die "SELF-GUARD failed: collide-cluster present before seeding" || true
base_eps="$(ep_names)"
log "baseline CDS clusters: $(cds_clusters) ; connected edge-proxy pods: $base_eps"

section "config change COINCIDENT with a control-plane restart (the collision scenario)"
k -n "$INFRA_NS" scale deploy/edge-control-plane --replicas=0 >/dev/null
k -n "$INFRA_NS" wait --for=delete pod -l app.kubernetes.io/name=edge-control-plane --timeout=60s >/dev/null 2>&1 || sleep 8
psql_e -f - >/dev/null <<SQL
INSERT INTO clusters (id,name,connect_timeout_ms,lb_policy) VALUES ('collide-cluster','collide-cluster',5000,'ROUND_ROBIN') ON CONFLICT (name) DO NOTHING;
INSERT INTO endpoints (id,cluster_id,address,port,weight) VALUES ('collide-cluster-0','collide-cluster','${BACKEND}',5678,1) ON CONFLICT (cluster_id,address,port) DO NOTHING;
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
  VALUES ('collide','collide','local-gw',ARRAY['collide.local']::text[],'/','collide-cluster',30,'none',NULL)
  ON CONFLICT (name) DO UPDATE SET cluster_name=EXCLUDED.cluster_name,deleted_at=NULL,updated_at=now();
SQL
# SELF-GUARD: the seed must actually be present, else the test could pass vacuously.
[ "$(psql_e -tAc "SELECT count(*) FROM clusters WHERE name='collide-cluster'" | tr -d '[:space:]')" = 1 ] \
  || die "SELF-GUARD failed: collide-cluster was not seeded"
k -n "$INFRA_NS" scale deploy/edge-control-plane --replicas=1 >/dev/null
k -n "$INFRA_NS" rollout status deploy/edge-control-plane --timeout=90s >/dev/null 2>&1 || true
sleep 12   # reconnect + delivery — deliberately NO edge-proxy roll

section "GREEN — the STILL-CONNECTED Envoy received the changed CDS, no edge-proxy roll"
now_eps="$(ep_names)"
[ "$now_eps" = "$base_eps" ] || die "edge-proxy pods changed ($base_eps -> $now_eps) — a roll would invalidate the still-connected test"
built="$(k -n "$INFRA_NS" logs deploy/edge-control-plane 2>/dev/null | grep -aE 'snapshot pushed' | tail -1)"
log "control-plane built: $built"
after="$(cds_clusters)"
log "Envoy CDS clusters after change+restart (same proxies): $after"
printf '%s' "$after" | grep -q 'collide-cluster' \
  || die "FAIL (bug still present): collide-cluster ABSENT from the still-connected Envoy CDS after restart"
code="$(gw_code collide.local)"
[ "$code" = 200 ] || die "FAIL: collide.local -> HTTP $code (expected 200 — changed config not delivered without an edge-proxy roll)"
ok "GREEN — collide-cluster delivered to still-connected proxies [$base_eps]; collide.local -> HTTP $code; NO edge-proxy roll"

section "cleanup — remove the test rows; reconverge"
cleanup
k -n edge rollout restart ds/edge-proxy >/dev/null 2>&1
k -n edge rollout status ds/edge-proxy --timeout=90s >/dev/null 2>&1 || true
ok "repro complete — fix verified live; cluster reconverged"
