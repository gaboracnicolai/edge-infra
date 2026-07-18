#!/usr/bin/env bash
# repro-version-collision.sh — REPRODUCTION TOOLING for the xDS "version-collision"
# spike. INVESTIGATION ONLY: it demonstrates the bug on a live standup and does not
# change any product behaviour. Run against an already-up cluster (deploy/local/up.sh).
#
# THE BUG (server-side, NOT an Envoy NACK): the control-plane is non-HA, so its xDS
# snapshot version counter (internal/xds/reconciler.go resolveVersion → "v%d" from a
# per-process atomic) RESETS to v1 on every process restart. go-control-plane's
# SnapshotCache decides whether to push by comparing the OPAQUE version string in the
# node's request to the snapshot's version (pkg/cache/v3/simple.go:439
# `if !exists || request.GetVersionInfo() == version { open watch }`). If a config
# change lands in a NEW process's first snapshot (also "v1") while a still-connected
# Envoy already holds "v1", the strings are equal → the cache HOLDS the watch open and
# never sends the changed CDS/LDS (wildcard) resources. Envoy logs cds/lds
# update_failure (the stream broke on restart) but update_REJECTED stays 0 — nothing is
# rejected; the new config is simply never delivered. Rolling edge-proxy fixes it
# because a fresh Envoy sends version_info="" ("" != "v1") → the cache responds.
#
# This script forces the collision deterministically (scale CP to 0, change the DB,
# scale back to 1) instead of relying on the ext_authz flip.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$DIR/lib.sh"
INFRA_NS="${INFRA_NS:-infra}"
BACKEND="${BACKEND:-10.96.81.76}"   # tenant-a echo ClusterIP:5678 — a real, valid upstream

pg() { k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}'; }
psql_e() { k exec -i -n "$INFRA_NS" "$(pg)" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 "$@"; }

# cds_clusters — sorted CDS cluster names currently in the first edge-proxy's Envoy.
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

section "REPRO — xDS version collision across a control-plane restart"
cleanup

# Clean, converged baseline: fresh proxies hold the current config at v1.
k -n edge rollout restart ds/edge-proxy >/dev/null 2>&1
k -n edge rollout status ds/edge-proxy --timeout=90s >/dev/null 2>&1 || true
sleep 6
[ "$(gw_code tenant-a.local)" = 200 ] || die "baseline broken: tenant-a.local not 200"
log "baseline CDS clusters: $(cds_clusters)"

section "force the collision: scale CP to 0, change config, scale CP to 1"
k -n "$INFRA_NS" scale deploy/edge-control-plane --replicas=0 >/dev/null
k -n "$INFRA_NS" wait --for=delete pod -l app.kubernetes.io/name=edge-control-plane --timeout=60s >/dev/null 2>&1 || sleep 8
psql_e -f - >/dev/null <<SQL
INSERT INTO clusters (id,name,connect_timeout_ms,lb_policy) VALUES ('collide-cluster','collide-cluster',5000,'ROUND_ROBIN') ON CONFLICT (name) DO NOTHING;
INSERT INTO endpoints (id,cluster_id,address,port,weight) VALUES ('collide-cluster-0','collide-cluster','${BACKEND}',5678,1) ON CONFLICT (cluster_id,address,port) DO NOTHING;
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
  VALUES ('collide','collide','local-gw',ARRAY['collide.local']::text[],'/','collide-cluster',30,'none',NULL)
  ON CONFLICT (name) DO UPDATE SET cluster_name=EXCLUDED.cluster_name,deleted_at=NULL,updated_at=now();
SQL
k -n "$INFRA_NS" scale deploy/edge-control-plane --replicas=1 >/dev/null
k -n "$INFRA_NS" rollout status deploy/edge-control-plane --timeout=90s >/dev/null 2>&1 || true
sleep 12

section "RED — the changed CDS never reaches the still-connected Envoy"
built="$(k -n "$INFRA_NS" logs deploy/edge-control-plane 2>/dev/null | grep -aE 'snapshot pushed' | tail -1)"
log "control-plane built: $built"                    # expect version v1, clusters 5
after="$(cds_clusters)"
log "Envoy CDS clusters after change+restart: $after"  # expect collide-cluster ABSENT
if printf '%s' "$after" | grep -q 'collide-cluster'; then
  die "NOT REPRODUCED: collide-cluster reached Envoy (version did not collide this run — check CP settled at v1)"
fi
code="$(gw_code collide.local)"
[ "$code" != 200 ] || die "NOT REPRODUCED: collide.local served 200 (cluster was delivered)"
ok "RED confirmed — collide-cluster ABSENT from Envoy CDS; collide.local -> HTTP $code (changed config withheld)"
log "NB: Envoy update_rejected stays 0 for CDS/LDS — this is withheld delivery, NOT a NACK (see /stats)."

section "WORKAROUND — roll edge-proxy (fresh version_info=\"\") restores delivery"
k -n edge rollout restart ds/edge-proxy >/dev/null 2>&1
k -n edge rollout status ds/edge-proxy --timeout=90s >/dev/null 2>&1 || true
sleep 8
[ "$(gw_code collide.local)" = 200 ] || die "workaround failed: collide.local not 200 after edge-proxy roll"
ok "WORKAROUND confirmed — after rolling edge-proxy, collide.local -> HTTP 200 (fresh proxy got collide-cluster)"

section "cleanup"
cleanup
k -n edge rollout restart ds/edge-proxy >/dev/null 2>&1
k -n edge rollout status ds/edge-proxy --timeout=90s >/dev/null 2>&1 || true
ok "repro complete — cluster reconverged"
