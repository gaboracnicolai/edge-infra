#!/usr/bin/env bash
# repro-firstboot-visibility.sh — live proof that a first-boot DEGRADED PUBLISH is
# now observable. The two guards (empty-collapse, consistency) are exempt on first
# boot (prev == nil) and PUBLISH the bad config so a fresh edge can come up — the one
# path where bad config reaches Envoy. This forces that path (seed an inconsistent
# config while the control-plane is DOWN, then bring it up so its FIRST reconcile sees
# prev == nil + bad config) and asserts: the bad route IS published (behaviour
# preserved), xds_snapshots_published_degraded_total{reason="inconsistent_first_boot"}
# incremented on :2112, the WARN is in the control-plane log, and tenants still serve.
# Run against an up cluster whose control-plane carries this change. Idempotent.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$DIR/lib.sh"
INFRA_NS="${INFRA_NS:-infra}"

pg() { k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}'; }
psql_e() { k exec -i -n "$INFRA_NS" "$(pg)" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 "$@"; }

# cp_degraded <reason> — value of the degraded-publish counter for <reason> from the
# control-plane /metrics on :2112 (port-forward routes via the API server, plain HTTP).
cp_degraded() {
  local reason="$1" lp pid out
  lp=$((12200 + RANDOM % 80))
  k -n "$INFRA_NS" port-forward deploy/edge-control-plane "${lp}:2112" >/dev/null 2>&1 & pid=$!
  local i=0; out=""
  while [ "$i" -lt 20 ]; do
    out="$(curl -s --max-time 4 "http://127.0.0.1:${lp}/metrics" 2>/dev/null || true)"
    [ -n "$out" ] && break; i=$((i + 1)); sleep 1
  done
  kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true
  printf '%s\n' "$out" | grep -F "xds_snapshots_published_degraded_total{reason=\"${reason}\"}" | awk '{print $NF}' | tail -1
}

drop_ghost() { psql_e -c "DELETE FROM routes WHERE name='r8-ghost';" >/dev/null 2>&1 || true; }
trap drop_ghost EXIT

section "REPRO — first-boot degraded publish is observable (inconsistent_first_boot)"
drop_ghost

# Baseline: the counter is PER-PROCESS (resets on restart) and only moves on a degraded
# FIRST boot. Restart the CP on the current (healthy, no r8-ghost) config so this
# process first-boots HEALTHY — its degraded counter is a clean 0 to measure against.
section "baseline — restart CP on healthy config; inconsistent_first_boot = 0"
k -n "$INFRA_NS" rollout restart deploy/edge-control-plane >/dev/null 2>&1
k -n "$INFRA_NS" rollout status deploy/edge-control-plane --timeout=90s >/dev/null 2>&1 || true
sleep 5
base="$(cp_degraded inconsistent_first_boot)"
[ -n "$base" ] || die "metric xds_snapshots_published_degraded_total{reason=inconsistent_first_boot} not scrapeable on :2112"
[ "$base" = 0 ] || die "baseline not 0 after a healthy restart ($base) — a healthy first boot must not count as degraded"
log "baseline (healthy first boot) inconsistent_first_boot = $base"

# Force the first-boot degraded path: seed an inconsistent config while the CP is DOWN,
# then bring it up so the NEW process's FIRST reconcile sees prev == nil + bad config.
section "scale CP to 0, seed a dangling route (r8-ghost -> absent cluster), scale CP to 1"
k -n "$INFRA_NS" scale deploy/edge-control-plane --replicas=0 >/dev/null
k -n "$INFRA_NS" wait --for=delete pod -l app.kubernetes.io/name=edge-control-plane --timeout=60s >/dev/null 2>&1 || sleep 8
psql_e -f - >/dev/null <<'SQL'
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('r8-ghost','r8-ghost','local-gw',ARRAY['r8-ghost.local']::text[],'/','r8-ghost-cluster-absent',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET cluster_name=EXCLUDED.cluster_name,auth_policy=EXCLUDED.auth_policy,deleted_at=NULL,updated_at=now();
SQL
[ "$(psql_e -tAc "SELECT count(*) FROM routes WHERE name='r8-ghost'" | tr -d '[:space:]')" = 1 ] || die "SELF-GUARD: r8-ghost not seeded"
k -n "$INFRA_NS" scale deploy/edge-control-plane --replicas=1 >/dev/null
k -n "$INFRA_NS" rollout status deploy/edge-control-plane --timeout=90s >/dev/null 2>&1 || true

section "GREEN — the degraded publish is visible AND behaviour is preserved"
# (1) behaviour preserved: the bad route IS published to Envoy (first-boot exemption).
# Retry: the fresh CP first-boots and publishes, then the reconnecting proxies pick it
# up via catch-up — allow time for the ADS reconnect + fan-out (a fixed sleep is racy).
dump=""; i=0
while [ "$i" -lt 20 ]; do
  dump="$(envoy_config_dump "$(ep_pod)")"
  has "$dump" r8-ghost && break
  i=$((i + 1)); sleep 2
done
has "$dump" r8-ghost || die "FAIL: r8-ghost NOT published to Envoy — first-boot publish behaviour changed"
ok "behaviour preserved — r8-ghost IS published to Envoy on first boot"
# (2) the WARN is in the control-plane log.
k -n "$INFRA_NS" logs deploy/edge-control-plane 2>/dev/null \
  | grep -aE 'first snapshot not internally consistent; publishing' | tail -1 | sed 's/^/    /' \
  || die "FAIL: the first-boot inconsistency WARN is absent from the control-plane log"
ok "WARN present — 'first snapshot not internally consistent; publishing (no last-good yet)'"
# (3) the metric incremented on :2112 (fresh process: 0 -> >=1, and > baseline).
after="$(cp_degraded inconsistent_first_boot)"
[ -n "$after" ] || die "FAIL: could not scrape inconsistent_first_boot after the restart"
log "after inconsistent_first_boot = $after"
awk -v a="$base" -v b="$after" 'BEGIN{exit !(b+0>=1 && b+0>a+0)}' \
  || die "FAIL: inconsistent_first_boot did not increment ($base -> $after) — degraded publish not counted"
ok "GREEN — xds_snapshots_published_degraded_total{reason=\"inconsistent_first_boot\"} = $after (was $base)"
# (4) tenants still serve.
ca="$(gw_code tenant-a.local)"; cb="$(gw_code tenant-b.local)"
{ [ "$ca" = 200 ] && [ "$cb" = 200 ]; } || die "FAIL: tenant-a/b broke under the degraded first-boot snapshot ($ca/$cb)"
ok "tenant-a=$ca tenant-b=$cb — the fleet still serves"

section "cleanup — remove r8-ghost; reconverge"
drop_ghost
i=0; while [ "$i" -lt 15 ]; do [ "$(gw_code tenant-a.local)" = 200 ] && break; i=$((i + 1)); sleep 2; done
ok "repro complete — first-boot degraded publish is observable; cluster reconverged"
