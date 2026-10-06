#!/usr/bin/env bash
# observability.sh — the edge-observability chart on a throwaway kind cluster
# that is deleted afterwards whether the drill passed or failed.
#
#   1. INSTALL  edge-observability into ns/monitoring, as its values.yaml says;
#               Prometheus, Loki, Tempo, the collector and Grafana all Ready.
#   2. RULES    Prometheus, asked through Grafana, has loaded every rule group in
#               the chart's rules/ and evaluated every rule without an error.
#   3. GATEWAY  an Envoy labelled and annotated like edge-proxy, with its stats
#               listener (manifests/observability-gateway.yaml), in front of
#               tenant-a. Prometheus finds it on its own: tenant-a's request
#               counter reads 0, and the Request Traffic dashboard's "RPS by
#               cluster" panel shows no rate for tenant-a yet (red first).
#   4. TRAFFIC  $REQUESTS requests to Host tenant-a.local, every one answered 200.
#   5. RATE     the same panel, run through Grafana the way Grafana runs it, shows
#               tenant-a above zero, and the counter it reads holds exactly
#               $REQUESTS.
#   6. OTLP     a log record and a span sent to the collector come back out of
#               Loki and Tempo through Grafana.
#
#   make kind-observability                    # == deploy/local/observability.sh
#   KEEP_CLUSTER=1 make kind-observability     # leave the cluster up afterwards
set -euo pipefail
export CLUSTER_NAME="${CLUSTER_NAME:-edge-observability}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_toolchain docker kind kubectl helm jq curl

CHART="$REPO_ROOT/deploy/helm/edge-observability"
RELEASE=edge-observability
NS=monitoring
GRAFANA_LP="${GRAFANA_LP:-13000}"
REQUESTS="${REQUESTS:-300}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69}"
PF_PID=""

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  die "kind cluster '$CLUSTER_NAME' already exists — delete it (kind delete cluster --name $CLUSTER_NAME) or pick another CLUSTER_NAME"
fi

started="$(date +%s)"
teardown() {
  local rc=$?
  trap - EXIT
  [ -z "$PF_PID" ] || kill "$PF_PID" 2>/dev/null || true
  if [ "$rc" != 0 ] && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    section "FAILED (exit $rc) — cluster state before teardown"
    k get pods,pvc -A -o wide 2>/dev/null || true
    local d
    for d in prometheus loki tempo otel-collector grafana; do
      echo "  --- $d"; k -n "$NS" logs "deploy/$d" --tail=20 2>/dev/null || true
    done
    k get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -30 || true
  fi
  if [ "${KEEP_CLUSTER:-0}" = 1 ]; then
    warn "KEEP_CLUSTER=1 — leaving '$CLUSTER_NAME' up; delete it with: kind delete cluster --name $CLUSTER_NAME"
  else
    kind delete cluster --name "$CLUSTER_NAME" || warn "teardown failed — delete it with: kind delete cluster --name $CLUSTER_NAME"
  fi
  if [ "$rc" = 0 ]; then
    ok "kind-observability PASSED in $(( ($(date +%s) - started) / 60 )) min — Grafana showed Envoy's request rate, cluster removed"
  else
    printf '%s  X kind-observability FAILED (exit %s)%s\n' "$C_RED" "$rc" "$C_RST" >&2
  fi
  exit "$rc"
}
trap teardown EXIT

# ---- Grafana, through one port-forward ----------------------------------------
pf_start() {
  [ -z "$PF_PID" ] || kill "$PF_PID" 2>/dev/null || true
  k -n "$NS" port-forward svc/grafana "$GRAFANA_LP:3000" >/dev/null 2>&1 &
  PF_PID=$!
  retry 20 1 curl -fs -o /dev/null --max-time 3 "http://127.0.0.1:$GRAFANA_LP/api/health" \
    || die "Grafana does not answer on the port-forward (127.0.0.1:$GRAFANA_LP)"
}
# graf <path> [curl args...] — the Grafana HTTP API as its admin; a dropped
# port-forward is restarted once.
graf() {
  local p="$1"; shift
  curl -fsS --max-time 15 -u "admin:$GF_PASS" "$@" "http://127.0.0.1:$GRAFANA_LP$p" 2>/dev/null && return 0
  curl -fs -o /dev/null --max-time 3 "http://127.0.0.1:$GRAFANA_LP/api/health" || { pf_start; curl -fsS --max-time 15 -u "admin:$GF_PASS" "$@" "http://127.0.0.1:$GRAFANA_LP$p"; }
}
# prom <expr> — an instant query through Grafana's Prometheus datasource, the
# path a dashboard panel takes. One line per series: {labels, value}.
prom() {
  graf /api/ds/query -H 'Content-Type: application/json' -d "$(jq -nc --arg e "$1" \
    '{from:"now-10m", to:"now", queries:[{refId:"A", datasource:{uid:"prometheus"}, expr:$e, instant:true, range:false}]}')" \
    | jq -c '.results.A.frames[]? | {labels: (.schema.fields[-1].labels // {}), value: (.data.values[-1][-1])}'
}
# tenant_value <expr> — that query's value for envoy_cluster_name=tenant-a, or "".
tenant_value() { { prom "$1" | jq -r 'select(.labels.envoy_cluster_name == "tenant-a") | .value' | head -1; } || true; }

# ---- 1. INSTALL ----------------------------------------------------------------
section "kind cluster '$CLUSTER_NAME'"
kind create cluster --name "$CLUSTER_NAME" --wait 120s

section "1. INSTALL — helm install $RELEASE -n $NS"
h install "$RELEASE" "$CHART" -n "$NS" --create-namespace --wait --timeout 10m >/dev/null \
  || die "INSTALL: the chart did not come up"
for d in prometheus loki tempo otel-collector grafana; do
  k -n "$NS" rollout status "deploy/$d" --timeout 60s >/dev/null || die "INSTALL: deploy/$d is not Ready"
done
ok "prometheus, loki, tempo, otel-collector and grafana are Ready"
GF_PASS="$(k -n "$NS" get secret "$RELEASE-grafana" -o jsonpath='{.data.admin-password}' | base64 -d)"
[ -n "$GF_PASS" ] || die "INSTALL: the chart made no Grafana admin password"
pf_start
dash="$(graf /api/dashboards/uid/edge-request-traffic)" || die "INSTALL: Grafana has no Request Traffic dashboard"
RPS_EXPR="$(jq -r '.dashboard.panels[] | select(.title == "RPS by cluster") | .targets[0].expr' <<<"$dash")"
[ -n "$RPS_EXPR" ] || die "INSTALL: the Request Traffic dashboard has no \"RPS by cluster\" panel"
ok "Grafana serves the Request Traffic dashboard; its \"RPS by cluster\" panel runs: $RPS_EXPR"

# ---- 2. RULES ------------------------------------------------------------------
section "2. RULES — every group in rules/ loaded and evaluated"
want_groups="$(grep -h '^  - name:' "$CHART"/rules/*.yaml | wc -l | tr -d ' ')"
want_rules="$(grep -hE '^ +- (alert|record):' "$CHART"/rules/*.yaml | wc -l | tr -d ' ')"
rules_ok() {
  local r
  r="$(graf /api/datasources/proxy/uid/prometheus/api/v1/rules)" || return 1
  RULES_SEEN="$(jq -r '[.data.groups | length, ([.data.groups[].rules[]] | length), ([.data.groups[].rules[] | select(.health == "ok")] | length)] | @tsv' <<<"$r")"
  RULES_ERR="$(jq -r '[.data.groups[].rules[] | select(.health == "err") | "\(.name): \(.lastError)"] | join("; ")' <<<"$r")"
  [ -z "$RULES_ERR" ] || return 1
  [ "$RULES_SEEN" = "$want_groups	$want_rules	$want_rules" ]
}
retry 24 5 rules_ok || die "RULES: want $want_groups groups / $want_rules rules all healthy, Prometheus has (groups, rules, healthy) = (${RULES_SEEN:-none})${RULES_ERR:+ — errors: $RULES_ERR}"
ok "Prometheus loaded $want_groups groups, $want_rules rules, every one evaluated with health ok"

# ---- 3. GATEWAY ----------------------------------------------------------------
section "3. GATEWAY — Envoy as edge-proxy in front of tenant-a; no rate before any request"
sed "s#envoyproxy/envoy:[^[:space:]]*#$ENVOY_IMAGE#" "$LOCAL_DIR/manifests/observability-gateway.yaml" | k apply -f - >/dev/null
k -n edge rollout status deploy/tenant-a --timeout 180s >/dev/null || die "GATEWAY: tenant-a is not Ready"
k -n edge rollout status deploy/edge-proxy --timeout 180s >/dev/null || die "GATEWAY: edge-proxy is not Ready"
counter_zero() { [ "$(tenant_value 'envoy_cluster_upstream_rq_total{envoy_cluster_name="tenant-a"}')" = 0 ]; }
retry 24 5 counter_zero \
  || die "GATEWAY: Prometheus never scraped Envoy's tenant-a counter at 0 — pod discovery or the :9903 stats listener is not reaching it"
ok "Prometheus found Envoy by its annotations; tenant-a's request counter reads 0"
before="$(tenant_value "$RPS_EXPR")"
awk -v v="${before:-0}" 'BEGIN { exit !(v + 0 == 0) }' \
  || die "GATEWAY RED broken: the panel shows tenant-a at $before req/s before any request was sent"
ok "RED: the panel shows tenant-a at ${before:-no series} req/s before any request"

# ---- 4. TRAFFIC ----------------------------------------------------------------
section "4. TRAFFIC — $REQUESTS requests to Host tenant-a.local through Envoy"
k -n edge run traffic --image="$CURL_IMAGE" --restart=Never --env="N=$REQUESTS" --command -- sh -c '
  i=0; ok=0
  while [ "$i" -lt "$N" ]; do
    c="$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -H "Host: tenant-a.local" http://edge-proxy.edge.svc.cluster.local:8443/)"
    [ "$c" = 200 ] && ok=$((ok + 1))
    i=$((i + 1)); sleep 0.1
  done
  echo "sent=$i ok=$ok"' >/dev/null
k -n edge wait --for=jsonpath='{.status.phase}'=Succeeded pod/traffic --timeout 300s >/dev/null \
  || die "TRAFFIC: the traffic pod did not finish ($(k -n edge logs traffic 2>/dev/null | tail -3))"
sent="$(k -n edge logs traffic | tail -1)"
[ "$sent" = "sent=$REQUESTS ok=$REQUESTS" ] || die "TRAFFIC: not every request was answered 200 ($sent)"
ok "$sent — every request answered 200 by tenant-a"

# ---- 5. RATE -------------------------------------------------------------------
section "5. RATE — Grafana shows Envoy's request rate for tenant-a"
rate_shown() {
  COUNT="$(tenant_value 'envoy_cluster_upstream_rq_total{envoy_cluster_name="tenant-a"}')"
  RATE="$(tenant_value "$RPS_EXPR")"
  [ "${COUNT:-}" = "$REQUESTS" ] && awk -v v="${RATE:-0}" 'BEGIN { exit !(v + 0 > 0) }'
}
retry 36 5 rate_shown \
  || die "RATE: Grafana shows tenant-a at ${RATE:-no series} req/s with ${COUNT:-no} requests counted (want > 0 and exactly $REQUESTS)"
ok "Grafana's \"RPS by cluster\" panel: tenant-a at $RATE req/s; Envoy counted $COUNT of the $REQUESTS requests"

# ---- 6. OTLP -------------------------------------------------------------------
section "6. OTLP — a log record and a span through the collector to Loki and Tempo"
marker="drill-$(date +%s)-$RANDOM"
trace_id="$(openssl rand -hex 16 2>/dev/null || od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
span_id="$(openssl rand -hex 8 2>/dev/null || od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
now_ns="$(date +%s)000000000"
resource='{"attributes":[{"key":"service.name","value":{"stringValue":"observability-drill"}}]}'
log_body="$(jq -nc --argjson r "$resource" --arg m "$marker" --arg t "$now_ns" \
  '{resourceLogs:[{resource:$r, scopeLogs:[{logRecords:[{timeUnixNano:$t, severityText:"INFO", body:{stringValue:$m}}]}]}]}')"
trace_body="$(jq -nc --argjson r "$resource" --arg m "$marker" --arg t "$now_ns" --arg tid "$trace_id" --arg sid "$span_id" \
  '{resourceSpans:[{resource:$r, scopeSpans:[{spans:[{traceId:$tid, spanId:$sid, name:$m, kind:2, startTimeUnixNano:$t, endTimeUnixNano:$t}]}]}]}')"
k -n "$NS" run otlp --image="$CURL_IMAGE" --restart=Never --env="LOG=$log_body" --env="TRACE=$trace_body" --command -- sh -c '
  curl -fsS -H "Content-Type: application/json" -d "$LOG" http://otel-collector:4318/v1/logs &&
  curl -fsS -H "Content-Type: application/json" -d "$TRACE" http://otel-collector:4318/v1/traces' >/dev/null
k -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded pod/otlp --timeout 120s >/dev/null \
  || die "OTLP: the collector did not accept the log record and span ($(k -n "$NS" logs otlp 2>/dev/null | tail -3))"
loki_has() {
  graf /api/ds/query -H 'Content-Type: application/json' -d "$(jq -nc \
    '{from:"now-15m", to:"now", queries:[{refId:"A", datasource:{uid:"loki"}, expr:"{service_name=\"observability-drill\"}", queryType:"range", maxLines:50}]}')" \
    | grep -q "$marker"
}
retry 24 5 loki_has || die "OTLP: Grafana's Loki datasource never returned the log line $marker"
ok "Loki, through Grafana, returned the log line $marker"
tempo_has() { graf "/api/datasources/proxy/uid/tempo/api/traces/$trace_id" | grep -q "$marker"; }
retry 24 5 tempo_has || die "OTLP: Grafana's Tempo datasource never returned trace $trace_id"
ok "Tempo, through Grafana, returned trace $trace_id"
