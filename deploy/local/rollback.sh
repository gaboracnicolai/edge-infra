#!/usr/bin/env bash
# rollback.sh — the ext_authz rollback (W5.3), rehearsed on a throwaway kind
# cluster. It reaches the cutover state with cutover.sh's own steps, records what
# the gateway serves just before the enable, then takes the auth-service down —
# the incident you roll back for, in which every gated request is denied — and
# shows, with a check after each part:
#
#   TRAP    flipping extAuthz.enabled back ALONE rolls nothing back. The jwt
#           route still exists, so the flipped control plane refuses every
#           snapshot (the CFG-1 guard) and never turns Ready, the old one keeps
#           serving ext_authz ON, and every gated request stays denied — a valid
#           token included. The flip is then undone, back to the cutover state.
#   REVERT  the full revert, in this order: remove the jwt routes provisioned
#           since the enable (ext_authz still ON, so the guard cannot fire), then
#           roll the control-plane release back to its pre-enable revision (old
#           image + extAuthz.enabled=false). The gateway then serves EXACTLY what
#           it served before the enable: the same xDS version (a pure function of
#           the config hash), acked by every edge-proxy, the same release values,
#           and the same answer to every request class.
#
# Tenant routes (auth_policy=none) are probed for the whole of both parts and
# must never be refused. The real-cluster rollback is
# docs/ext-authz-cutover-and-rollback.md §2.
#
#   make kind-rollback                  # == deploy/local/rollback.sh
#   KEEP_CLUSTER=1 make kind-rollback   # leave the cluster up afterwards
#   deploy/local/rollback.sh full_revert  # re-run named part(s) on a kept cluster
#
# Uses its own cluster name (edge-rollback) and refuses to start if it exists, so
# the teardown only ever deletes a cluster this run created.
set -euo pipefail
export CLUSTER_NAME="${CLUSTER_NAME:-edge-rollback}"
# Source cutover.sh (and through it up.sh) for its steps and checks without
# running any (its entry point runs each argument as a function; `:` is a no-op).
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cutover.sh" :

BEFORE="$LOCAL_DIR/.rollback-before"   # the pre-enable state, carried between parts
UMAIL="cutover@edge.local"             # the issuer user step4_enable creates
UPASS="cutover-password-12345"
TOK=""

cp_revision() { h status edge-control-plane -n "$INFRA_NS" -o json | jq -r .version; }
cp_image() { k -n "$INFRA_NS" get deploy edge-control-plane -o jsonpath='{.spec.template.spec.containers[0].image}'; }
cp_values() { h get values edge-control-plane -n "$INFRA_NS" -o json "$@" | jq -S -c .; }
before() { sed -n "s/^$1=//p" "$BEFORE"; }

mint_token() {  # a valid JWT from the in-cluster issuer (macOS curl cannot TLS to it)
  local tok="" i=0
  k -n "$INFRA_NS" exec deploy/edge-issuer -- /issuer adduser --email "$UMAIL" --password "$UPASS" --team eng >/dev/null 2>&1 || true
  k -n tenant-secure wait --for=condition=Ready pod/minter --timeout=120s >/dev/null
  while [ "$i" -lt 10 ]; do
    tok="$(k -n tenant-secure exec minter -- curl -sk --max-time 6 -X POST \
      "https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081/login" -H 'Content-Type: application/json' \
      -d "{\"email\":\"$UMAIL\",\"password\":\"$UPASS\"}" 2>/dev/null | jq -r '.access_token // empty' 2>/dev/null || true)"
    [ -n "$tok" ] && break
    i=$((i + 1)); sleep 2
  done
  [ -n "$tok" ] || die "could not mint a JWT from the issuer"
  printf '%s' "$tok"
}

# fleet_version — the published xDS version once every Ready edge-proxy has a
# stream and has acked it (empty if that does not happen within 40s).
fleet_version() {
  local want got="" i=0
  want="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o json \
    | jq '[.items[] | select(.metadata.deletionTimestamp == null)
           | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length')"
  while [ "$i" -lt 20 ]; do
    got="$(admin_get /admin/v1/nodes | jq -r --argjson n "$want" '.published_version as $v
      | if .active_streams == $n and .nodes_behind == 0 and ([.nodes[] | select(.acked_version != $v)] | length) == 0
        then $v else empty end' 2>/dev/null || true)"
    [ -n "$got" ] && break
    i=$((i + 1)); sleep 2
  done
  printf '%s' "$got"
}

# traffic <token> — the gateway's answer to every request class, on one line.
traffic() {
  printf 'tenant-a=%s tenant-b=%s secure=%s secure+garbage=%s secure+jwt=%s' \
    "$(gw_code tenant-a.local)" "$(gw_code tenant-b.local)" "$(gw_code secure.local)" \
    "$(gw_code secure.local -H 'Authorization: Bearer not-a-jwt')" \
    "$(gw_code secure.local -H "Authorization: Bearer $1")"
}

# gated_denied <label> — 10 rounds: every request to the jwt route is denied
# with 403 (fail-closed), whether it carries no token, garbage or a VALID JWT.
gated_denied() {
  local r none garbage valid
  for r in $(seq 1 10); do
    none="$(gw_code secure.local)"
    garbage="$(gw_code secure.local -H 'Authorization: Bearer not-a-jwt')"
    valid="$(gw_code secure.local -H "Authorization: Bearer $TOK")"
    [ "$none $garbage $valid" = "403 403 403" ] \
      || die "$1: a gated request was not denied (round $r): no-token=$none garbage=$garbage valid-JWT=$valid (want 403 403 403)"
  done
  ok "10/10 rounds: secure.local (jwt) no token / garbage / VALID JWT -> 403 / 403 / 403 — every gated request denied"
}

# ---- before the enable: the state the rollback must restore ----------------------
before_enable() {
  section "BEFORE — what the gateway serves just before the enable (the state the rollback must restore)"
  local rev img v t
  rev="$(cp_revision)"; img="$(cp_image)"
  [ "$(admin_get /admin/v1/config | jq -c .ext_authz.enabled)" = false ] || die "ext_authz is not off before the enable"
  v="$(fleet_version)"; [ -n "$v" ] || die "the fleet did not converge on one acked xDS version before the enable"
  t="$(traffic "$(mint_token)")"
  [ "$t" = "tenant-a=200 tenant-b=200 secure=404 secure+garbage=404 secure+jwt=404" ] \
    || die "unexpected pre-enable traffic: $t"
  printf 'rev=%s\nimage=%s\nversion=%s\ntraffic=%s\n' "$rev" "$img" "$v" "$t" > "$BEFORE"
  ok "control-plane release rev $rev ($img), ext_authz off, xDS $v acked by every edge-proxy"
  ok "traffic: $t"
}

# ---- the incident ------------------------------------------------------------------
incident() {
  section "INCIDENT — the auth-service goes down with ext_authz ON"
  [ -n "$TOK" ] || TOK="$(mint_token)"
  k -n "$INFRA_NS" scale deploy/auth-service --replicas=0 >/dev/null
  k -n "$INFRA_NS" wait --for=delete pod -l app.kubernetes.io/name=auth-service --timeout=60s >/dev/null 2>&1 || true
  served_within secure.local 403 15 || die "the gated route did not fail closed with the auth-service down ($(gw_code secure.local))"
  gated_denied "incident"
  tenants_200 "incident (auth_policy=none never calls the auth-service)"
}

# ---- the trap: flip the flag back alone --------------------------------------------
flip_back_alone() {
  section "TRAP — flip extAuthz.enabled back ALONE (the jwt route still exists)"
  [ -n "$TOK" ] || TOK="$(mint_token)"
  local rev_on; rev_on="$(cp_revision)"
  prober_start
  # No --wait: whether the flipped control plane ever turns Ready is what this measures.
  cp_release "$IMAGE_TAG" false >/dev/null
  sleep 45

  section "CHECK — the flip never takes effect, and the deny continues"
  local pods flipped serving logs
  pods="$(k -n "$INFRA_NS" get pod -l app.kubernetes.io/name=edge-control-plane -o json)"
  flipped="$(printf '%s' "$pods" | jq -r '[.items[] | select(.metadata.deletionTimestamp == null)
    | select(any(.spec.containers[0].env[]?; .name == "EXT_AUTHZ_ENABLED" and .value == "false"))][0].metadata.name // empty')"
  [ -n "$flipped" ] || die "no control-plane pod with EXT_AUTHZ_ENABLED=false — the flip was not applied"
  [ "$(printf '%s' "$pods" | jq -r --arg p "$flipped" '.items[] | select(.metadata.name == $p)
    | any(.status.conditions[]?; .type == "Ready" and .status == "True")')" = false ] \
    || die "the flipped control plane ($flipped) turned Ready with a jwt route present — the CFG-1 guard did not fire"
  logs="$(k -n "$INFRA_NS" logs "$flipped" --tail=200)"
  has "$logs" 'refusing to build snapshot' || die "the flipped control plane did not log the CFG-1 refusal: $logs"
  ok "the flipped control plane ($flipped) refuses every snapshot (CFG-1 guard) and never turns Ready"
  serving="$(cp_pod)"
  [ -n "$serving" ] && [ "$serving" != "$flipped" ] || die "no other control plane is serving (serving='$serving')"
  [ "$(admin_get /admin/v1/config | jq -c .ext_authz.enabled)" = true ] || die "the serving control plane does not report ext_authz on"
  ok "the serving control plane ($serving) is the old one, still ext_authz ON — the flip changed nothing the fleet runs"
  gated_denied "flip-back-alone"
  prober_stop "flip-back-alone"
  ok "FLIP-BACK-ALONE DENIES EVERYTHING GATED — no route is restored, the deny continues"

  section "undo the flip — back to the cutover state (control-plane release rev $rev_on)"
  h rollback edge-control-plane "$rev_on" -n "$INFRA_NS" --wait --timeout 240s
  local i=0
  while [ "$(k -n "$INFRA_NS" get pod -l app.kubernetes.io/name=edge-control-plane -o json \
      | jq '[.items[] | select(.metadata.deletionTimestamp == null)] | length')" != 1 ] && [ "$i" -lt 30 ]; do
    i=$((i + 1)); sleep 2
  done
  [ "$(admin_get /admin/v1/config | jq -c .ext_authz.enabled)" = true ] || die "undoing the flip did not restore ext_authz on"
  gated_denied "cutover state, incident ongoing"
}

# ---- the rollback: the full revert -------------------------------------------------
full_revert() {
  section "ROLLBACK — the full revert, from the cutover state, during the incident"
  [ -n "$TOK" ] || TOK="$(mint_token)"
  local rev; rev="$(before rev)"
  prober_start
  # 1. The routes that want auth go first, while ext_authz is still ON: the CFG-1
  #    guard only fires when ext_authz is off and such a route exists.
  drop_secure_route
  served_within secure.local 404 20 || die "removing the jwt route was not published (secure.local -> $(gw_code secure.local))"
  ok "1. jwt route removed while ext_authz is ON — published (secure.local -> 404)"
  # 2. The control-plane release back to its pre-enable revision: image and flag.
  h rollback edge-control-plane "$rev" -n "$INFRA_NS" --wait --timeout 240s
  ok "2. control-plane release rolled back to rev $rev"
  prober_stop "the rollback"

  section "CHECK — traffic exactly as before the enable"
  [ "$(cp_values)" = "$(cp_values --revision "$rev")" ] || die "release values differ from rev $rev: $(cp_values)"
  [ "$(cp_image)" = "$(before image)" ] || die "control-plane image is $(cp_image), was $(before image)"
  [ "$(admin_get /admin/v1/config | jq -c .ext_authz.enabled)" = false ] || die "ext_authz is not off after the rollback"
  ok "release values = rev $rev's, image $(cp_image), ext_authz.enabled=false"
  expect_auth_off_blocked "the rollback" 0
  local v r t
  v="$(fleet_version)"
  [ "$v" = "$(before version)" ] || die "xDS version is '$v', was $(before version) before the enable — the config is not the same"
  ok "xDS $v acked by every edge-proxy — the same version as before the enable, so the same config"
  for r in $(seq 1 10); do
    t="$(traffic "$TOK")"
    [ "$t" = "$(before traffic)" ] || die "traffic differs from before the enable (round $r): $t, was $(before traffic)"
  done
  ok "10/10 rounds: $t — exactly as before the enable"
  fleet_live rollback
  ok "ROLLBACK DONE — traffic exactly as before the enable, no tenant request refused on the way"
}

rehearse() {
  setup
  step0_committed
  step1_image_bump
  step2_auth_service
  step3_client_cert
  before_enable
  step4_enable
  incident
  flip_back_alone
  full_revert
}

if [ "$#" -gt 0 ]; then
  for _fn in "$@"; do "$_fn"; done
  exit 0
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  die "kind cluster '$CLUSTER_NAME' already exists — delete it (CLUSTER_NAME=$CLUSTER_NAME deploy/local/down.sh) or pick another CLUSTER_NAME"
fi
started="$(date +%s)"
teardown() {
  local rc=$?
  trap - EXIT
  [ -n "$PROBER_PID" ] && kill "$PROBER_PID" >/dev/null 2>&1 || true
  if [ "$rc" != 0 ] && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    section "rollback rehearsal FAILED (exit $rc) — cluster state before teardown"
    k get pods -A -o wide 2>/dev/null || true
    k get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -30 || true
  fi
  if [ "${KEEP_CLUSTER:-0}" = 1 ]; then
    warn "KEEP_CLUSTER=1 — leaving '$CLUSTER_NAME' up; delete it with: CLUSTER_NAME=$CLUSTER_NAME deploy/local/down.sh"
  else
    bash "$LOCAL_DIR/down.sh" || warn "teardown failed — delete it with: kind delete cluster --name $CLUSTER_NAME"
  fi
  rm -f "$STATE" "$BEFORE" "$LOCAL_DIR/.cutover-probe"
  if [ "$rc" = 0 ]; then
    ok "kind-rollback PASSED in $(( ($(date +%s) - started) / 60 )) min — flip-back-alone denied every gated request, the full revert restored the pre-enable traffic exactly, cluster removed"
  else
    printf '%s  X kind-rollback FAILED (exit %s)%s\n' "$C_RED" "$rc" "$C_RST" >&2
  fi
  exit "$rc"
}
trap teardown EXIT
rehearse
