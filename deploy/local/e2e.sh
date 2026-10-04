#!/usr/bin/env bash
# e2e.sh — the self-host stack end to end, in one command, on a throwaway kind
# cluster: create the cluster, install every chart, prove each property (up.sh
# phases 1-15), and delete the cluster again whether the run passed or failed.
#
#   make kind-e2e                    # == deploy/local/e2e.sh
#   KEEP_CLUSTER=1 make kind-e2e     # leave the cluster up afterwards (debugging)
#
# It uses its own cluster name (edge-e2e, not up.sh's edge-local) and refuses to
# start if that cluster already exists, so the teardown can only ever delete a
# cluster this run created. Which page claim each phase proves:
# docs/self-host-claims.md.
set -euo pipefail
export CLUSTER_NAME="${CLUSTER_NAME:-edge-e2e}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_toolchain docker kind kubectl helm jq openssl curl

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  die "kind cluster '$CLUSTER_NAME' already exists — delete it (CLUSTER_NAME=$CLUSTER_NAME deploy/local/down.sh) or pick another CLUSTER_NAME"
fi

started="$(date +%s)"
teardown() {
  local rc=$?
  trap - EXIT
  if [ "$rc" != 0 ] && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    section "e2e FAILED (exit $rc) — cluster state before teardown"
    k get pods -A -o wide 2>/dev/null || true
    echo "  recent events:"
    k get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -30 || true
  fi
  if [ "${KEEP_CLUSTER:-0}" = 1 ]; then
    warn "KEEP_CLUSTER=1 — leaving '$CLUSTER_NAME' up; delete it with: CLUSTER_NAME=$CLUSTER_NAME deploy/local/down.sh"
  else
    bash "$LOCAL_DIR/down.sh" || warn "teardown failed — delete it with: kind delete cluster --name $CLUSTER_NAME"
  fi
  if [ "$rc" = 0 ]; then
    ok "kind-e2e PASSED in $(( ($(date +%s) - started) / 60 )) min — every phase of up.sh green, cluster removed"
  else
    printf '%s  X kind-e2e FAILED (exit %s)%s\n' "$C_RED" "$rc" "$C_RST" >&2
  fi
  exit "$rc"
}
trap teardown EXIT

bash "$LOCAL_DIR/up.sh"
