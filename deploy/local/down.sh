#!/usr/bin/env bash
# down.sh — tear down the local edge-infra kind cluster (and everything in it).
#
# Usage:
#   deploy/local/down.sh
#   CLUSTER_NAME=foo deploy/local/down.sh
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
require_toolchain kind

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  section "deleting kind cluster '$CLUSTER_NAME'"
  kind delete cluster --name "$CLUSTER_NAME"
  ok "cluster '$CLUSTER_NAME' deleted"
else
  log "cluster '$CLUSTER_NAME' not present — nothing to do"
fi
