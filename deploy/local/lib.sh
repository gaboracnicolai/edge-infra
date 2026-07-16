#!/usr/bin/env bash
# lib.sh — shared config + helpers for the edge-infra LOCAL standup tooling.
#
# Sourced by up.sh / down.sh (and phase helpers). Sourcing has no side effects
# beyond defining variables and functions. Every knob is overridable via env so
# the standup is reproducible AND tweakable without editing tracked files.

# ---- repo layout (this file lives at <repo>/deploy/local/lib.sh) -------------
LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LOCAL_DIR/../.." && pwd)"

# ---- knobs -------------------------------------------------------------------
CLUSTER_NAME="${CLUSTER_NAME:-edge-local}"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
INFRA_NS="${INFRA_NS:-infra}"                 # all edge-infra services live here
IMAGE_TAG="${IMAGE_TAG:-local}"               # local image tag the charts point at

# Pinned dependency versions (fetched at run time, like any kind bootstrap).
# up.sh fails loudly if a URL is unreachable rather than standing up half a stack.
# Pinned for k8s 1.35 (kind 0.31 default node image) — newest that supports it.
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-}"        # empty => kind's default for this kind binary
CALICO_VERSION="${CALICO_VERSION:-v3.30.2}"
CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.20.0}"
KYVERNO_VERSION="${KYVERNO_VERSION:-v1.16.0}"

# In-cluster dev datastores (Phase 2) are dev-grade (ephemeral emptyDir, single
# replica). Their images are pinned in deploy/local/manifests/{postgres,nats}.yaml.

# ---- logging -----------------------------------------------------------------
if [ -t 1 ]; then
  C_BLUE=$'\033[1;34m'; C_GRN=$'\033[1;32m'; C_YEL=$'\033[1;33m'
  C_RED=$'\033[1;31m';  C_DIM=$'\033[2m';    C_RST=$'\033[0m'
else
  C_BLUE=; C_GRN=; C_YEL=; C_RED=; C_DIM=; C_RST=
fi
section() { printf '\n%s==> %s%s\n' "$C_BLUE" "$*" "$C_RST"; }
log()  { printf '%s  - %s%s\n' "$C_DIM" "$*" "$C_RST"; }
ok()   { printf '%s  OK %s%s\n' "$C_GRN" "$*" "$C_RST"; }
warn() { printf '%s  ! %s%s\n'  "$C_YEL" "$*" "$C_RST" >&2; }
die()  { printf '%s  X %s%s\n'   "$C_RED" "$*" "$C_RST" >&2; exit 1; }

# ---- guards ------------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not found on PATH"; }
require_toolchain() { local t; for t in "$@"; do need "$t"; done; }

# kubectl/helm pinned to OUR context — never touches the operator's other
# kube-contexts even though `kind create` flips current-context.
k() { kubectl --context "$KUBE_CONTEXT" "$@"; }
h() { helm --kube-context "$KUBE_CONTEXT" "$@"; }

# ---- waiters -----------------------------------------------------------------
# retry <tries> <sleep-seconds> <cmd...>
retry() { local n="$1" s="$2"; shift 2; local i; for ((i=1; i<=n; i++)); do "$@" && return 0; sleep "$s"; done; return 1; }

wait_nodes_ready() {
  section "waiting for all nodes Ready"
  k wait --for=condition=Ready nodes --all --timeout="${1:-240s}" \
    && ok "all nodes Ready" || die "nodes never became Ready (is the CNI installed?)"
}

# wait_rollout <kind/name> <ns> [timeout]
wait_rollout() { k -n "$2" rollout status "$1" --timeout="${3:-240s}"; }
