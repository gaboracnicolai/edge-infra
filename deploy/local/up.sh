#!/usr/bin/env bash
# up.sh — reproducible LOCAL standup for edge-infra on kind.
#
#   git clone  ->  deploy/local/up.sh  ->  a routable local gateway (two tenants).
#
# Idempotent + re-runnable: an existing cluster is reused, manifests re-apply as
# no-ops, secrets/certs are not duplicated. Phases run in order and each is
# guarded so a re-run resumes cleanly.
#
# Usage:
#   deploy/local/up.sh                    # run all implemented phases
#   CLUSTER_NAME=foo deploy/local/up.sh   # override the cluster name
#
# Phases (built incrementally; see deploy/local/README.md):
#   1  kind cluster (no default CNI) + Calico
#   2  cluster deps: cert-manager, Kyverno, Postgres, NATS
#   3  build local images (all 7 targets) + load into the cluster
#
# Run a single phase for iteration, e.g.:  deploy/local/up.sh phase3_images
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_toolchain docker kind kubectl helm jq openssl

# ---- Phase 1 — cluster + Calico ---------------------------------------------
phase1_cluster() {
  section "PHASE 1 — kind cluster '$CLUSTER_NAME' (default CNI disabled) + Calico"

  if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "cluster '$CLUSTER_NAME' already exists — reusing"
  else
    # NB: kept array-free for bash 3.2 (macOS default) — an empty "${arr[@]}"
    # trips `set -u` there.
    if [ -n "$KIND_NODE_IMAGE" ]; then
      kind create cluster --name "$CLUSTER_NAME" \
        --config "$LOCAL_DIR/kind-config.yaml" --image "$KIND_NODE_IMAGE"
    else
      kind create cluster --name "$CLUSTER_NAME" \
        --config "$LOCAL_DIR/kind-config.yaml"
    fi
    ok "cluster created"
  fi
  k version --request-timeout=10s >/dev/null 2>&1 || k cluster-info >/dev/null \
    || die "kubectl cannot reach context $KUBE_CONTEXT"

  # Calico enforces NetworkPolicy (kindnet does not). Nodes stay NotReady until
  # the CNI is up, so install BEFORE waiting on node readiness.
  if k get ds calico-node -n kube-system >/dev/null 2>&1; then
    log "Calico already installed — reusing"
  else
    section "installing Calico $CALICO_VERSION"
    k apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
  fi

  wait_nodes_ready 300s
  section "waiting for Calico control plane"
  k -n kube-system rollout status ds/calico-node --timeout=300s
  k -n kube-system rollout status deploy/calico-kube-controllers --timeout=300s
  ok "Calico running"
}

verify_phase1() {
  section "VERIFY Phase 1"
  k get nodes -o wide
  echo
  k get pods -n kube-system -l k8s-app=calico-node -o wide
  echo
  k get networkpolicies -A >/dev/null \
    && ok "NetworkPolicy API reachable — enforcement path is live" \
    || die "NetworkPolicy API not reachable"
  ok "Phase 1 verified"
}

# ---- Phase 2 — cluster dependencies -----------------------------------------
phase2_deps() {
  section "PHASE 2 — cluster deps (cert-manager, Kyverno, Postgres, NATS)"

  log "namespaces (infra, edge)"
  k apply -f "$LOCAL_DIR/manifests/namespaces.yaml"

  if k get deploy cert-manager -n cert-manager >/dev/null 2>&1; then
    log "cert-manager already installed — reusing"
  else
    section "installing cert-manager $CERT_MANAGER_VERSION"
    k apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
  fi
  section "waiting for cert-manager"
  k -n cert-manager wait --for=condition=Available deploy --all --timeout=300s
  ok "cert-manager ready"

  if k get crd clusterpolicies.kyverno.io >/dev/null 2>&1 \
     && k get deploy kyverno-admission-controller -n kyverno >/dev/null 2>&1; then
    log "Kyverno already installed — reusing"
  else
    section "installing Kyverno $KYVERNO_VERSION (server-side — its CRDs exceed the client-side annotation limit)"
    k apply --server-side --force-conflicts \
      -f "https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSION}/install.yaml"
  fi
  section "waiting for Kyverno (engine only — SEC-3 policies are a later run)"
  k -n kyverno wait --for=condition=Available deploy --all --timeout=300s
  ok "Kyverno ready"

  section "Postgres (dev, in $INFRA_NS)"
  k apply -f "$LOCAL_DIR/manifests/postgres.yaml"
  wait_rollout deploy/postgres "$INFRA_NS" 240s
  ok "Postgres ready"

  section "NATS (dev JetStream, in $INFRA_NS)"
  k apply -f "$LOCAL_DIR/manifests/nats.yaml"
  wait_rollout deploy/nats "$INFRA_NS" 240s
  ok "NATS ready"
}

verify_phase2() {
  section "VERIFY Phase 2"
  k get pods -n cert-manager
  echo
  k get pods -n kyverno
  echo
  k get pods,svc -n "$INFRA_NS" -l part-of=edge-local
  echo
  # Prove the shared DB actually accepts queries and both databases exist.
  local pgpod
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -tAc \
    "select 'edge db reachable, datnames='||string_agg(datname,',') from pg_database where datname in ('edge','issuer');" \
    && ok "Postgres serving; edge + issuer databases present"
  ok "Phase 2 verified"
}

# ---- Phase 3 — build + load local images ------------------------------------
# Extends `make docker-build-local` (which builds only server/osb/auth-service):
# builds ALL seven images the charts need and loads them into the kind nodes.
# The control-plane Dockerfile compiles its 5 Go binaries once in a shared builder
# layer, so issuer/ratelimit/secrets/migrate are cheap after `server`. Rust
# (auth-service) builds IN-container (BUILD_MODE=local) so the binary is linux/*,
# not the host's darwin/arm64.
phase3_images() {
  section "PHASE 3 — build local images (tag ':$IMAGE_TAG') + load into kind"

  section "control-plane Go binaries (server, issuer, ratelimit, secrets, migrate)"
  docker build -f "$REPO_ROOT/Dockerfile.control-plane" --target server \
    -t "edge-control-plane:$IMAGE_TAG" "$REPO_ROOT"
  local tgt
  for tgt in issuer ratelimit secrets migrate; do
    docker build -f "$REPO_ROOT/Dockerfile.control-plane" --target "$tgt" \
      -t "edge-$tgt:$IMAGE_TAG" "$REPO_ROOT"
  done

  section "edge-osb (Python) image"
  docker build -f "$REPO_ROOT/osb/Dockerfile" -t "edge-osb:$IMAGE_TAG" "$REPO_ROOT"

  section "auth-service (Rust, built in-container so the binary is linux)"
  docker build -f "$REPO_ROOT/auth-service/Dockerfile" \
    --build-arg BUILD_MODE=local -t "auth-service:$IMAGE_TAG" "$REPO_ROOT/auth-service"

  section "pulling public images (envoy, busybox)"
  docker pull "$ENVOY_IMAGE"
  docker pull "$BUSYBOX_IMAGE"

  section "kind load — importing images onto the cluster nodes"
  local img
  for img in \
    "edge-control-plane:$IMAGE_TAG" "edge-issuer:$IMAGE_TAG" \
    "edge-ratelimit:$IMAGE_TAG" "edge-secrets:$IMAGE_TAG" \
    "edge-migrate:$IMAGE_TAG" "edge-osb:$IMAGE_TAG" "auth-service:$IMAGE_TAG"; do
    kind load docker-image --name "$CLUSTER_NAME" "$img"
  done
  # Public images: best-effort (the node can still pull them at runtime).
  for img in "$ENVOY_IMAGE" "$BUSYBOX_IMAGE"; do
    kind load docker-image --name "$CLUSTER_NAME" "$img" \
      || warn "kind load $img failed — node will pull it at runtime"
  done
  ok "images built + loaded"
}

verify_phase3() {
  section "VERIFY Phase 3 — local images present on a worker node"
  docker exec "${CLUSTER_NAME}-worker" crictl images 2>/dev/null \
    | grep -E 'edge-(control-plane|issuer|ratelimit|secrets|migrate|osb)|auth-service|envoyproxy/envoy' \
    || die "expected local images not found on node ${CLUSTER_NAME}-worker"
  ok "Phase 3 verified"
}

main() {
  phase1_cluster
  verify_phase1
  phase2_deps
  verify_phase2
  phase3_images
  verify_phase3
  section "up.sh: Phases 1–3 complete."
}

# Entry: no args -> full standup; args -> run the named phase function(s) in order
# (e.g. `up.sh phase3_images verify_phase3` to re-run just Phase 3).
if [ "$#" -gt 0 ]; then
  for _fn in "$@"; do "$_fn"; done
else
  main
fi
