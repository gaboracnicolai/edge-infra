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
#   4  data-plane PKI (cert-manager Certificates)
#   5  admin PKI (bootstrap-pki.sh) + app secrets
#   6  migrate the shared DB (control-plane + OSB schemas)
#   7  deploy all charts with dev overlays, extAuthz OFF
#   8  seed two tenant backends + a gateway/route per tenant
#   9  prove routable: a request per tenant through the node :443 hostPort
#  10  SEC-3 Property 1 — Kyverno admission rejects open rules (red-first)
#  11  SEC-3 Property 2 — Calico drops the bypass hop, gateway stays allowed
#  12  CFG-1 flip + ext_authz LIVE — four properties, red-first, one at a time
#  13  R8 fail-static inconsistent-snapshot guard (live, red-first)
#  14  fail-static guard counters exported as metrics (live, red-first)
#  15  OSB broker answers; a service it provisions is served through Envoy
#  16  two nodes serve two tenants; each node's SDS holds only its own key (XDS-1)
#  17  the charts' NetworkPolicies refuse a pod outside the allowed flows (red-first)
#  18  a user created through SCIM signs in through OIDC (Dex as the IdP)
#
# One command for the whole thing, cluster created and deleted:  make kind-e2e
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

  # kind nodes share ONE subnet, so IPIP encapsulation is unnecessary — and it
  # actively breaks the SEC-3 gateway-allow: with ipipMode=Always, cross-node
  # hostNetwork traffic (the edge-proxy gateway) egresses via tunl0 and takes the
  # tunnel's POD-CIDR IP as source, which would NOT match a node-CIDR ipBlock allow.
  # CrossSubnet => native routing for same-subnet nodes => the node IP is preserved
  # as source (gateway matches NODE_CIDR), while pod sources stay real (the SEC-3
  # drop still bites). Applied here, before any workload, so every connection is
  # native from the start.
  if k get ippool default-ipv4-ippool >/dev/null 2>&1; then
    k patch ippool default-ipv4-ippool --type merge -p '{"spec":{"ipipMode":"CrossSubnet"}}' >/dev/null \
      && ok "Calico ipipMode=CrossSubnet (node-IP source preserved for same-subnet nodes)" \
      || warn "could not patch Calico IPPool to CrossSubnet"
  fi
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

# ---- Phase 4 — data-plane PKI (cert-manager Certificates) -------------------
phase4_dataplane_pki() {
  section "PHASE 4 — data-plane PKI (cert-manager Certificates)"
  # Order matters: selfSigned root -> CA ClusterIssuer -> leaves.
  section "root CA bootstrap (selfsigned-bootstrap -> edge-root-ca)"
  k apply -f "$REPO_ROOT/k8s/certs/root-ca-bootstrap.yaml"
  k -n cert-manager wait --for=condition=Ready certificate/edge-root-ca --timeout=180s

  section "edge-internal-ca ClusterIssuer"
  k apply -f "$REPO_ROOT/k8s/certs/cluster-issuer.yaml"
  k wait --for=condition=Ready clusterissuer/edge-internal-ca --timeout=120s

  section "leaf Certificates (4 in $INFRA_NS, 3 in edge)"
  local c
  for c in auth-service-cert control-plane-cert issuer-cert osb-client-cert \
           envoy-serving-cert envoy-xds-client-cert envoy-authz-client-cert; do
    k apply -f "$REPO_ROOT/k8s/certs/$c.yaml"
  done
  section "waiting for leaf Certificates Ready"
  k -n "$INFRA_NS" wait --for=condition=Ready certificate --all --timeout=180s
  k -n edge        wait --for=condition=Ready certificate --all --timeout=180s
  ok "all Certificates issued"
}

verify_phase4() {
  section "VERIFY Phase 4 — cert-manager minted every expected secret"
  local s ok_all=1
  for s in auth-service-tls-secret edge-cp-tls-secret issuer-tls-secret osb-client-tls-secret; do
    if k -n "$INFRA_NS" get secret "$s" >/dev/null 2>&1; then ok "$INFRA_NS/$s"; else warn "MISSING $INFRA_NS/$s"; ok_all=0; fi
  done
  for s in envoy-serving-tls-secret envoy-xds-client-tls-secret envoy-authz-client-tls-secret; do
    if k -n edge get secret "$s" >/dev/null 2>&1; then ok "edge/$s"; else warn "MISSING edge/$s"; ok_all=0; fi
  done
  [ "$ok_all" = 1 ] || die "some cert-manager secrets are missing"
  ok "Phase 4 verified"
}

# ---- Phase 5 — admin PKI (bootstrap-pki.sh) + app secrets -------------------
phase5_secrets() {
  section "PHASE 5 — admin PKI + app secrets"
  local PKI="$LOCAL_DIR/.pki-bootstrap"

  # 1. Admin-plane PKI material — reuse if already generated so the KEK stays
  #    stable across re-runs (the control-plane must share it with the custodian).
  if [ -f "$PKI/admin-ca.crt" ] && [ -f "$PKI/server.crt" ] \
     && [ -f "$PKI/server.key" ] && [ -f "$PKI/secret_kek.b64" ]; then
    log "reusing admin PKI material in .pki-bootstrap"
  else
    section "generating admin PKI (scripts/bootstrap-pki.sh)"
    rm -rf "$PKI"
    # Redirect stdout: the banner echoes the KEK — keep it out of logs.
    EDGE_NAMESPACE="$INFRA_NS" bash "$REPO_ROOT/scripts/bootstrap-pki.sh" "$PKI" >/dev/null
  fi
  local KEK; KEK="$(cat "$PKI/secret_kek.b64")"

  # 2. Issuer RSA signing key (kid=k1) — reuse if present. activeKid is set in the
  #    Phase-7 issuer overlay to match.
  [ -f "$PKI/k1.pem" ] || openssl genrsa -out "$PKI/k1.pem" 2048 2>/dev/null

  # DSNs — sslmode=disable locally (prod uses TLS). One shared 'edge' DB for
  # control-plane + osb + secrets; issuer has its own 'issuer' DB.
  local PGH="postgres.${INFRA_NS}.svc.cluster.local"
  local SHARED_DSN="postgres://postgres:edgedevpass@${PGH}:5432/edge?sslmode=disable"
  local OSB_DSN="postgresql://postgres:edgedevpass@${PGH}:5432/edge?sslmode=disable"
  local ISSUER_DSN="postgres://postgres:edgedevpass@${PGH}:5432/issuer?sslmode=disable"
  local ISSUER_URL="https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081"
  local AUD="edge-gateway"

  section "app + custodian secrets in $INFRA_NS"
  # control-plane: shared-DB DSN (key 'dsn') + SECRET_KEK
  apply_secret "$INFRA_NS" generic edge-control-plane-postgres \
    --from-literal=dsn="$SHARED_DSN" \
    --from-literal=SECRET_KEK="$KEK"

  # edge-osb: same shared DB + NATS. ALLOW_UNTENANTED lets the broker boot with
  # zero tenant_api_keys (dev); DB/NATS TLS is turned off via the Phase-7 overlay.
  apply_secret "$INFRA_NS" generic edge-osb-secrets \
    --from-literal=DATABASE_URL="$OSB_DSN" \
    --from-literal=DB_SSL_MODE="disable" \
    --from-literal=NATS_URL="nats://nats.${INFRA_NS}.svc.cluster.local:4222" \
    --from-literal=ALLOW_UNTENANTED="true"

  # edge-issuer: its own DB + iss/aud (self-migrated by the chart's migrate Job).
  # SCIM + OIDC sign-in are on from the start: the IdP (Dex, Phase 18) is
  # discovered on first sign-in, so the issuer boots without it.
  apply_secret "$INFRA_NS" generic issuer-secrets \
    --from-literal=ISSUER_URL="$ISSUER_URL" \
    --from-literal=ISSUER_AUDIENCE="$AUD" \
    --from-literal=ISSUER_DATABASE_URL="$ISSUER_DSN" \
    --from-literal=ISSUER_SCIM_TOKEN="$SCIM_TOKEN" \
    --from-literal=ISSUER_OIDC_ISSUER="https://dex.${INFRA_NS}.svc.cluster.local:5556/dex" \
    --from-literal=ISSUER_OIDC_CLIENT_ID="edge-issuer" \
    --from-literal=ISSUER_OIDC_CLIENT_SECRET="local-dev-dex-client-secret" \
    --from-literal=ISSUER_OIDC_REDIRECT_URL="${ISSUER_URL}/sso/callback"
  apply_secret "$INFRA_NS" generic issuer-signing-keys \
    --from-file=k1.pem="$PKI/k1.pem"

  # auth-service: JWKS -> issuer (https + SAN match); iss/aud match; >=16-char secret.
  apply_secret "$INFRA_NS" generic auth-service-secrets \
    --from-literal=JWKS_URL="${ISSUER_URL}/.well-known/jwks.json" \
    --from-literal=JWT_ISSUER="$ISSUER_URL" \
    --from-literal=JWT_AUDIENCE="$AUD" \
    --from-literal=GATEWAY_AUTH_SECRET="local-dev-gateway-auth-secret-0123456789"

  # edge-secrets custodian (out-of-band admin PKI from bootstrap-pki.sh).
  apply_secret "$INFRA_NS" generic edge-admin-ca \
    --from-file=ca.crt="$PKI/admin-ca.crt"
  apply_secret "$INFRA_NS" tls edge-secrets-tls \
    --cert="$PKI/server.crt" --key="$PKI/server.key"
  apply_secret "$INFRA_NS" generic edge-secrets-config \
    --from-literal=SECRET_KEK="$KEK" \
    --from-literal=SECRETS_DATABASE_URL="$SHARED_DSN" \
    --from-literal=SECRETS_ADMIN_API_KEY="local-dev-admin-key"

  ok "secrets created"
}

verify_phase5() {
  section "VERIFY Phase 5 — all referenced app secrets exist in $INFRA_NS"
  local s ok_all=1
  for s in edge-control-plane-postgres edge-osb-secrets issuer-secrets \
           issuer-signing-keys auth-service-secrets edge-admin-ca \
           edge-secrets-tls edge-secrets-config; do
    if k -n "$INFRA_NS" get secret "$s" >/dev/null 2>&1; then ok "$s"; else warn "MISSING $s"; ok_all=0; fi
  done
  [ "$ok_all" = 1 ] || die "some app secrets are missing"
  ok "Phase 5 verified"
}

# ---- Phase 6 — migrate the shared DB ----------------------------------------
phase6_migrate() {
  section "PHASE 6 — migrate the shared 'edge' DB (control-plane + OSB schemas)"
  # Job is not re-appliable once complete; recreate it (migrate is idempotent).
  k -n "$INFRA_NS" delete job edge-migrate-shared --ignore-not-found >/dev/null 2>&1 || true
  k apply -f "$LOCAL_DIR/manifests/migrate-job.yaml"
  section "waiting for the migrate Job to complete"
  if ! k -n "$INFRA_NS" wait --for=condition=complete job/edge-migrate-shared --timeout=180s 2>/dev/null; then
    warn "migrate Job did not report complete — logs:"
    k -n "$INFRA_NS" logs job/edge-migrate-shared || true
    die "migrate Job failed"
  fi
  k -n "$INFRA_NS" logs job/edge-migrate-shared | tail -25
  ok "migrations applied"
}

verify_phase6() {
  section "VERIFY Phase 6 — schema present in the shared 'edge' DB"
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  echo "  public tables:"
  k exec -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -tAc \
    "select string_agg(table_name, ', ' order by table_name) from information_schema.tables where table_schema='public';"
  local core
  core="$(k exec -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -tAc \
    "select count(*) from information_schema.tables where table_schema='public' and table_name in ('gateways','routes','clusters','endpoints');" | tr -d '[:space:]')"
  [ "$core" = "4" ] || die "core routing tables missing (gateways/routes/clusters/endpoints found: $core/4)"
  ok "Phase 6 verified (control-plane + OSB schema present)"
}

# ---- Phase 7 — deploy all charts (extAuthz OFF) -----------------------------
# helm_install <release> <namespace> — chart default values.yaml is implicit;
# layer the dev overlay then the local overlay (each if present). --wait blocks
# until Ready so the next chart's dependency is satisfied.
helm_install() {
  local rel="$1" ns="$2" suffix
  suffix="${rel#edge-}"
  local chart="$REPO_ROOT/deploy/helm/$rel"
  local dev="$REPO_ROOT/deploy/envs/dev/values-${suffix}.yaml"
  local loc="$LOCAL_DIR/values/values-${suffix}.yaml"
  section "helm upgrade --install $rel -> ns/$ns"
  # Clear a prior stuck/failed release (e.g. a hook that timed out) so a re-run
  # proceeds cleanly instead of erroring on "another operation in progress".
  local st
  st="$(h status "$rel" -n "$ns" -o json 2>/dev/null | jq -r '.info.status // empty' 2>/dev/null || true)"
  case "$st" in
    pending-install|pending-upgrade|pending-rollback|failed|uninstalling)
      warn "clearing prior '$st' release $rel"
      h uninstall "$rel" -n "$ns" >/dev/null 2>&1 || true
      k -n "$ns" delete job "${rel}-migrate" --ignore-not-found >/dev/null 2>&1 || true ;;
  esac
  set -- upgrade --install "$rel" "$chart" -n "$ns" --create-namespace
  if [ -f "$dev" ]; then set -- "$@" -f "$dev"; fi
  if [ -f "$loc" ]; then set -- "$@" -f "$loc"; fi
  set -- "$@" --wait --timeout "${HELM_TIMEOUT:-300s}"
  h "$@"
}

diag_fail() {  # <release> <ns> — dump why a chart didn't come up, then stop.
  warn "deploy failed for $1 (ns $2) — diagnostics:"
  k -n "$2" get pods -o wide 2>/dev/null || true
  echo "  recent events:"
  k -n "$2" get events --sort-by=.lastTimestamp 2>/dev/null | tail -15 || true
  die "chart $1 failed to become Ready"
}

phase7_deploy() {
  section "PHASE 7 — deploy charts (dev overlays, extAuthz OFF)"
  # The local overlays switch the charts' NetworkPolicies on with the gateway
  # (hostNetwork edge-proxy) allowed from 172.16.0.0/12. A node outside it
  # would be cut off from the control-plane, so stop here rather than later.
  local nip
  for nip in $(k get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}' | grep -E '^[0-9.]+$'); do
    in_gateway_cidr "$nip" || die "node IP $nip is outside 172.16.0.0/12, the gateway CIDR in deploy/local/values — set networkPolicy.gatewayCIDRs to this cluster's node network"
  done
  # Order encodes dependencies: control-plane (xDS) first; issuer before
  # auth-service (which fetches the issuer JWKS at startup); proxy after the
  # control-plane is serving xDS.
  helm_install edge-control-plane "$INFRA_NS" || diag_fail edge-control-plane "$INFRA_NS"
  helm_install edge-issuer        "$INFRA_NS" || diag_fail edge-issuer "$INFRA_NS"
  helm_install auth-service       "$INFRA_NS" || diag_fail auth-service "$INFRA_NS"
  helm_install edge-osb           "$INFRA_NS" || diag_fail edge-osb "$INFRA_NS"
  helm_install edge-proxy         edge        || diag_fail edge-proxy edge
  # Auxiliary charts (not on the routing path). Best-effort so the run isn't
  # blocked if a custodian/RLS detail needs tuning.
  helm_install edge-ratelimit "$INFRA_NS" || warn "edge-ratelimit not Ready (auxiliary — continuing)"
  helm_install edge-secrets   "$INFRA_NS" || warn "edge-secrets not Ready (auxiliary — continuing)"
  ok "charts deployed"
}

verify_phase7() {
  section "VERIFY Phase 7 — services Ready + Envoy connected to control-plane"
  k get pods -n "$INFRA_NS" -o wide
  echo; k get pods -n edge -o wide
  echo
  # Envoy admin is localhost-only in the pod (R7); reach it via a short-lived
  # port-forward and confirm the xDS connection is up.
  local ep
  ep="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$ep" ] || ep="$(k -n edge get pod -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [ -n "$ep" ]; then
    section "edge-proxy admin ($ep) — xDS link + received config"
    # kubectl directly (see envoy_config_dump): a backgrounded k() leaks the forward.
    kubectl --context "$KUBE_CONTEXT" -n edge port-forward "pod/$ep" 19001:9901 >/dev/null 2>&1 &
    local pf=$!; sleep 3
    echo "  control_plane connection (1 = connected):"
    curl -s --max-time 5 http://127.0.0.1:19001/stats 2>/dev/null \
      | grep -E 'control_plane\.(connected_state|identifier)' | sed 's/^/    /' || true
    echo "  received listeners / clusters:"
    curl -s --max-time 5 http://127.0.0.1:19001/config_dump 2>/dev/null \
      | jq -r '[.configs[]?.dynamic_listeners[]?]|length as $l|null|"    dynamic_listeners=\($l)"' 2>/dev/null || true
    curl -s --max-time 5 http://127.0.0.1:19001/config_dump 2>/dev/null \
      | jq -r '[.configs[]?.dynamic_active_clusters[]?]|length as $c|null|"    dynamic_active_clusters=\($c)"' 2>/dev/null || true
    kill "$pf" >/dev/null 2>&1 || true; wait "$pf" 2>/dev/null || true
  fi
  ok "Phase 7 verified (all required charts Ready via --wait)"
}

# ---- Phase 8 — seed two tenants (backends + gateway/route) -------------------
phase8_seed() {
  section "PHASE 8 — seed two tenant backends + a gateway/route per tenant"
  # Preload the echo image (a tag, so kind load works), then the two backends.
  if docker pull "$ECHO_IMAGE" >/dev/null 2>&1; then
    kind load docker-image --name "$CLUSTER_NAME" "$ECHO_IMAGE" >/dev/null 2>&1 || true
  else
    warn "echo image not preloaded — nodes will pull at runtime"
  fi
  k apply -f "$LOCAL_DIR/manifests/tenants.yaml"
  wait_rollout deploy/echo tenant-a 120s
  wait_rollout deploy/echo tenant-b 120s

  local ipA ipB pgpod
  ipA="$(k -n tenant-a get svc echo -o jsonpath='{.spec.clusterIP}')"
  ipB="$(k -n tenant-b get svc echo -o jsonpath='{.spec.clusterIP}')"
  [ -n "$ipA" ] && [ -n "$ipB" ] || die "could not resolve echo Service ClusterIPs"
  log "tenant-a echo=$ipA:5678   tenant-b echo=$ipB:5678"

  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  section "seeding gateway 'local-gw' (HTTP :443) + 2 host-routes (auth_policy=none)"
  # This is the missing route source. Direct SQL (a tiny seed helper) mirrors
  # translator.apply_create's columns but: (1) a plaintext-HTTP listener on :443
  # to match the node hostPort, (2) upstream DECOUPLED from the match host (echo
  # ClusterIP), and (3) auth_policy='none' — MANDATORY, since the xDS reconciler
  # is fail-closed and withholds the WHOLE snapshot if any route wants auth while
  # ext_authz is off.
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -f - <<SQL
BEGIN;
INSERT INTO gateways (id, name, port, protocol, node_selector)
VALUES ('local-gw','local-gw',443,'HTTP','{}'::jsonb)
ON CONFLICT (name) DO UPDATE SET port=EXCLUDED.port, protocol=EXCLUDED.protocol, updated_at=now();

INSERT INTO clusters (id,name) VALUES ('tenant-a','tenant-a') ON CONFLICT (name) DO NOTHING;
DELETE FROM endpoints WHERE cluster_id='tenant-a';
INSERT INTO endpoints (id,cluster_id,address,port,weight) VALUES ('tenant-a-0','tenant-a','${ipA}',5678,1);
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('tenant-a','tenant-a','local-gw',ARRAY['tenant-a.local']::text[],'/','tenant-a',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,
  cluster_name=EXCLUDED.cluster_name,timeout_seconds=EXCLUDED.timeout_seconds,auth_policy=EXCLUDED.auth_policy,updated_at=now(),deleted_at=NULL;

INSERT INTO clusters (id,name) VALUES ('tenant-b','tenant-b') ON CONFLICT (name) DO NOTHING;
DELETE FROM endpoints WHERE cluster_id='tenant-b';
INSERT INTO endpoints (id,cluster_id,address,port,weight) VALUES ('tenant-b-0','tenant-b','${ipB}',5678,1);
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('tenant-b','tenant-b','local-gw',ARRAY['tenant-b.local']::text[],'/','tenant-b',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,
  cluster_name=EXCLUDED.cluster_name,timeout_seconds=EXCLUDED.timeout_seconds,auth_policy=EXCLUDED.auth_policy,updated_at=now(),deleted_at=NULL;
COMMIT;
SQL
  ok "routes seeded in Postgres"
}

verify_phase8() {
  section "VERIFY Phase 8 — routes in Postgres AND published to Envoy"
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  echo "  routes (Postgres):"
  k exec -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -tAc \
    "select r.name||': host='||array_to_string(r.hosts,',')||' -> '||r.cluster_name||' (auth='||r.auth_policy||') on '||g.name||':'||g.port||'/'||g.protocol from routes r join gateways g on g.id=r.gateway_id where r.deleted_at is null order by 1;" \
    | sed 's/^/    /'

  # Reconciler polls Postgres every ~5s; wait for the snapshot to reach Envoy.
  local ep dump i=0
  ep="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{.items[0].metadata.name}')"
  while [ "$i" -lt 10 ]; do
    dump="$(envoy_config_dump "$ep")"
    if has "$dump" tenant-a && has "$dump" tenant-b; then break; fi
    i=$((i + 1)); sleep 2
  done
  echo "  Envoy listeners:"
  printf '%s' "$dump" | jq -r '.configs[]?.dynamic_listeners[]?.active_state.listener | "    "+(.name//"?")+" on :"+((.address.socket_address.port_value//0)|tostring)' 2>/dev/null | sort -u || true
  echo "  Envoy clusters:"
  printf '%s' "$dump" | jq -r '.configs[]?.dynamic_active_clusters[]?.cluster.name | "    "+.' 2>/dev/null | sort -u || true
  echo "  Envoy vhost domains (Host match):"
  printf '%s' "$dump" | jq -r '.configs[]?.dynamic_route_configs[]?.route_config.virtual_hosts[]?.domains[]? | "    "+.' 2>/dev/null | sort -u || true
  if has "$dump" tenant-a && has "$dump" tenant-b; then
    ok "both tenant routes published to Envoy (control-plane -> xDS)"
  else
    die "Envoy config_dump does not show both tenant routes"
  fi
}

# ---- Phase 9 — prove routable ------------------------------------------------
phase9_prove() {
  local hp="${GATEWAY_HOST_PORT:-443}"
  section "PHASE 9 — PROVE ROUTABLE (each tenant via node :$hp hostPort, ext_authz OFF)"
  local i=0 ca cb a b cn
  # Retry briefly: the :443 listener may land a beat after the clusters.
  while [ "$i" -lt 10 ]; do
    ca="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: tenant-a.local' "http://127.0.0.1:${hp}/" 2>/dev/null || true)"
    cb="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: tenant-b.local' "http://127.0.0.1:${hp}/" 2>/dev/null || true)"
    [ "$ca" = 200 ] && [ "$cb" = 200 ] && break
    i=$((i + 1)); sleep 3
  done
  a="$(curl -s --max-time 6 -H 'Host: tenant-a.local' "http://127.0.0.1:${hp}/" 2>/dev/null || true)"
  b="$(curl -s --max-time 6 -H 'Host: tenant-b.local' "http://127.0.0.1:${hp}/" 2>/dev/null || true)"
  cn="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: nope.local' "http://127.0.0.1:${hp}/" 2>/dev/null || true)"
  echo "  http://127.0.0.1:${hp}/  -H 'Host: tenant-a.local'  ->  HTTP $ca   body: $(printf '%s' "$a" | tr -d '\n')"
  echo "  http://127.0.0.1:${hp}/  -H 'Host: tenant-b.local'  ->  HTTP $cb   body: $(printf '%s' "$b" | tr -d '\n')"
  echo "  http://127.0.0.1:${hp}/  -H 'Host: nope.local'      ->  HTTP $cn   (expect 404 — no route)"
  local pass=1
  { [ "$ca" = 200 ] && has "$a" TENANT-A-BACKEND; } || pass=0
  { [ "$cb" = 200 ] && has "$b" TENANT-B-BACKEND; } || pass=0
  [ "$pass" = 1 ] || die "ROUTABLE PROOF FAILED — see the responses above"
  ok "ROUTABLE: tenant-a.local & tenant-b.local each return 200 from their OWN backend, ext_authz OFF"
}

# ---- Phase 10 — SEC-3 Property 1: Kyverno admission (red-first) --------------
phase10_sec3_admission() {
  section "PHASE 10 — SEC-3 Property 1: Kyverno admission rejects open rules (red-first)"
  section "applying Kyverno guardrails (Enforce)"
  k apply -f "$REPO_ROOT/k8s/policies/disallow-open-intra-namespace-ingress.yaml"
  k apply -f "$REPO_ROOT/k8s/policies/disallow-public-backend-services.yaml"
  k wait --for=condition=Ready clusterpolicy/disallow-open-intra-namespace-ingress --timeout=120s 2>/dev/null || true
  k wait --for=condition=Ready clusterpolicy/disallow-public-backend-services   --timeout=120s 2>/dev/null || true

  # RED-A (required): an ingress `from` with an EMPTY podSelector ({}) = every pod
  # in the namespace — the exact lateral-movement hole. Must be DENIED at admission.
  local bad; bad="$(mktemp)"
  cat > "$bad" <<'NP'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: sec3-red-open-ingress, namespace: tenant-a }
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {}
NP
  section "RED — an open (podSelector {}) NetworkPolicy MUST be DENIED"
  local denied="" i=0 out
  while [ "$i" -lt 20 ]; do
    out="$(k apply -f "$bad" 2>&1 || true)"
    if has "$out" denied || has "$out" disallow-open-intra-namespace-ingress; then denied="$out"; break; fi
    k -n tenant-a delete networkpolicy sec3-red-open-ingress --ignore-not-found >/dev/null 2>&1 || true
    i=$((i + 1)); sleep 3
  done
  rm -f "$bad"
  [ -n "$denied" ] || die "guardrail NOT live: the open-podSelector NetworkPolicy was ADMITTED"
  echo "  Kyverno denial:"; printf '%s\n' "$denied" | fold -s -w 96 | sed 's/^/    /'
  ok "RED proven — Kyverno DENIED the open-podSelector NetworkPolicy"

  # RED-B (supporting): a NodePort backend Service bypasses the gateway → DENIED.
  local svc; svc="$(mktemp)"
  cat > "$svc" <<'SVC'
apiVersion: v1
kind: Service
metadata: { name: sec3-red-public, namespace: tenant-a }
spec:
  type: NodePort
  selector: { app: echo }
  ports: [{ port: 5678, targetPort: 5678 }]
SVC
  section "RED (supporting) — a NodePort backend Service MUST be DENIED"
  out="$(k apply -f "$svc" 2>&1 || true)"; rm -f "$svc"
  if has "$out" denied || has "$out" disallow-public-backend-services; then
    echo "  Kyverno denial:"; printf '%s\n' "$out" | fold -s -w 96 | sed 's/^/    /'
    ok "RED (supporting) proven — Kyverno DENIED the NodePort Service"
  else
    k -n tenant-a delete service sec3-red-public --ignore-not-found >/dev/null 2>&1 || true
    warn "NodePort not denied — continuing (the required NetworkPolicy guardrail is proven)"
  fi
  ok "Phase 10 (Property 1) verified"
}

# ---- Phase 11 — SEC-3 Property 2: Calico data-plane (red-first) --------------
phase11_sec3_dataplane() {
  section "PHASE 11 — SEC-3 Property 2: Calico drops the bypass hop, gateway allowed (red-first)"

  # NODE_CIDR = the kind docker network IPv4 subnet (the hostNetwork edge-proxy's
  # source). Take the IPv4 line only (kind also has an IPv6 subnet).
  local NODE_CIDR pfx
  NODE_CIDR="$(docker network inspect kind --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/' | head -1)"
  [ -n "$NODE_CIDR" ] || die "could not compute NODE_CIDR from docker network 'kind'"
  pfx="$(printf '%s' "$NODE_CIDR" | cut -d/ -f1 | cut -d. -f1-2)"
  log "NODE_CIDR=$NODE_CIDR  (/16 prefix '$pfx')  echo backend port=5678"

  section "verify edge-proxy node IPs fall INSIDE NODE_CIDR (else gateway-allow won't match)"
  local ip ok_nodes=1
  for ip in $(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{range .items[*]}{.status.hostIP}{"\n"}{end}' | sort -u); do
    if in_cidr16 "$pfx" "$ip"; then ok "edge-proxy node $ip ∈ $NODE_CIDR"; else warn "edge-proxy node $ip ∉ $NODE_CIDR"; ok_nodes=0; fi
  done
  [ "$ok_nodes" = 1 ] || die "an edge-proxy node IP is outside NODE_CIDR — the gateway-allow would not match"

  section "deploy attacker (pod-network pod, neutral ns)"
  if docker pull "$ATTACKER_IMAGE" >/dev/null 2>&1; then
    kind load docker-image --name "$CLUSTER_NAME" "$ATTACKER_IMAGE" >/dev/null 2>&1 || true
  else warn "attacker image not preloaded — node will pull at runtime"; fi
  k apply -f "$LOCAL_DIR/manifests/sec3-attacker.yaml"
  wait_rollout deploy/attacker sec3-attacker 120s
  local atk_ip
  atk_ip="$(k -n sec3-attacker get pod -l app=attacker -o jsonpath='{.items[0].status.podIP}')"
  [ -n "$atk_ip" ] || die "attacker pod has no IP"
  if in_cidr16 "$pfx" "$atk_ip"; then die "attacker IP $atk_ip is INSIDE NODE_CIDR — it would be allowed; proof invalid"; fi
  ok "attacker pod IP $atk_ip ∉ NODE_CIDR $NODE_CIDR — a genuine pod-network source"

  local ipA ipB
  ipA="$(k -n tenant-a get svc echo -o jsonpath='{.spec.clusterIP}')"
  ipB="$(k -n tenant-b get svc echo -o jsonpath='{.spec.clusterIP}')"
  log "tenant-a echo ClusterIP=$ipA:5678   tenant-b echo ClusterIP=$ipB:5678"

  # TRUE red baseline every run: remove any backend NetworkPolicies first.
  section "RED baseline — delete any existing backend NetworkPolicies"
  k -n tenant-a delete networkpolicy --all --ignore-not-found >/dev/null 2>&1 || true
  k -n tenant-b delete networkpolicy --all --ignore-not-found >/dev/null 2>&1 || true
  sleep 2

  section "RED — attacker → each backend DIRECTLY (gateway bypass) MUST succeed"
  local ra rb
  ra="$(attacker_get "$ipA" 5678)"; rb="$(attacker_get "$ipB" 5678)"
  echo "  attacker($atk_ip) -> tenant-a $ipA:5678  =>  $ra"
  echo "  attacker($atk_ip) -> tenant-b $ipB:5678  =>  $rb"
  { has "$ra" code=200 && has "$ra" TENANT-A-BACKEND; } || die "RED baseline broken: attacker couldn't reach tenant-a with no policy"
  { has "$rb" code=200 && has "$rb" TENANT-B-BACKEND; } || die "RED baseline broken: attacker couldn't reach tenant-b with no policy"
  ok "RED proven — with NO backend policy the bypass hop is OPEN (200 from each backend)"

  # Resolve the template locally (NOT by editing k8s/policies): backend-ns -> each
  # tenant, NODE_CIDR computed, ipBlock port = the REAL echo port 5678, intra-ns
  # from/ports block DROPPED (a bare echo has no legitimate intra-ns client).
  section "apply resolved backend policy (default-deny + allow ipBlock $NODE_CIDR:5678) to tenant-a, tenant-b"
  local ns
  for ns in tenant-a tenant-b; do
    k apply -f - <<NP
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny-ingress, namespace: $ns, labels: { part-of: edge-local, sec3: "true" } }
spec:
  podSelector: {}
  policyTypes: [Ingress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: allow-from-gateway, namespace: $ns, labels: { part-of: edge-local, sec3: "true" } }
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - ipBlock: { cidr: $NODE_CIDR }
      ports:
        - { protocol: TCP, port: 5678 }
NP
  done
  ok "backend policy applied (also Property 1 GREEN: the ipBlock policy is ADMITTED, not denied)"
  sleep 3   # let Calico program the rules

  # Converge: default-deny programs a beat before allow-from-gateway, so the
  # gateway path can 503 briefly right after apply. Wait until BOTH the drop and
  # the allow hold, then assert them SEPARATELY below.
  section "GREEN — waiting for Calico to converge (attacker dropped AND gateway allowed)"
  local i=0 ga gb ca cb
  while [ "$i" -lt 20 ]; do
    ga="$(attacker_get "$ipA" 5678)"; gb="$(attacker_get "$ipB" 5678)"
    ca="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H 'Host: tenant-a.local' http://127.0.0.1:443/ 2>/dev/null || true)"
    cb="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H 'Host: tenant-b.local' http://127.0.0.1:443/ 2>/dev/null || true)"
    if has "$ga" code=000 && has "$gb" code=000 && [ "$ca" = 200 ] && [ "$cb" = 200 ]; then break; fi
    i=$((i + 1)); sleep 2
  done

  # (a) the bypass DROP — proven on its own.
  section "GREEN (a) — attacker bypass DROPPED (flip from the RED success)"
  echo "  attacker($atk_ip) -> tenant-a $ipA:5678  =>  $ga"
  echo "  attacker($atk_ip) -> tenant-b $ipB:5678  =>  $gb"
  has "$ga" code=000 || die "tenant-a bypass NOT dropped (expected timeout) — got: $ga"
  has "$gb" code=000 || die "tenant-b bypass NOT dropped (expected timeout) — got: $gb"
  ok "GREEN DROP proven — the cross-tenant bypass FLIPPED 200 -> dropped for BOTH tenants"

  # (b) the gateway path preserved — a SEPARATE assertion (never combined with the drop).
  section "GREEN (b) — gateway path (node :443) still ALLOWED"
  local ba bb
  ba="$(curl -s --max-time 6 -H 'Host: tenant-a.local' http://127.0.0.1:443/ 2>/dev/null || true)"
  bb="$(curl -s --max-time 6 -H 'Host: tenant-b.local' http://127.0.0.1:443/ 2>/dev/null || true)"
  echo "  gateway :443 Host tenant-a.local => HTTP $ca  $ba"
  echo "  gateway :443 Host tenant-b.local => HTTP $cb  $bb"
  { [ "$ca" = 200 ] && has "$ba" TENANT-A-BACKEND; } || die "gateway path to tenant-a BROKE under the policy (HTTP $ca)"
  { [ "$cb" = 200 ] && has "$bb" TENANT-B-BACKEND; } || die "gateway path to tenant-b BROKE under the policy (HTTP $cb)"
  ok "GREEN ALLOW proven — gateway :443 still 200 from each backend (source node IP ∈ NODE_CIDR, allowed on :5678)"

  section "confirm echo pods stay Ready under the policy (kubelet probes ride the node IP)"
  k -n tenant-a rollout status deploy/echo --timeout=40s
  k -n tenant-b rollout status deploy/echo --timeout=40s
  ok "Phase 11 (Property 2) verified"
}

# ---- Phase 12 — CFG-1 flip + ext_authz LIVE (four properties, red-first) -----
# helm_set_extauthz <true|false> — flip ext_authz LIVE via --set (the committed
# local overlay stays enabled:false — base-off + deliberate flip, the real launch
# model). helm only rolls the control-plane when the value actually changes.
helm_set_extauthz() {
  section "helm: ext_authz enabled=$1 (LIVE --set flip; overlay stays off)"
  h upgrade edge-control-plane "$REPO_ROOT/deploy/helm/edge-control-plane" -n "$INFRA_NS" \
    -f "$REPO_ROOT/deploy/envs/dev/values-control-plane.yaml" \
    -f "$LOCAL_DIR/values/values-control-plane.yaml" \
    --set extAuthz.enabled="$1" --wait --timeout 200s
  # The control-plane's snapshot version counter is per-process (non-HA), so it
  # RESETS to v1 when the control-plane rolls on a flip. A still-connected
  # edge-proxy that holds a higher version then rejects the new push as stale
  # (cds/lds update_failure; the config silently never applies). A FRESH
  # edge-proxy connection has no prior version and applies it cleanly — so roll
  # edge-proxy after every flip.
  section "roll edge-proxy for a fresh xDS connection (avoid the version-reset collision)"
  k -n edge rollout restart ds/edge-proxy >/dev/null
  k -n edge rollout status ds/edge-proxy --timeout=120s
}

# seed_secure_route / drop_secure_route — the secure.local (auth_policy='jwt')
# route -> whoami, mirroring phase8's direct SQL. $1 = whoami ClusterIP (seed only).
drop_secure_route() {
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -f - <<'SQL' >/dev/null
DELETE FROM routes    WHERE name='secure-whoami';
DELETE FROM endpoints WHERE cluster_id='secure-whoami';
DELETE FROM clusters  WHERE name='secure-whoami';
SQL
}
seed_secure_route() {
  local wip="$1" pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -f - <<SQL >/dev/null
INSERT INTO clusters (id,name) VALUES ('secure-whoami','secure-whoami') ON CONFLICT (name) DO NOTHING;
DELETE FROM endpoints WHERE cluster_id='secure-whoami';
INSERT INTO endpoints (id,cluster_id,address,port,weight) VALUES ('secure-whoami-0','secure-whoami','${wip}',80,1);
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('secure-whoami','secure-whoami','local-gw',ARRAY['secure.local']::text[],'/','secure-whoami',30,'jwt',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,
  cluster_name=EXCLUDED.cluster_name,timeout_seconds=EXCLUDED.timeout_seconds,auth_policy=EXCLUDED.auth_policy,updated_at=now(),deleted_at=NULL;
SQL
}

phase12_extauthz_cutover() {
  section "PHASE 12 — CFG-1 flip + ext_authz LIVE (four properties, red-first)"
  local AUD="edge-gateway"   # issuer ISSUER_AUDIENCE == auth-service JWT_AUDIENCE (Phase 5)
  local ISS="https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081"  # iss == JWT_ISSUER

  # ---- reset to a clean PRE-FLIP state (idempotent re-runs) ----
  section "reset — remove secure.local + ensure ext_authz OFF (safe: no jwt route present)"
  drop_secure_route
  helm_set_extauthz false
  retry 20 2 sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 -H 'Host: tenant-a.local' http://127.0.0.1:443/)\" = 200 ]" \
    && ok "pre-flip baseline serving (ext_authz OFF, none-routes up)" || die "pre-flip baseline not serving"

  # ---- PREREQ GATE — the deny-all trap (flip ONLY if BOTH pass) ----
  section "PREREQ GATE — deny-all-trap (flip only if BOTH pass, else STOP)"
  k -n "$INFRA_NS" wait --for=condition=Available deploy/auth-service --timeout=60s >/dev/null 2>&1 \
    || die "PREREQ FAIL: auth-service not Available (JWKS-at-boot would have failed it)"
  local eps; eps="$(k -n "$INFRA_NS" get endpoints auth-service -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)"
  [ -n "$eps" ] || die "PREREQ FAIL: auth-service Service has no ready endpoints (:50051 unreachable)"
  ok "(1) auth-service Ready + endpoints [$eps]; Ready ⇒ JWKS-at-boot succeeded (it fails to boot otherwise)"
  k -n edge exec "$(ep_pod)" -- ls -l /etc/authz-client-tls/ca.crt >/dev/null 2>&1 \
    && ok "(2) edge-proxy has /etc/authz-client-tls/ca.crt mounted (mTLS caFile present)" \
    || die "PREREQ FAIL: edge-proxy lacks /etc/authz-client-tls/ca.crt — flipping renders plaintext ⇒ deny-all"

  # ---- header-reflecting backend ----
  section "deploy whoami (header-reflecting backend for secure.local)"
  if docker pull "$WHOAMI_IMAGE" >/dev/null 2>&1; then kind load docker-image --name "$CLUSTER_NAME" "$WHOAMI_IMAGE" >/dev/null 2>&1 || true; fi
  k apply -f "$LOCAL_DIR/manifests/secure-backend.yaml"
  wait_rollout deploy/whoami tenant-secure 120s
  local wip; wip="$(k -n tenant-secure get svc whoami -o jsonpath='{.spec.clusterIP}')"
  [ -n "$wip" ] || die "whoami ClusterIP unresolved"
  log "whoami ClusterIP=$wip:80"

  # ================= PROPERTY 4 — CFG-1 config-time guard (red-first, BEFORE flip) ==========
  section "PROPERTY 4 (red-first) — CFG-1 guard REFUSES the jwt route while ext_authz OFF"
  local before_ver; before_ver="$(envoy_config_dump "$(ep_pod)" | jq -r '[.configs[]?.dynamic_route_configs[]?.version_info]|sort|join(",")' 2>/dev/null)"
  log "Envoy route-config version(s) BEFORE seeding secure.local: ${before_ver:-<none>}"
  seed_secure_route "$wip"
  sleep 10   # reconciler polls every ~5s; let it hit the guard
  echo "  control-plane refusal log:"
  k -n "$INFRA_NS" logs deploy/edge-control-plane --tail=80 2>/dev/null \
    | grep -aiE 'refusing to build snapshot|auth_policy != none' | tail -2 | sed 's/^/    /' \
    || die "P4 FAIL: no control-plane refusal log — the guard did not fire"
  local dump after_ver
  dump="$(envoy_config_dump "$(ep_pod)")"
  after_ver="$(printf '%s' "$dump" | jq -r '[.configs[]?.dynamic_route_configs[]?.version_info]|sort|join(",")' 2>/dev/null)"
  log "Envoy route-config version(s) AFTER: ${after_ver:-<none>}"
  has "$dump" secure.local && die "P4 FAIL: secure.local present in Envoy — an auth-wanting route is served OPEN"
  [ "$before_ver" = "$after_ver" ] && ok "Envoy snapshot version did NOT advance (${after_ver})" \
    || warn "route-config version changed ($before_ver -> $after_ver) — but secure.local absent (below)"
  local p4c; p4c="$(gw_code secure.local)"
  [ "$p4c" != 200 ] || die "P4 FAIL: secure.local served 200 while ext_authz OFF (open identity listener)"
  ok "P4 GREEN — control-plane refused; secure.local ABSENT from Envoy + not served ($p4c); tenant-a still $(gw_code tenant-a.local) (last-good retained)"

  # ================= THE FLIP ==========
  section "THE FLIP — ext_authz ON (live)"
  helm_set_extauthz true
  # Wait until it is published AND gated on the gateway that serves :443 (no
  # token => 401), and assert on that same result: edge-proxy has just rolled, so
  # a second, separate dump can land on the other pod before its snapshot does.
  local i=0 flipped=0
  while [ "$i" -lt 25 ]; do
    if has "$(envoy_config_dump "$(ep_pod)")" secure.local && [ "$(gw_code secure.local)" = 401 ]; then flipped=1; break; fi
    i=$((i + 1)); sleep 2
  done
  [ "$flipped" = 1 ] || die "FLIP FAIL: secure.local not published (and gated, 401 without a token) after enabling ext_authz"
  ok "FLIP done — ext_authz ON; secure.local published (now gated by ext_authz)"

  # ================= PROPERTY 1 — valid JWT -> 200 + trusted injection (red-first) ==========
  section "PROPERTY 1 (red-first) — valid JWT → 200 + TRUSTED header injection"
  local UMAIL="dev@edge.local" UPASS="devpassword-abc12345"
  k -n "$INFRA_NS" exec deploy/edge-issuer -- /issuer adduser --email "$UMAIL" --password "$UPASS" --team eng >/dev/null 2>&1 \
    && log "created issuer user $UMAIL" || log "issuer user $UMAIL already exists (adduser idempotent)"
  # Mint from the in-cluster OpenSSL curl pod (macOS system curl is LibreSSL and
  # cannot handshake the issuer). Reaches edge-issuer.infra directly over TLS.
  k -n tenant-secure wait --for=condition=Ready pod/minter --timeout=60s >/dev/null 2>&1 || true
  local TOK="" mi=0
  while [ "$mi" -lt 10 ]; do
    TOK="$(k -n tenant-secure exec minter -- curl -sk --max-time 6 -X POST \
      "https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081/login" \
      -H 'Content-Type: application/json' -d "{\"email\":\"$UMAIL\",\"password\":\"$UPASS\"}" 2>/dev/null \
      | jq -r '.access_token // empty' 2>/dev/null || true)"
    { [ -n "$TOK" ] && [ "$TOK" != null ]; } && break
    mi=$((mi + 1)); sleep 2
  done
  { [ -n "$TOK" ] && [ "$TOK" != null ]; } || die "P1 FAIL: could not mint a JWT via POST /login"
  ok "minted a real JWT via /login (aud=$AUD iss=$ISS; token len ${#TOK})"

  local c1 b1
  c1="$(gw_code secure.local -H "Authorization: Bearer $TOK")"
  b1="$(gw_body secure.local -H "Authorization: Bearer $TOK")"
  [ "$c1" = 200 ] || die "P1 FAIL: valid JWT did not yield 200 (got $c1)"
  local low; low="$(printf '%s' "$b1" | tr 'A-Z' 'a-z')"
  local hdr
  for hdr in x-user-id x-user-email x-auth-iss x-gateway-auth; do
    has "$low" "$hdr" || die "P1 FAIL: injected header '$hdr' absent from whoami reflection"
  done
  has "$low" "$UMAIL" || die "P1 FAIL: whoami did not reflect the JWT-derived email $UMAIL"
  echo "  secure.local + valid JWT -> HTTP $c1; whoami reflected injected headers:"
  printf '%s\n' "$b1" | grep -iE 'X-User-Id|X-User-Teams|X-User-Email|X-Auth-Iss|X-Gateway-Auth' | sed 's/^/    /'
  ok "P1 GREEN — 200 + x-user-id/x-user-email/x-auth-iss/x-gateway-auth injected (JWT-derived)"

  section "P1 anti-spoof — a client-forged x-user-email MUST be overwritten"
  local bsp lsp
  bsp="$(gw_body secure.local -H "Authorization: Bearer $TOK" -H 'x-user-email: attacker@evil.com')"
  lsp="$(printf '%s' "$bsp" | tr 'A-Z' 'a-z')"
  has "$lsp" 'attacker@evil.com' && die "P1 FAIL: forged x-user-email SURVIVED (client value not overwritten)"
  has "$lsp" "$UMAIL" || die "P1 FAIL: JWT email missing after the spoof attempt"
  echo "  forged 'x-user-email: attacker@evil.com' -> whoami shows: $(printf '%s' "$bsp" | grep -iE 'X-User-Email' | head -1 | sed 's/^ *//')"
  ok "P1 anti-spoof GREEN — whoami shows the JWT email ($UMAIL); the forged attacker@evil.com was stripped"

  local cc; cc="$(gw_code tenant-a.local)"
  [ "$cc" = 200 ] || die "P1 FAIL: control tenant-a.local (none) not 200 (got $cc)"
  ok "P1 control — tenant-a.local (auth_policy=none) with NO token still 200"

  # ================= PROPERTY 2 — no/invalid JWT -> 401 (red-first) ==========
  section "PROPERTY 2 (red-first) — no / invalid JWT → 401"
  local c_none c_garbage
  c_none="$(gw_code secure.local)"
  c_garbage="$(gw_code secure.local -H 'Authorization: Bearer not-a-jwt')"
  echo "  secure.local, no Authorization -> HTTP $c_none"
  echo "  secure.local, garbage token    -> HTTP $c_garbage"
  [ "$c_none" = 401 ]    || die "P2 FAIL: no-token got $c_none (expected 401)"
  [ "$c_garbage" = 401 ] || die "P2 FAIL: garbage token got $c_garbage (expected 401)"
  ok "P2 GREEN — secure.local without a valid JWT → 401 (no-token AND garbage)"

  # ================= PROPERTY 3 — auth-service down -> fail-closed deny (red-first) ==========
  section "PROPERTY 3 (red-first) — auth-service DOWN → fail-closed deny (failure_mode_allow:false)"
  k -n "$INFRA_NS" scale deploy/auth-service --replicas=0 >/dev/null
  k -n "$INFRA_NS" wait --for=delete pod -l app.kubernetes.io/name=auth-service --timeout=60s >/dev/null 2>&1 || true
  sleep 3
  local c_down; c_down="$(gw_code secure.local -H "Authorization: Bearer $TOK")"
  echo "  secure.local + VALID JWT, auth-service DOWN -> HTTP $c_down"
  [ "$c_down" != 200 ] || die "P3 FAIL: served 200 with auth-service DOWN — this would be fail-OPEN"
  ok "P3 GREEN — with auth-service down, even a VALID JWT is DENIED ($c_down), never served (fail-closed)"

  section "P3 recovery — scale auth-service back to 1"
  k -n "$INFRA_NS" scale deploy/auth-service --replicas=1 >/dev/null
  k -n "$INFRA_NS" rollout status deploy/auth-service --timeout=120s
  local j=0 c_rec
  while [ "$j" -lt 25 ]; do c_rec="$(gw_code secure.local -H "Authorization: Bearer $TOK")"; [ "$c_rec" = 200 ] && break; j=$((j + 1)); sleep 2; done
  echo "  secure.local + VALID JWT, auth-service back -> HTTP $c_rec"
  [ "$c_rec" = 200 ] || die "P3 FAIL: did not recover to 200 after auth-service returned (got $c_rec)"
  ok "P3 recovery — auth-service back → secure.local + valid JWT → 200 again"

  section "Phase 12 end state — ext_authz ON, secure.local(jwt) + tenant-a/b(none) all serving"
  echo "    secure.local (jwt, valid token) -> HTTP $(gw_code secure.local -H "Authorization: Bearer $TOK")"
  echo "    tenant-a.local (none, no token) -> HTTP $(gw_code tenant-a.local)"
  echo "    tenant-b.local (none, no token) -> HTTP $(gw_code tenant-b.local)"
  ok "Phase 12 (all four ext_authz properties) verified"
}

# ---- Phase 13 — R8 fail-static inconsistent-snapshot guard (live) -----------
# drop_ghost_route removes the injected dangling route (idempotent).
drop_ghost_route() {
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 \
    -c "DELETE FROM routes WHERE name='r8-ghost';" >/dev/null
}

phase13_inconsistent_guard() {
  section "PHASE 13 — R8 fail-static inconsistent-snapshot guard (live, red-first)"
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  drop_ghost_route   # clean any prior injection (idempotent)

  # RED baseline: a HEALTHY snapshot is serving (last-good exists); capture Envoy's
  # route-config version so we can prove it does NOT advance.
  section "RED baseline — tenant-a/b serve 200; capture Envoy route-config version"
  local ca cb; ca="$(gw_code tenant-a.local)"; cb="$(gw_code tenant-b.local)"
  { [ "$ca" = 200 ] && [ "$cb" = 200 ]; } || die "R8 baseline broken: tenant-a/b not both 200 ($ca/$cb)"
  local before_ver; before_ver="$(envoy_config_dump "$(ep_pod)" | jq -r '[.configs[]?.dynamic_route_configs[]?.version_info]|sort|join(",")' 2>/dev/null)"
  log "tenant-a=$ca tenant-b=$cb ; Envoy route-config version BEFORE: ${before_ver:-<none>}"

  # Inject the inconsistency the guard reliably catches AND the data path can
  # produce: a route -> a cluster with NO clusters row (dangling RDS->CDS, which
  # Envoy's Consistent() misses but the widened R8 check blocks). auth_policy='none'
  # so CFG-1 does NOT also fire. Injected AFTER a healthy snapshot exists.
  section "inject a dangling route (r8-ghost -> a nonexistent cluster) via the data path"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -f - <<'SQL' >/dev/null
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('r8-ghost','r8-ghost','local-gw',ARRAY['r8-ghost.local']::text[],'/','r8-ghost-cluster-absent',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET cluster_name=EXCLUDED.cluster_name,auth_policy=EXCLUDED.auth_policy,deleted_at=NULL,updated_at=now();
SQL
  sleep 10   # let the reconciler poll (~5s) + hit the guard

  # GREEN (fail-static, LIVE): the control-plane REFUSED — its log carries the
  # refusal + blocked_total (the InconsistentSnapshotsBlocked counter); Envoy's
  # route-config version did not advance; the bad route is ABSENT from Envoy;
  # tenant-a/b STILL serve 200.
  section "GREEN — control-plane REFUSED; last-good retained"
  echo "  control-plane refusal log (carries blocked_total = the counter):"
  k -n "$INFRA_NS" logs deploy/edge-control-plane --tail=120 2>/dev/null \
    | grep -aiE 'refusing to publish inconsistent snapshot|absent from CDS|blocked_total' | tail -1 | sed 's/^/    /' \
    || die "R8 FAIL: no 'refusing to publish inconsistent snapshot' log — the guard did not fire (control-plane lacks the R8 widening?)"
  local dump after_ver
  dump="$(envoy_config_dump "$(ep_pod)")"
  after_ver="$(printf '%s' "$dump" | jq -r '[.configs[]?.dynamic_route_configs[]?.version_info]|sort|join(",")' 2>/dev/null)"
  log "Envoy route-config version AFTER: ${after_ver:-<none>}"
  has "$dump" r8-ghost && die "R8 FAIL: the dangling route r8-ghost IS in Envoy — the inconsistent snapshot was published"
  [ "$before_ver" = "$after_ver" ] && ok "Envoy route-config version did NOT advance ($after_ver)" \
    || warn "route-config version changed ($before_ver -> $after_ver) — but r8-ghost is absent (asserted above)"
  local ca2 cb2; ca2="$(gw_code tenant-a.local)"; cb2="$(gw_code tenant-b.local)"
  { [ "$ca2" = 200 ] && [ "$cb2" = 200 ]; } || die "R8 FAIL: tenant-a/b broke under the inconsistent snapshot ($ca2/$cb2)"
  ok "GREEN — r8-ghost ABSENT from Envoy; version unchanged; tenant-a=$ca2 tenant-b=$cb2 (last-good served)"

  # Clean up so the phase leaves a consistent, re-runnable state.
  section "cleanup — remove the dangling route; confirm the reconciler resumes"
  drop_ghost_route
  local i=0
  while [ "$i" -lt 15 ]; do [ "$(gw_code tenant-a.local)" = 200 ] && break; i=$((i + 1)); sleep 2; done
  ok "Phase 13 (R8 inconsistent guard) verified — cleaned up; tenant-a/b serving"
}

# ---- Phase 14 — fail-static guard counters exported as metrics (live) --------
# inject_ghost_route inserts the dangling route (r8-ghost -> a nonexistent
# cluster) via the data path so the reconciler's inconsistent-snapshot guard
# trips. Same injection phase 13 uses; paired with drop_ghost_route.
inject_ghost_route() {
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -f - <<'SQL' >/dev/null
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('r8-ghost','r8-ghost','local-gw',ARRAY['r8-ghost.local']::text[],'/','r8-ghost-cluster-absent',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET cluster_name=EXCLUDED.cluster_name,auth_policy=EXCLUDED.auth_policy,deleted_at=NULL,updated_at=now();
SQL
}

# cp_scrape — the control-plane's /metrics text (fail-static guard counters) via a
# short-lived port-forward to :2112 (the port the edge-control-plane chart declares
# and Prometheus scrapes). Plain HTTP, so host curl (macOS LibreSSL) is fine.
# Port-forward routes through the API server, so SEC-3 NetworkPolicies don't apply.
# Echoes the exposition; empty on failure.
cp_scrape() {
  local lp="${CP_METRICS_LP:-12112}" pid out i=0
  k -n "$INFRA_NS" port-forward deploy/edge-control-plane "${lp}:2112" >/dev/null 2>&1 &
  pid=$!
  while [ "$i" -lt 20 ]; do
    out="$(curl -s --max-time 4 "http://127.0.0.1:${lp}/metrics" 2>/dev/null || true)"
    [ -n "$out" ] && break
    i=$((i + 1)); sleep 1
  done
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" 2>/dev/null || true
  printf '%s' "$out"
}

# blocked_of <metrics-text> <reason> — value of the
# xds_snapshots_blocked_total{reason="<reason>"} series in the given exposition
# (empty if the series is absent). The {reason=...} match skips the # HELP/# TYPE
# lines, and the tiny doc makes the pipe SIGPIPE-safe.
blocked_of() {
  printf '%s\n' "$1" | grep -F "xds_snapshots_blocked_total{reason=\"$2\"}" | awk '{print $NF}' | tail -1
}

phase14_failstatic_metrics() {
  section "PHASE 14 — fail-static guard counters exported as metrics (live, red-first)"
  drop_ghost_route   # clean slate

  # The metrics endpoint must be LIVE on :2112 — before this change nothing bound
  # it, so the chart's already-configured Prometheus scrape got connection-refused.
  section "scrape the control-plane /metrics on :2112 (the chart's declared scrape target)"
  local m0; m0="$(cp_scrape)"
  [ -n "$m0" ] || die "PHASE14 FAIL: /metrics on :2112 returned nothing — the metrics server is not serving (connection refused?)"
  has "$m0" "xds_snapshots_blocked_total" || die "PHASE14 FAIL: xds_snapshots_blocked_total absent from the live /metrics"
  echo "  live fail-static series:"; printf '%s\n' "$m0" | grep -F "xds_snapshots_blocked_total{" | sed 's/^/    /'

  # RED baseline: capture the inconsistent-reason counter on the running process.
  local before; before="$(blocked_of "$m0" inconsistent)"
  [ -n "$before" ] || die "PHASE14 FAIL: the inconsistent series is absent (it must exist from t=0)"
  log "baseline  xds_snapshots_blocked_total{reason=\"inconsistent\"} = $before"

  # Trip the guard on the ACTUAL control-plane: inject a dangling route
  # (auth_policy=none so CFG-1 does not also fire). The reconciler withholds the
  # publish and increments the counter each poll while it is present.
  section "inject a dangling route (r8-ghost -> absent cluster) to trip the guard"
  inject_ghost_route
  sleep 10   # reconciler poll (~5s) + guard trip

  # GREEN: the exported counter ROSE on the live control-plane.
  section "GREEN — the exported counter ROSE (prod can alert on this)"
  local m1 after; m1="$(cp_scrape)"; after="$(blocked_of "$m1" inconsistent)"
  [ -n "$after" ] || die "PHASE14 FAIL: could not read the inconsistent counter after injection"
  log "after     xds_snapshots_blocked_total{reason=\"inconsistent\"} = $after"
  awk -v a="$before" -v b="$after" 'BEGIN{exit !(b>a)}' \
    || { drop_ghost_route; die "PHASE14 FAIL: the inconsistent counter did NOT rise ($before -> $after) — the metric is not wired to the guard"; }
  ok "GREEN — xds_snapshots_blocked_total{reason=\"inconsistent\"} rose $before -> $after on the live control-plane"

  # Cleanup so the phase leaves a consistent, re-runnable state.
  section "cleanup — remove the dangling route; confirm serving resumes"
  drop_ghost_route
  local i=0
  while [ "$i" -lt 15 ]; do [ "$(gw_code tenant-a.local)" = 200 ] && break; i=$((i + 1)); sleep 2; done
  ok "Phase 14 (fail-static metrics) verified — cleaned up; tenant-a/b serving"
}

# ---- Phase 15 — the OSB broker answers, and its provision is served ---------
# The tenant key the broker resolves to team 'e2e' (stored hashed, as in prod).
OSB_KEY="${OSB_KEY:-local-e2e-osb-tenant-key-0123456789}"
OSB_TEAM="e2e"
OSB_SERVICE="e2e-stub"

# osb_call <METHOD> <path> [json-body] — call the broker API (plain HTTP in the
# cluster) through a short-lived port-forward, as the 'e2e' tenant. Echoes
# "<http_code> <body>"; the code is 000 if the broker never answered.
osb_call() {
  local m="$1" path="$2" data="${3:-}" lp="${OSB_LP:-18080}" pid out code=000 i=0
  k -n "$INFRA_NS" port-forward svc/edge-osb "${lp}:8080" >/dev/null 2>&1 &
  pid=$!
  while [ "$i" -lt 20 ]; do
    if [ -n "$data" ]; then
      out="$(curl -s --max-time 6 -w '\n%{http_code}' -X "$m" -H "Authorization: Bearer $OSB_KEY" \
        -H 'Content-Type: application/json' -d "$data" "http://127.0.0.1:${lp}${path}" 2>/dev/null || true)"
    else
      out="$(curl -s --max-time 6 -w '\n%{http_code}' -X "$m" -H "Authorization: Bearer $OSB_KEY" \
        "http://127.0.0.1:${lp}${path}" 2>/dev/null || true)"
    fi
    code="$(printf '%s\n' "$out" | tail -1)"
    [ -n "$code" ] && [ "$code" != 000 ] && break
    i=$((i + 1)); sleep 1
  done
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" 2>/dev/null || true
  printf '%s %s' "${code:-000}" "$(printf '%s\n' "$out" | sed '$d')"
}

# osb_wait_completed <request_id> — poll the broker until the worker has applied
# the request (COMPLETED); dies on FAILED or after ~90s.
osb_wait_completed() {
  local rid="$1" i=0 r st=""
  while [ "$i" -lt 45 ]; do
    r="$(osb_call GET "/v1/requests/$rid")"
    st="$(printf '%s' "${r#* }" | jq -r '.status // empty' 2>/dev/null || true)"
    case "$st" in
      COMPLETED) ok "request $rid COMPLETED by the OSB worker"; return 0 ;;
      FAILED) die "PHASE15 FAIL: request $rid FAILED — $(printf '%s' "${r#* }" | jq -r '.error // empty')" ;;
    esac
    i=$((i + 1)); sleep 2
  done
  die "PHASE15 FAIL: request $rid never completed (last status '${st:-<none>}', last answer: $r)"
}

# gw80_code / gw80_body <host> — a request through the gateway's shared HTTP
# listener (node :80), where OSB-provisioned HTTP services land.
gw80_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H "Host: $1" http://127.0.0.1:80/ 2>/dev/null || true; }
gw80_body() { curl -s --max-time 6 -H "Host: $1" http://127.0.0.1:80/ 2>/dev/null || true; }

phase15_osb_broker() {
  section "PHASE 15 — the OSB broker answers; a service it provisions is served through Envoy"
  local pgpod; pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"

  section "register the 'e2e' tenant API key (stored as its SHA-256, never in the clear)"
  local kh; kh="$(printf '%s' "$OSB_KEY" | openssl dgst -sha256 -r | cut -d' ' -f1)"
  k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -c \
    "INSERT INTO tenant_api_keys (key_hash, team) VALUES ('$kh', '$OSB_TEAM') ON CONFLICT (key_hash) DO UPDATE SET team = EXCLUDED.team;" >/dev/null
  ok "tenant key registered for team '$OSB_TEAM'"

  section "deploy the stub upstream (osb-stub/echo -> OSB-PROVISIONED-BACKEND)"
  k apply -f "$LOCAL_DIR/manifests/osb-stub.yaml"
  wait_rollout deploy/echo osb-stub 120s
  local sip; sip="$(k -n osb-stub get svc echo -o jsonpath='{.spec.clusterIP}')"
  [ -n "$sip" ] || die "osb-stub echo ClusterIP unresolved"
  log "stub upstream ClusterIP=$sip:5678 (also the Host the provisioned route matches)"

  section "the broker answers — GET /healthz"
  local r; r="$(osb_call GET /healthz)"
  echo "  GET /healthz -> HTTP ${r%% *}  ${r#* }"
  [ "${r%% *}" = 200 ] && has "$r" '"ok":true' || die "PHASE15 FAIL: the broker did not answer /healthz (got: $r)"
  ok "edge-osb answers"

  # Clean slate for re-runs: a prior run may have left the service provisioned.
  r="$(osb_call DELETE "/v1/services/$OSB_SERVICE")"
  if [ "${r%% *}" = 202 ]; then
    log "removing a leftover '$OSB_SERVICE' from a prior run"
    osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  fi

  section "RED — before provisioning, Host $sip is NOT served on :80"
  local c0; c0="$(gw80_code "$sip")"
  echo "  :80 Host $sip -> HTTP $c0"
  [ "$c0" != 200 ] || die "PHASE15 FAIL: Host $sip already served 200 before the broker provisioned it — the proof would be vacuous"
  ok "RED proven — not served ($c0)"

  section "POST /v1/services — provision '$OSB_SERVICE' (HTTP, auth_policy=none) -> the stub"
  r="$(osb_call POST /v1/services \
    "{\"name\":\"$OSB_SERVICE\",\"team\":\"$OSB_TEAM\",\"host\":\"$sip\",\"port\":5678,\"protocol\":\"HTTP\",\"auth_policy\":\"none\"}")"
  echo "  POST /v1/services -> HTTP ${r%% *}  ${r#* }"
  [ "${r%% *}" = 202 ] || die "PHASE15 FAIL: provision not accepted (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"

  section "GREEN — the provisioned service is served through Envoy on :80"
  local i=0 c1="" b1=""
  while [ "$i" -lt 30 ]; do
    c1="$(gw80_code "$sip")"
    [ "$c1" = 200 ] && break
    i=$((i + 1)); sleep 2
  done
  b1="$(gw80_body "$sip")"
  echo "  :80 Host $sip -> HTTP $c1  body: $(printf '%s' "$b1" | tr -d '\n')"
  { [ "$c1" = 200 ] && has "$b1" OSB-PROVISIONED-BACKEND; } \
    || die "PHASE15 FAIL: the provisioned service is not served by the stub through Envoy (HTTP $c1)"
  has "$(envoy_config_dump "$(ep_pod)")" "osb-${OSB_TEAM}-${OSB_SERVICE}" \
    || die "PHASE15 FAIL: Envoy has no osb-${OSB_TEAM}-${OSB_SERVICE} cluster/route"
  ok "GREEN — broker -> NATS -> worker -> Postgres -> control-plane -> xDS -> Envoy -> stub: 200 OSB-PROVISIONED-BACKEND"

  section "DELETE /v1/services/$OSB_SERVICE — deprovision, and the route goes away"
  r="$(osb_call DELETE "/v1/services/$OSB_SERVICE")"
  echo "  DELETE /v1/services/$OSB_SERVICE -> HTTP ${r%% *}  ${r#* }"
  [ "${r%% *}" = 202 ] || die "PHASE15 FAIL: deprovision not accepted (got: $r)"
  osb_wait_completed "$(printf '%s' "${r#* }" | jq -r '.request_id')"
  i=0
  local c2=""
  while [ "$i" -lt 30 ]; do
    c2="$(gw80_code "$sip")"
    [ "$c2" != 200 ] && break
    i=$((i + 1)); sleep 2
  done
  echo "  :80 Host $sip -> HTTP $c2"
  [ "$c2" != 200 ] || die "PHASE15 FAIL: still served 200 after deprovision"
  ok "Phase 15 (OSB broker) verified — provisioned, served, deprovisioned"
}

# ---- Phase 16 — each node gets only its own tenant's TLS keys (XDS-1) ---------
# ep_pod_on <node> — the edge-proxy pod scheduled on that node.
ep_pod_on() { k -n edge get pod -l app.kubernetes.io/name=edge-proxy --field-selector "spec.nodeName=$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }

# node_secrets <node> — the SDS secret names that node's Envoy holds, one per line.
node_secrets() {
  envoy_config_dump "$(ep_pod_on "$1")" | jq -r '.configs[]?.dynamic_active_secrets[]?.name' 2>/dev/null | sort -u
}

# tls_get <node-ip> <host> — HTTPS to that node's :8443 with SNI and Host <host>,
# from inside the kind network (macOS cannot reach a node IP); curl -v output.
tls_get() {
  docker exec "${CLUSTER_NAME}-control-plane" curl -skv --max-time 6 \
    --resolve "$2:8443:$1" -H "Host: $2" "https://$2:8443/" 2>&1 || true
}

phase16_sds_scope() {
  section "PHASE 16 — two nodes serve two tenants; each node's SDS holds only its own tenant's key"
  local nodes nodeA nodeB ipA ipB pgpod tmp
  nodes="$(k -n edge get pod -l app.kubernetes.io/name=edge-proxy -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | sort -u)"
  [ "$(printf '%s\n' "$nodes" | grep -c .)" = 2 ] || die "need edge-proxy on exactly two nodes, found: $(echo $nodes)"
  nodeA="$(printf '%s\n' "$nodes" | sed -n 1p)"; nodeB="$(printf '%s\n' "$nodes" | sed -n 2p)"
  ipA="$(k get node "$nodeA" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
  ipB="$(k get node "$nodeB" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
  log "tenant-a pinned to $nodeA ($ipA), tenant-b pinned to $nodeB ($ipB)"

  section "seed a cert per tenant and an HTTPS :8443 gateway per tenant presenting it, pinned by node_selector"
  # The keys go in as plaintext PEM, which the control plane reads as-is beside
  # sealed ones (the custodian seals at rest); what this phase measures is which
  # node the decrypted key is shipped to.
  tmp="$(mktemp -d)"
  local t sql=""
  for t in a b; do
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=tenant-$t.local" \
      -keyout "$tmp/$t.key" -out "$tmp/$t.crt" >/dev/null 2>&1 || die "openssl could not mint tenant-$t's cert"
  done
  local node c64 k64
  for t in a b; do
    if [ "$t" = a ]; then node="$nodeA"; else node="$nodeB"; fi
    c64="$(base64 < "$tmp/$t.crt" | tr -d '\n')"; k64="$(base64 < "$tmp/$t.key" | tr -d '\n')"
    sql+="
INSERT INTO secrets (id,name,cert_pem,key_pem,kind)
VALUES ('tenant-$t-cert','tenant-$t-cert',convert_from(decode('$c64','base64'),'UTF8'),convert_from(decode('$k64','base64'),'UTF8'),'tls_certificate')
ON CONFLICT (name) DO UPDATE SET cert_pem=EXCLUDED.cert_pem,key_pem=EXCLUDED.key_pem,updated_at=now();
INSERT INTO gateways (id,name,port,protocol,tls_secret,node_selector,deleted_at)
VALUES ('tenant-$t-https','tenant-$t-https',8443,'HTTPS','tenant-$t-cert',jsonb_build_object('kubernetes.io/hostname','$node'),NULL)
ON CONFLICT (name) DO UPDATE SET port=EXCLUDED.port,protocol=EXCLUDED.protocol,tls_secret=EXCLUDED.tls_secret,node_selector=EXCLUDED.node_selector,deleted_at=NULL,updated_at=now();
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy,deleted_at)
VALUES ('tenant-$t-tls','tenant-$t-tls','tenant-$t-https',ARRAY['tenant-$t.local']::text[],'/','tenant-$t',30,'none',NULL)
ON CONFLICT (name) DO UPDATE SET gateway_id=EXCLUDED.gateway_id,hosts=EXCLUDED.hosts,path_prefix=EXCLUDED.path_prefix,
  cluster_name=EXCLUDED.cluster_name,auth_policy=EXCLUDED.auth_policy,updated_at=now(),deleted_at=NULL;"
  done
  rm -rf "$tmp"
  pgpod="$(k get pod -n "$INFRA_NS" -l app=postgres -o jsonpath='{.items[0].metadata.name}')"
  printf 'BEGIN;%s\nCOMMIT;\n' "$sql" | k exec -i -n "$INFRA_NS" "$pgpod" -- psql -U postgres -d edge -v ON_ERROR_STOP=1 -q -f - >/dev/null
  ok "tenant-a-https -> $nodeA, tenant-b-https -> $nodeB (each with its own cert)"

  # assert_scope <node> <own> <other> — the node's Envoy holds its own tenant's
  # secret and not the other's, waiting out the reconcile poll and delivery.
  assert_scope() {
    local s i=0
    while :; do
      s="$(node_secrets "$1")"
      if printf '%s\n' "$s" | grep -qx "$2"; then break; fi
      i=$((i + 1)); [ "$i" -lt 15 ] || die "$1 never received $2 (holds: $(echo $s))"
      sleep 2
    done
    echo "  $1 SDS secrets: $(echo $s)"
    ! printf '%s\n' "$s" | grep -qx "$3" || die "$1 holds $3 — another tenant's key reached it"
    ok "$1 holds $2 and not $3"
  }
  # assert_serves <ip> <host> <backend> / assert_refuses <ip> <host>
  assert_serves() {
    local out; out="$(tls_get "$1" "$2")"
    has "$out" "CN=$2" && has "$out" "$3" || { printf '%s\n' "$out" | tail -15; die "$1 did not serve $2 with its own cert"; }
    ok "$1 serves $2 with CN=$2 -> $3"
  }
  assert_refuses() {
    local out; out="$(tls_get "$1" "$2")"
    ! has "$out" "CN=$2" && ! has "$out" "TENANT-" || { printf '%s\n' "$out" | tail -15; die "$1 presented $2's cert or served its backend — it holds that tenant's key"; }
    ok "$1 cannot serve $2 (presents no $2 cert: it holds no such key)"
  }

  section "each node's live Envoy SDS"
  assert_scope "$nodeA" tenant-a-cert tenant-b-cert
  assert_scope "$nodeB" tenant-b-cert tenant-a-cert

  section "each node serves its own tenant over TLS with that tenant's cert, and cannot present the other's"
  assert_serves "$ipA" tenant-a.local TENANT-A-BACKEND
  assert_serves "$ipB" tenant-b.local TENANT-B-BACKEND
  assert_refuses "$ipA" tenant-b.local
  assert_refuses "$ipB" tenant-a.local

  section "a node that reconnects is caught up with its own scope (config unchanged)"
  # Restart the control plane: a new replica turns Ready (/readyz) only after its
  # first publish, before any edge node can reach it, so with config unchanged
  # every node it serves afterwards is served by the late-join catch-up. Then
  # restart $nodeB's edge-proxy: the fresh Envoy holds nothing, so whatever it
  # ends up holding came from that catch-up.
  k -n "$INFRA_NS" rollout restart deploy/edge-control-plane >/dev/null
  wait_rollout deploy/edge-control-plane "$INFRA_NS" 240s
  local old new i=0
  old="$(ep_pod_on "$nodeB")"
  k -n edge delete pod "$old" --wait=true >/dev/null
  while :; do
    new="$(ep_pod_on "$nodeB")"
    [ -n "$new" ] && [ "$new" != "$old" ] && k -n edge wait --for=condition=Ready "pod/$new" --timeout=10s >/dev/null 2>&1 && break
    i=$((i + 1)); [ "$i" -lt 30 ] || die "no new edge-proxy became Ready on $nodeB"
    sleep 3
  done
  log "edge-proxy on $nodeB restarted: $old -> $new"
  assert_scope "$nodeB" tenant-b-cert tenant-a-cert
  assert_serves "$ipB" tenant-b.local TENANT-B-BACKEND
  assert_refuses "$ipB" tenant-a.local
  assert_scope "$nodeA" tenant-a-cert tenant-b-cert
  assert_serves "$ipA" tenant-a.local TENANT-A-BACKEND
  ok "PHASE 16 — per-node SDS scoping proven on two nodes, through a reconnect"
}

# ---- Phase 17 — the charts' NetworkPolicies refuse a pod outside the flows ----
# reach <ns> <deploy> <host> <port> — "connected" when a TCP connection from that
# workload opens (whatever the protocol says after); otherwise "dropped (curl
# exit N)": 28 = timed out (dropped on the way to a pod), 7 = refused or, from
# a node, denied in its own OUTPUT chain (connect() fails at once with EPERM).
reach() {
  local out
  out="$(k -n "$1" exec "deploy/$2" -- sh -c \
    'curl -sk --connect-timeout 4 -m 6 -o /dev/null -w "%{time_connect}" "$0"; echo " $?"' "https://$3:$4/" 2>/dev/null || true)"
  reach_verdict "$out"
}
# reach_from_node <node> <ip> <port> — the same probe from a kind node, i.e. from
# the node network the hostNetwork gateway sends from.
reach_from_node() {
  local out
  out="$(docker exec "$1" sh -c \
    'curl -sk --connect-timeout 4 -m 6 -o /dev/null -w "%{time_connect}" "$0"; echo " $?"' "https://$2:$3/" 2>/dev/null || true)"
  reach_verdict "$out"
}
reach_verdict() {  # "<time_connect> <curl exit>"
  if [ -z "$1" ]; then echo "error (the probe did not run)"
  elif awk -v t="${1% *}" 'BEGIN { exit !(t + 0 > 0) }'; then echo connected
  else echo "dropped (curl exit ${1##* })"; fi
}
reach_is() { local want="$1"; shift; case "$(reach "$@")" in "$want"*) return 0 ;; *) return 1 ;; esac; }
reach_from_node_is() { local want="$1"; shift; case "$(reach_from_node "$@")" in "$want"*) return 0 ;; *) return 1 ;; esac; }

phase17_network_policy() {
  section "PHASE 17 — the charts' NetworkPolicies: a pod outside the allowed flows is refused (red-first)"
  k -n "$INFRA_NS" get networkpolicy
  wait_rollout deploy/attacker sec3-attacker 60s
  local atk_ip; atk_ip="$(k -n sec3-attacker get pod -l app=attacker -o jsonpath='{.items[0].status.podIP}')"
  log "attacker pod $atk_ip (namespace sec3-attacker — no chart allows it)"

  # Every chart port, two sources each: the attacker (refused) and a node, the
  # gateway's own source (allowed) — so a drop is the policy, not a dead pod.
  # Policies have been in place since Phase 7, so nothing is reprogramming here.
  section "every chart's port: attacker dropped, gateway (node network) allowed"
  local node="${CLUSTER_NAME}-worker2" t svc port ip eps r
  for t in auth-service:50051:gw edge-control-plane:18000:gw edge-issuer:8081:gw \
           edge-osb:8080:gw edge-ratelimit:8082:gw edge-secrets:8082:none; do
    svc="${t%%:*}"; port="$(printf '%s' "$t" | cut -d: -f2)"
    eps="$(k -n "$INFRA_NS" get endpoints "$svc" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)"
    if [ -z "$eps" ]; then warn "$svc has no ready endpoints — skipped (a refused connection would prove nothing)"; continue; fi
    if [ "${t##*:}" = gw ]; then
      ip="$(k -n "$INFRA_NS" get svc "$svc" -o jsonpath='{.spec.clusterIP}')"
      retry 10 2 reach_from_node_is connected "$node" "$ip" "$port" || true
      r="$(reach_from_node "$node" "$ip" "$port")"
      echo "  node $node -> $svc:$port  =>  $r"
      if [ "$r" != connected ]; then
        k -n "$INFRA_NS" get endpoints "$svc" -o wide; k -n "$INFRA_NS" get pods -o wide | grep -E "^${svc}" || true
        die "$svc:$port refused to the gateway's node network ($r) — the policy blocks an allowed flow"
      fi
    fi
    r="$(reach sec3-attacker attacker "$svc.${INFRA_NS}.svc.cluster.local" "$port")"
    echo "  attacker -> $svc:$port  =>  $r"
    case "$r" in dropped*) ;; *) die "$svc:$port NOT refused to a pod outside the allowed flows ($r)" ;; esac
  done

  # RED first, on one chart: its policy switched off, the attacker gets in;
  # switched back on, it is dropped again — the refusal is the chart's policy.
  local AS="auth-service.${INFRA_NS}.svc.cluster.local"
  section "RED — auth-service NetworkPolicy OFF: the attacker reaches ext_authz :50051"
  h upgrade auth-service "$REPO_ROOT/deploy/helm/auth-service" -n "$INFRA_NS" --reuse-values \
    --set networkPolicy.enabled=false --wait --timeout 120s >/dev/null
  k -n "$INFRA_NS" get networkpolicy auth-service >/dev/null 2>&1 && die "RED setup: auth-service NetworkPolicy still present"
  retry 15 2 reach_is connected sec3-attacker attacker "$AS" 50051 \
    || die "RED baseline broken: the attacker cannot reach auth-service:50051 even with no policy ($(reach sec3-attacker attacker "$AS" 50051))"
  ok "RED — no policy: attacker($atk_ip) -> auth-service:50051 connected"

  section "GREEN — auth-service NetworkPolicy back ON: the same connection is dropped"
  h upgrade auth-service "$REPO_ROOT/deploy/helm/auth-service" -n "$INFRA_NS" --reuse-values \
    --set networkPolicy.enabled=true --wait --timeout 120s >/dev/null
  retry 15 2 reach_is dropped sec3-attacker attacker "$AS" 50051 \
    || die "GREEN FAIL: auth-service:50051 still reachable from the attacker with the chart's policy on"
  ok "GREEN — chart policy on: attacker($atk_ip) -> auth-service:50051 $(reach sec3-attacker attacker "$AS" 50051)"
  ok "PHASE 17 — every chart refuses a pod outside its allowed flows; the gateway's flows stay open"
}

# ---- Phase 18 — a user created through SCIM signs in through OIDC -------------
ISSUER_HTTPS="https://edge-issuer.${INFRA_NS}.svc.cluster.local:8081"
SSO_EMAIL="sso-user@corp.local"   # Dex's static user (manifests/dex.yaml)
SSO_PASS="password"

# scim <method> <path> [json] — the IdP's SCIM client, from the minter pod.
# Prints the body, then a last line HTTP=<code>.
scim() {
  if [ -n "${3:-}" ]; then
    k -n tenant-secure exec minter -- curl -sk --max-time 10 -X "$1" "$ISSUER_HTTPS/scim/v2$2" \
      -H "Authorization: Bearer $SCIM_TOKEN" -H 'Content-Type: application/scim+json' -d "$3" -w '\nHTTP=%{http_code}'
  else
    k -n tenant-secure exec minter -- curl -sk --max-time 10 -X "$1" "$ISSUER_HTTPS/scim/v2$2" \
      -H "Authorization: Bearer $SCIM_TOKEN" -w '\nHTTP=%{http_code}'
  fi
}

# sso_sign_in — a browser's OIDC sign-in, from the minter pod: /sso/login on the
# issuer -> Dex's login form; post Dex the user's password -> Dex redirects to
# the issuer's /sso/callback, which answers. Body, then HTTP=<code>.
sso_sign_in() {
  k -n tenant-secure exec minter -- sh -c '
    J=/tmp/sso-jar; rm -f "$J"
    form="$(curl -sk --max-time 10 -L -c "$J" -b "$J" -o /dev/null -w "%{url_effective}" "$1/sso/login")"
    curl -sk --max-time 10 -L -c "$J" -b "$J" -w "\nHTTP=%{http_code}" \
      --data-urlencode "login=$2" --data-urlencode "password=$3" "$form"
  ' sh "$ISSUER_HTTPS" "$SSO_EMAIL" "$SSO_PASS"
}

http_of() { printf '%s' "${1##*HTTP=}"; }
body_of() { printf '%s' "${1%HTTP=*}"; }

phase18_scim_oidc() {
  section "PHASE 18 — a user created through SCIM signs in through OIDC (Dex stands in for the customer's IdP)"
  if docker pull "$DEX_IMAGE" >/dev/null 2>&1; then kind load docker-image --name "$CLUSTER_NAME" "$DEX_IMAGE" >/dev/null 2>&1 || true; fi
  k apply -f "$LOCAL_DIR/manifests/dex.yaml"
  k -n "$INFRA_NS" wait --for=condition=Ready certificate/dex-cert --timeout=120s >/dev/null
  wait_rollout deploy/dex "$INFRA_NS" 180s
  k -n tenant-secure wait --for=condition=Ready pod/minter --timeout=60s >/dev/null

  section "reset — delete $SSO_EMAIL if an earlier run left it"
  local out filter id
  filter="$(jq -rn --arg f "userName eq \"$SSO_EMAIL\"" '$f|@uri')"
  out="$(scim GET "/Users?filter=$filter")"
  [ "$(http_of "$out")" = 200 ] || die "SCIM list refused: $out"
  for id in $(body_of "$out" | jq -r '.Resources[]?.id'); do
    [ "$(http_of "$(scim DELETE "/Users/$id")")" = 204 ] || die "could not delete leftover user $id"
    log "deleted leftover $id"
  done

  section "RED — before SCIM provisions $SSO_EMAIL, Dex signs them in and the issuer refuses"
  out="$(sso_sign_in)"
  echo "  sign-in -> HTTP $(http_of "$out")  $(body_of "$out" | tr -d '\n')"
  [ "$(http_of "$out")" = 403 ] || die "RED FAIL: an IdP user SCIM never created got HTTP $(http_of "$out")"
  has "$(body_of "$out")" "not provisioned" || die "RED FAIL: refused for the wrong reason: $out"
  ok "RED — the IdP vouched for $SSO_EMAIL, and the issuer refused: not provisioned"

  section "SCIM — the IdP creates $SSO_EMAIL (POST /scim/v2/Users)"
  out="$(scim POST /Users "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"$SSO_EMAIL\",\"name\":{\"givenName\":\"SSO\",\"familyName\":\"User\"},\"externalId\":\"dex-08a8684b\",\"active\":true}")"
  [ "$(http_of "$out")" = 201 ] || die "SCIM create failed: $out"
  id="$(body_of "$out" | jq -r .id)"
  [ "$(body_of "$out" | jq -r '.active')" = true ] || die "SCIM create: user not active: $out"
  ok "SCIM created $SSO_EMAIL as user $id"

  section "GREEN — the same Dex sign-in now yields a gateway token, and the gateway serves the SCIM user"
  out="$(sso_sign_in)"
  [ "$(http_of "$out")" = 200 ] || die "GREEN FAIL: provisioned user's OIDC sign-in got HTTP $(http_of "$out"): $(body_of "$out")"
  local TOK c b low
  TOK="$(body_of "$out" | jq -r '.access_token // empty')"
  [ -n "$TOK" ] || die "GREEN FAIL: sign-in answered 200 without an access_token: $out"
  c="$(gw_code secure.local -H "Authorization: Bearer $TOK")"
  b="$(gw_body secure.local -H "Authorization: Bearer $TOK")"
  low="$(printf '%s' "$b" | tr 'A-Z' 'a-z')"
  printf '%s\n' "$b" | grep -iE 'X-User-Id|X-User-Email' | sed 's/^/    /'
  [ "$c" = 200 ] || die "GREEN FAIL: the gateway refused the SSO token (HTTP $c)"
  has "$low" "x-user-email: $SSO_EMAIL" || die "GREEN FAIL: whoami did not see x-user-email $SSO_EMAIL"
  has "$low" "x-user-id: $id" || die "GREEN FAIL: whoami did not see x-user-id $id (the SCIM user)"
  ok "GREEN — signed in through OIDC; secure.local served to x-user-email=$SSO_EMAIL x-user-id=$id"

  section "SCIM deprovision — PATCH active=false, and the next Dex sign-in is refused"
  out="$(scim PATCH "/Users/$id" '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}')"
  [ "$(http_of "$out")" = 200 ] && [ "$(body_of "$out" | jq -r .active)" = false ] || die "SCIM deactivate failed: $out"
  out="$(sso_sign_in)"
  echo "  sign-in -> HTTP $(http_of "$out")  $(body_of "$out" | tr -d '\n')"
  [ "$(http_of "$out")" = 403 ] || die "deprovisioned user's sign-in got HTTP $(http_of "$out") (expected 403)"
  ok "deactivated by SCIM -> sign-in refused"

  [ "$(http_of "$(scim DELETE "/Users/$id")")" = 204 ] || die "SCIM delete failed"
  ok "PHASE 18 — SCIM-provisioned user signed in through OIDC and reached the gateway; unprovisioned and deprovisioned were refused"
}

main() {
  phase1_cluster
  verify_phase1
  phase2_deps
  verify_phase2
  phase3_images
  verify_phase3
  phase4_dataplane_pki
  verify_phase4
  phase5_secrets
  verify_phase5
  phase6_migrate
  verify_phase6
  phase7_deploy
  verify_phase7
  phase8_seed
  verify_phase8
  phase9_prove
  phase10_sec3_admission
  phase11_sec3_dataplane
  phase12_extauthz_cutover
  phase13_inconsistent_guard
  phase14_failstatic_metrics
  phase15_osb_broker
  phase16_sds_scope
  phase17_network_policy
  phase18_scim_oidc
  section "up.sh: FULL STANDUP COMPLETE — routable + SEC-3 + ext_authz LIVE + R8 fail-static inconsistent guard + fail-static metrics + OSB broker + per-node SDS + chart NetworkPolicies + SCIM/OIDC sign-in."
}

# Entry: no args -> full standup; args -> run the named phase function(s) in order
# (e.g. `up.sh phase4_dataplane_pki verify_phase4` to re-run just Phase 4).
if [ "$#" -gt 0 ]; then
  for _fn in "$@"; do "$_fn"; done
else
  main
fi
