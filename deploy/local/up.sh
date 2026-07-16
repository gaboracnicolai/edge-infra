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
  apply_secret "$INFRA_NS" generic issuer-secrets \
    --from-literal=ISSUER_URL="$ISSUER_URL" \
    --from-literal=ISSUER_AUDIENCE="$AUD" \
    --from-literal=ISSUER_DATABASE_URL="$ISSUER_DSN"
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
    k -n edge port-forward "pod/$ep" 19001:9901 >/dev/null 2>&1 &
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

  section "GREEN (flip) — attacker → each backend now DROPPED"
  local i=0 ga gb
  while [ "$i" -lt 10 ]; do
    ga="$(attacker_get "$ipA" 5678)"; gb="$(attacker_get "$ipB" 5678)"
    { has "$ga" code=000 && has "$gb" code=000; } && break
    i=$((i + 1)); sleep 2
  done
  echo "  attacker($atk_ip) -> tenant-a $ipA:5678  =>  $ga"
  echo "  attacker($atk_ip) -> tenant-b $ipB:5678  =>  $gb"
  has "$ga" code=000 || die "tenant-a bypass NOT dropped (expected timeout) — got: $ga"
  has "$gb" code=000 || die "tenant-b bypass NOT dropped (expected timeout) — got: $gb"
  ok "GREEN DROP proven — the cross-tenant bypass FLIPPED 200 -> dropped for BOTH tenants"

  section "GREEN — the gateway path (node :443) stays ALLOWED"
  local ca cb ba bb
  ca="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: tenant-a.local' http://127.0.0.1:443/ 2>/dev/null || true)"
  ba="$(curl -s --max-time 6 -H 'Host: tenant-a.local' http://127.0.0.1:443/ 2>/dev/null || true)"
  cb="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H 'Host: tenant-b.local' http://127.0.0.1:443/ 2>/dev/null || true)"
  bb="$(curl -s --max-time 6 -H 'Host: tenant-b.local' http://127.0.0.1:443/ 2>/dev/null || true)"
  echo "  gateway :443 Host tenant-a.local => HTTP $ca  $ba"
  echo "  gateway :443 Host tenant-b.local => HTTP $cb  $bb"
  { [ "$ca" = 200 ] && has "$ba" TENANT-A-BACKEND; } || die "gateway path to tenant-a BROKE under the policy"
  { [ "$cb" = 200 ] && has "$bb" TENANT-B-BACKEND; } || die "gateway path to tenant-b BROKE under the policy"
  ok "GREEN ALLOW proven — gateway :443 still 200 from each backend (source ∈ NODE_CIDR, allowed on :5678)"

  section "confirm echo pods stay Ready under the policy (kubelet probes ride the node IP)"
  k -n tenant-a rollout status deploy/echo --timeout=40s
  k -n tenant-b rollout status deploy/echo --timeout=40s
  ok "Phase 11 (Property 2) verified"
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
  section "up.sh: FULL STANDUP COMPLETE — routable gateway + SEC-3 live enforcement (both flips), ext_authz OFF."
}

# Entry: no args -> full standup; args -> run the named phase function(s) in order
# (e.g. `up.sh phase4_dataplane_pki verify_phase4` to re-run just Phase 4).
if [ "$#" -gt 0 ]; then
  for _fn in "$@"; do "$_fn"; done
else
  main
fi
