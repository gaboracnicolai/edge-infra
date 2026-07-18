#!/usr/bin/env bash
# sec3-preflight.sh — will SEC-3's ipBlock gateway-allow work on THIS cluster,
# or would it drop my own gateway?
#
# SEC-3 (k8s/policies/backend-network-policies.yaml) isolates a backend namespace
# with default-deny-ingress + an allow-from-gateway NetworkPolicy whose only
# gateway rule is:
#
#     - from: [ ipBlock: { cidr: <NODE_CIDR> } ]
#       ports: [ { protocol: TCP, port: <backend port> } ]
#
# That works ONLY because the gateway (edge-proxy) is a hostNetwork DaemonSet, so
# its traffic to a backend should carry a NODE IP as source and match <NODE_CIDR>.
# If the CNI/topology does NOT preserve the node IP (an encapsulating overlay
# across subnets rewrites the source to a tunnel/pod IP; or nodes span multiple
# subnets a single <NODE_CIDR> can't cover), the allow does NOT match and SEC-3
# DROPS THE GATEWAY — a self-inflicted outage.
#
# This script is STRICTLY READ-ONLY. It runs only kubectl get/describe (and,
# where possible, an exec-to-curl from an EXISTING pod). It never applies,
# patches, deletes, scales, or otherwise mutates cluster state. It is safe to run
# against a cluster another session owns.
#
# Exit codes (so a cutover can gate on it):
#   0  PASS         — node IP is preserved; SEC-3 ipBlock will match the gateway
#   1  FAIL         — encapsulated and/or multi-subnet; SEC-3 would drop the gateway
#   2  INCONCLUSIVE — could not determine read-only; see the MANUAL VERIFICATION step
#   3  usage / prerequisite error (kubectl missing, no cluster, bad flag)
#
# Usage:
#   scripts/sec3-preflight.sh [--context KUBE_CONTEXT] [--backend-namespace NS] \
#                             [--node-cidr CIDR]
#
# --context            kube-context to target (default: current-context)
# --backend-namespace  a real backend namespace, so the script reports the actual
#                      backend container port SEC-3 must allow (the template
#                      defaults to 8080, which is usually WRONG for your workload)
# --node-cidr          override the auto-derived node CIDR (the value you would
#                      put in the policy's ipBlock)
set -euo pipefail

CONTEXT=""
BACKEND_NS=""
NODE_CIDR_OVERRIDE=""

# ── tiny output helpers (stderr for humans; stdout stays parseable) ────────────
if [ -t 1 ]; then C_B=$'\033[1m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_D=$'\033[2m'; C_0=$'\033[0m'; else C_B=""; C_G=""; C_Y=""; C_R=""; C_D=""; C_0=""; fi
sec()  { printf '\n%s==> %s%s\n' "$C_B" "$*" "$C_0"; }
inf()  { printf '   %s- %s%s\n' "$C_D" "$*" "$C_0"; }
good() { printf '   %sOK%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '   %s! %s%s\n' "$C_Y" "$*" "$C_0"; }
bad()  { printf '   %sX %s%s\n' "$C_R" "$*" "$C_0"; }
die()  { printf '%sX %s%s\n' "$C_R" "$*" "$C_0" >&2; exit 3; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 3; }

while [ $# -gt 0 ]; do
  case "$1" in
    --context)           CONTEXT="${2:-}"; shift 2 ;;
    --backend-namespace) BACKEND_NS="${2:-}"; shift 2 ;;
    --node-cidr)         NODE_CIDR_OVERRIDE="${2:-}"; shift 2 ;;
    -h|--help)           usage ;;
    *) # allow a bare kube-context as the sole positional
       if [ -z "$CONTEXT" ]; then CONTEXT="$1"; shift; else die "unexpected argument: $1"; fi ;;
  esac
done

command -v kubectl >/dev/null 2>&1 || die "kubectl not found on PATH"

# kc — the ONE kubectl entrypoint; every call is read-only by construction.
kc() { kubectl ${CONTEXT:+--context "$CONTEXT"} "$@"; }

kc version --request-timeout=10s >/dev/null 2>&1 || kc cluster-info >/dev/null 2>&1 \
  || die "cannot reach the cluster (context='${CONTEXT:-<current>}')"

# ── CIDR helpers (octet compare; supports /8,/16,/24 — the node-subnet cases) ──
# ip_in_cidr <ip> <cidr> → 0 if ip is inside cidr, else 1. Unsupported prefix
# lengths return 2 so callers can degrade to "cannot decide" instead of guessing.
ip_in_cidr() {
  local ip="$1" cidr="$2" net pfx
  net="${cidr%/*}"; pfx="${cidr#*/}"
  case "$pfx" in
    8)  [ "${ip%%.*}" = "${net%%.*}" ] && return 0 || return 1 ;;
    16) [ "$(printf '%s' "$ip" | cut -d. -f1-2)" = "$(printf '%s' "$net" | cut -d. -f1-2)" ] && return 0 || return 1 ;;
    24) [ "$(printf '%s' "$ip" | cut -d. -f1-3)" = "$(printf '%s' "$net" | cut -d. -f1-3)" ] && return 0 || return 1 ;;
    32) [ "$ip" = "$net" ] && return 0 || return 1 ;;
    *)  return 2 ;;
  esac
}

VERDICT="PASS"                 # PASS | FAIL | INCONCLUSIVE
set_fail()  { VERDICT="FAIL"; }
set_incon() { [ "$VERDICT" = "FAIL" ] || VERDICT="INCONCLUSIVE"; }

printf '%s=== SEC-3 prod preflight — gateway-allow / node-IP preservation ===%s\n' "$C_B" "$C_0"
inf "context: ${CONTEXT:-$(kc config current-context 2>/dev/null || echo '<current>')}"

# ── 1. node topology: InternalIPs, subnet span ────────────────────────────────
sec "1. Node topology (do all node InternalIPs share ONE subnet?)"
NODE_IPS="$(kc get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}' | grep -E '^[0-9]+\.' | sort -u)"
[ -n "$NODE_IPS" ] || die "no node InternalIPs found"
inf "node InternalIPs:"; while IFS= read -r ip; do inf "    $ip"; done <<<"$NODE_IPS"

# Group by /24 as the same-L2-subnet heuristic (documented; the empirical source
# measurement below is the authoritative check).
SUBNETS_24="$(while IFS= read -r ip; do printf '%s.0/24\n' "$(printf '%s' "$ip" | cut -d. -f1-3)"; done <<<"$NODE_IPS" | sort -u)"
SUBNET_COUNT="$(printf '%s\n' "$SUBNETS_24" | grep -c . || true)"
if [ "$SUBNET_COUNT" -eq 1 ]; then
  good "nodes span a SINGLE /24 subnet: $SUBNETS_24"
  DERIVED_NODE_CIDR="$SUBNETS_24"
else
  bad "nodes span MULTIPLE subnets (/24 grouping): $(printf '%s' "$SUBNETS_24" | tr '\n' ' ')"
  warn "a single <NODE_CIDR> ipBlock cannot cover multiple node subnets, and an overlay"
  warn "typically encapsulates cross-subnet traffic → the gateway source would not match"
  set_fail
  DERIVED_NODE_CIDR="$(printf '%s\n' "$SUBNETS_24" | head -1)"
fi
NODE_CIDR="${NODE_CIDR_OVERRIDE:-$DERIVED_NODE_CIDR}"
inf "candidate NODE_CIDR (ipBlock value): ${C_B}${NODE_CIDR}${C_0}${NODE_CIDR_OVERRIDE:+ (overridden)}"

# ── 2. CNI + encapsulation mode ───────────────────────────────────────────────
sec "2. CNI and encapsulation (does the CNI preserve the node IP as source?)"
POD_CIDRS="$(kc get nodes -o jsonpath='{range .items[*]}{.spec.podCIDR}{"\n"}{end}' | grep -E '^[0-9]+\.' | sort -u | tr '\n' ' ' || true)"
inf "pod CIDR(s): ${POD_CIDRS:-<unset>}"

CNI="unknown"
if kc -n kube-system get ds calico-node >/dev/null 2>&1; then CNI="calico"
elif kc -n kube-system get ds -l k8s-app=cilium >/dev/null 2>&1 && [ -n "$(kc -n kube-system get ds -l k8s-app=cilium -o name 2>/dev/null)" ]; then CNI="cilium"
elif kc -n kube-system get ds -l app=flannel >/dev/null 2>&1 && [ -n "$(kc -n kube-system get ds -l app=flannel -o name 2>/dev/null)" ]; then CNI="flannel"
elif kc -n kube-system get ds kube-flannel-ds >/dev/null 2>&1; then CNI="flannel"
fi
inf "CNI detected: ${C_B}${CNI}${C_0}"

case "$CNI" in
  calico)
    # Calico IPPool overlapping the pod CIDR governs encapsulation.
    IPPOOLS="$(kc get ippools.crd.projectcalico.org -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.spec.ipipMode}{"|"}{.spec.vxlanMode}{"|"}{.spec.cidr}{"\n"}{end}' 2>/dev/null || true)"
    if [ -z "$IPPOOLS" ]; then
      warn "Calico present but no readable IPPools (RBAC?) — cannot assess encapsulation"
      set_incon
    else
      while IFS='|' read -r name ipip vxlan cidr; do
        [ -n "$name" ] || continue
        ipip="${ipip:-Never}"; vxlan="${vxlan:-Never}"
        inf "IPPool $name: ipipMode=$ipip vxlanMode=$vxlan cidr=$cidr"
        if [ "$ipip" = "Always" ] || [ "$vxlan" = "Always" ]; then
          bad "encapsulation is ALWAYS on → every cross-node hop is tunnelled → the"
          bad "gateway source becomes a tunnel/pod IP, NOT a node IP → SEC-3 would drop it"
          set_fail
        elif [ "$ipip" = "CrossSubnet" ] || [ "$vxlan" = "CrossSubnet" ]; then
          if [ "$SUBNET_COUNT" -eq 1 ]; then
            good "CrossSubnet + single node subnet → same-subnet nodes route natively →"
            good "node IP preserved as source (this is exactly the local kind proof)"
          else
            bad "CrossSubnet + MULTIPLE node subnets → cross-subnet gateway hops are"
            bad "tunnelled → source becomes tunnel/pod IP → SEC-3 would drop the gateway"
            set_fail
          fi
        else
          good "ipipMode=$ipip vxlanMode=$vxlan → native routing, no encapsulation →"
          good "node IP preserved as source"
        fi
      done <<<"$IPPOOLS"
    fi
    ;;
  flannel)
    bad "flannel defaults to a vxlan overlay → cross-node traffic is encapsulated →"
    bad "the gateway source becomes the flannel.1 tunnel IP → SEC-3 would drop it"
    bad "(confirm the flannel backend; 'host-gw' would instead preserve the node IP)"
    set_fail
    ;;
  cilium)
    RM="$(kc -n kube-system get cm cilium-config -o jsonpath='{.data.routing-mode}' 2>/dev/null || true)"
    TUN="$(kc -n kube-system get cm cilium-config -o jsonpath='{.data.tunnel}' 2>/dev/null || true)"
    inf "cilium routing-mode='${RM:-?}' tunnel='${TUN:-?}'"
    if [ "$RM" = "native" ] || [ "$TUN" = "disabled" ]; then
      good "Cilium native routing → node IP preserved as source"
    elif [ -n "$RM$TUN" ]; then
      bad "Cilium tunnel/overlay mode → cross-node traffic encapsulated → SEC-3 would drop the gateway"
      set_fail
    else
      warn "could not read cilium-config routing mode — cannot assess encapsulation"
      set_incon
    fi
    ;;
  *)
    warn "CNI not recognised — cannot assess encapsulation from topology alone"
    set_incon
    ;;
esac

# ── 3. edge-proxy: hostNetwork + node membership ──────────────────────────────
sec "3. Gateway (edge-proxy) — hostNetwork + node IPs inside NODE_CIDR"
EP="$(kc -n edge get pods -l app.kubernetes.io/name=edge-proxy \
      -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.spec.hostNetwork}{"|"}{.status.hostIP}{"|"}{.spec.nodeName}{"\n"}{end}' 2>/dev/null || true)"
if [ -z "$EP" ]; then
  warn "no edge-proxy pods found in namespace 'edge' — is the gateway deployed here?"
  set_incon
else
  while IFS='|' read -r pod host hostip node; do
    [ -n "$pod" ] || continue
    if [ "$host" != "true" ]; then
      bad "edge-proxy $pod is NOT hostNetwork (hostNetwork=$host) — the whole SEC-3"
      bad "node-IP premise is void; the gateway source would be a pod IP"
      set_fail
      continue
    fi
    if ip_in_cidr "$hostip" "$NODE_CIDR"; then
      good "edge-proxy $pod hostNetwork node $hostip ($node) ∈ $NODE_CIDR"
    else
      case $? in
        2) warn "edge-proxy $pod node $hostip: NODE_CIDR prefix /${NODE_CIDR#*/} unsupported by the octet check — verify manually"; set_incon ;;
        *) bad "edge-proxy $pod node $hostip ($node) ∉ $NODE_CIDR → the ipBlock would NOT allow this gateway node"; set_fail ;;
      esac
    fi
  done <<<"$EP"
fi

# ── 4. real backend port (NOT the template's 8080 default) ────────────────────
sec "4. Backend container port SEC-3 must allow (template default 8080 is usually wrong)"
if [ -n "$BACKEND_NS" ]; then
  PORTS="$(kc -n "$BACKEND_NS" get pods -o jsonpath='{range .items[*]}{.metadata.name}{" "}{range .spec.containers[*]}{.name}{":"}{.ports[*].containerPort}{" "}{end}{"\n"}{end}' 2>/dev/null || true)"
  if [ -n "$PORTS" ]; then
    inf "backend pods in '$BACKEND_NS' (set the ipBlock 'port:' to the real container port):"
    while IFS= read -r line; do [ -n "$line" ] && inf "    $line"; done <<<"$PORTS"
  else
    warn "no pods in backend namespace '$BACKEND_NS'"
  fi
else
  warn "no --backend-namespace given: the SEC-3 template hard-codes port 8080, which is"
  warn "almost never your backend's real port. Re-run with --backend-namespace <ns>, or find it:"
  inf  "  kubectl get pods -n <backend-ns> -o jsonpath='{range .items[*]}{.metadata.name}{\" \"}{.spec.containers[*].ports[*].containerPort}{\"\\n\"}{end}'"
fi

# ── 5. decisive empirical check: measure the source a hostNetwork gateway presents
sec "5. Decisive check — source IP a hostNetwork gateway presents to a cross-node backend"
# Find a header-reflecting backend (traefik/whoami reflects RemoteAddr). Its pod
# must be on a DIFFERENT node than an edge-proxy pod so the hop is cross-node.
REFLECT="$(kc get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"|"}{.metadata.name}{"|"}{.status.podIP}{"|"}{.spec.nodeName}{"|"}{range .spec.containers[*]}{.image}{","}{end}{"\n"}{end}' 2>/dev/null \
  | grep -Ei 'whoami|echoserver|http-echo-reflect' | head -1 || true)"
EP_NODE="$(printf '%s\n' "$EP" | awk -F'|' 'NR==1{print $4}')"
EP_POD="$(printf '%s\n' "$EP" | awk -F'|' 'NR==1{print $1}')"

measured=""
if [ -n "$REFLECT" ] && [ -n "${EP_POD:-}" ]; then
  r_ns="$(printf '%s' "$REFLECT" | cut -d'|' -f1)"; r_ip="$(printf '%s' "$REFLECT" | cut -d'|' -f3)"; r_node="$(printf '%s' "$REFLECT" | cut -d'|' -f4)"
  inf "header-reflecting backend: $r_ns pod ip=$r_ip node=$r_node"
  # Pick an edge-proxy pod on a node different from the reflector's.
  probe_pod="$EP_POD"; probe_node="$EP_NODE"
  while IFS='|' read -r pod host hostip node; do
    [ -n "$pod" ] || continue; [ "$node" != "$r_node" ] && { probe_pod="$pod"; probe_node="$node"; break; }
  done <<<"$EP"
  if [ "$probe_node" = "$r_node" ]; then
    warn "edge-proxy and the reflector are co-located (no cross-node pair) — cannot measure automatically"
    measured="NO"
  else
    # Need an HTTP client INSIDE a hostNetwork pod on probe_node. Try edge-proxy itself.
    client="$(kc -n edge exec "$probe_pod" -- sh -c 'command -v curl || command -v wget' 2>/dev/null | head -1 || true)"
    if [ -n "$client" ]; then
      inf "measuring: exec $probe_pod ($probe_node, hostNetwork) → $r_ip (node $r_node)"
      body="$(kc -n edge exec "$probe_pod" -- sh -c "${client##*/} -s -m 5 http://$r_ip/ 2>/dev/null || ${client##*/} -q -O- -T 5 http://$r_ip/ 2>/dev/null" 2>/dev/null || true)"
      src="$(printf '%s\n' "$body" | grep -iE 'RemoteAddr' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
      if [ -n "$src" ]; then
        inf "backend observed source IP = $src"
        if ip_in_cidr "$src" "$NODE_CIDR"; then good "source $src ∈ $NODE_CIDR → NODE IP PRESERVED (empirical PASS)"; measured="PASS"
        else bad "source $src ∉ $NODE_CIDR (a pod/tunnel IP) → SEC-3 WOULD DROP THE GATEWAY (empirical FAIL)"; set_fail; measured="FAIL"; fi
      else
        warn "reflector returned no parseable RemoteAddr — cannot measure automatically"; measured="NO"
      fi
    else
      warn "no curl/wget inside the hostNetwork gateway pod — cannot measure automatically"; measured="NO"
    fi
  fi
else
  inf "no header-reflecting backend found (traefik/whoami or echoserver) on a cross-node pair"
  measured="NO"
fi

if [ "$measured" = "NO" ] || [ -z "$measured" ]; then
  # NOTE: an empirical probe that could not RUN read-only does not overturn a
  # deterministic topology verdict — it only leaves the PASS/FAIL unconfirmed. So
  # we print the confirmation step but do NOT force INCONCLUSIVE here; that state
  # is reserved for a topology we genuinely could not read (unknown CNI, etc).
  printf '\n%s   ┌─ MANUAL VERIFICATION (empirical confirmation could not run read-only) ─┐%s\n' "$C_Y" "$C_0"
  cat <<MANUAL
     The gate could not directly measure the gateway's source IP read-only
     (no header-reflecting backend on a cross-node pair, or no HTTP client in a
     hostNetwork pod). To CONFIRM the verdict below empirically, do this one-time
     check on the target cluster during a maintenance window, BEFORE enabling SEC-3:

       1. Deploy a header-reflecting backend on node B:
            kubectl create ns sec3-check
            kubectl -n sec3-check create deploy whoami --image=traefik/whoami -- --port 80
            kubectl -n sec3-check expose deploy whoami --port 80
       2. From a hostNetwork context on node A (a different node than B), curl it:
            kubectl -n sec3-check run probe --restart=Never --image=curlimages/curl \\
              --overrides='{"spec":{"hostNetwork":true,"nodeName":"<NODE_A>"}}' \\
              -it --rm -- curl -s http://<whoami-clusterIP-or-podIP>/ | grep RemoteAddr
       3. If RemoteAddr's IP is a NODE IP (∈ ${NODE_CIDR}) → SEC-3 will work (PASS).
          If it is a pod/tunnel IP (e.g. from ${POD_CIDRS:-the pod CIDR}) → SEC-3 would
          DROP the gateway (FAIL); do not enable it until the CNI preserves the node IP.
       (Clean up: kubectl delete ns sec3-check)
MANUAL
  printf '%s   └────────────────────────────────────────────────────────────────────┘%s\n' "$C_Y" "$C_0"
fi

# ── verdict ───────────────────────────────────────────────────────────────────
sec "VERDICT"
case "$VERDICT" in
  PASS)
    if [ "$measured" = "PASS" ]; then
      good "PASS (empirically confirmed) — the gateway's source to a cross-node backend"
      good "was a node IP ∈ $NODE_CIDR; SEC-3's ipBlock will match the gateway."
    else
      good "PASS (topology-predicted) — node IP is preserved; SEC-3's ipBlock ($NODE_CIDR)"
      good "will match the gateway. Run the MANUAL VERIFICATION above to confirm empirically."
    fi
    inf  "Set the policy ipBlock cidr=$NODE_CIDR and port to the REAL backend container port."
    exit 0 ;;
  FAIL)
    bad  "FAIL — the gateway source would NOT match the ipBlock; enabling SEC-3 would drop the gateway."
    inf  "Do NOT enable SEC-3 on this cluster until the CNI/topology preserves the node IP as source."
    exit 1 ;;
  *)
    warn "INCONCLUSIVE — could not determine read-only; complete the MANUAL VERIFICATION above before any cutover."
    exit 2 ;;
esac
