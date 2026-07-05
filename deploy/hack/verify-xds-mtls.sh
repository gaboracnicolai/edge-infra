#!/usr/bin/env bash
# verify-xds-mtls.sh — INVARIANT LOCK for R1 (xDS mTLS asymmetry fix).
#
# Asserts the edge-proxy bootstrap renders MUTUAL TLS to the control plane WITH
# peer-identity pinning (SNI + SAN match) for base defaults and every env
# overlay. Fails (exit 1) if anyone reverts xDS to plaintext or drops the SAN
# pin — the guard that stops the mTLS asymmetry from silently returning.
#
# The control-plane server requires client mTLS unconditionally; this proves the
# proxy side presents a client cert AND verifies the server by CA + SAN.
#
# Run: make verify-xds-mtls    (or: bash deploy/hack/verify-xds-mtls.sh)
set -uo pipefail

REPO="$(git rev-parse --show-toplevel)"
CHART="$REPO/deploy/helm/edge-proxy"
HOST="edge-control-plane.infra.svc.cluster.local" # MUST equal the control-plane server cert SAN
MP="/etc/xds-client-tls"                          # xds.tls.mountPath

fail=0
check() { # label  overlay-relpath(optional)
	local label="$1" overlay="${2:-}"
	local args=(edge-proxy "$CHART")
	[ -n "$overlay" ] && args+=(--values "$REPO/$overlay")
	local out
	if ! out="$(helm template "${args[@]}" 2>&1)"; then
		echo "FAIL  $label  (helm render error)"
		echo "$out" | tail -3
		fail=1
		return
	fi
	local miss=()
	grep -q 'UpstreamTlsContext' <<<"$out" || miss+=("transport_socket")
	grep -q "sni: $HOST" <<<"$out" || miss+=("sni==host")
	grep -q 'match_typed_subject_alt_names' <<<"$out" || miss+=("SAN-matcher")
	grep -q 'san_type: DNS' <<<"$out" || miss+=("san_type:DNS")
	grep -q "exact: $HOST" <<<"$out" || miss+=("SAN-exact==host")
	grep -q "$MP/tls.crt" <<<"$out" || miss+=("client-cert")
	grep -q "$MP/tls.key" <<<"$out" || miss+=("client-key")
	grep -q "$MP/ca.crt" <<<"$out" || miss+=("trusted_ca")
	if [ ${#miss[@]} -eq 0 ]; then
		echo "PASS  $label"
	else
		echo "FAIL  $label  missing: ${miss[*]}"
		fail=1
	fi
}

check "base" ""
check "staging" "deploy/envs/staging/values-proxy.yaml"
check "prod/eu-west-1" "deploy/envs/prod/eu-west-1/values-proxy.yaml"
check "prod/us-east-1" "deploy/envs/prod/us-east-1/values-proxy.yaml"

echo
if [ "$fail" -eq 0 ]; then
	echo "OK: xDS mutual TLS + peer pinning (SNI + SAN==$HOST) asserted for all envs."
else
	echo "INVARIANT VIOLATED: xDS mTLS/peer-pinning missing in one or more envs (see FAILs above)."
	exit 1
fi
