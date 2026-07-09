#!/usr/bin/env bash
# bootstrap-pki.sh — generate the OUT-OF-BAND admin-plane PKI + KEK for edge-infra.
#
# Generates:
#   - edge-admin-ca         the OPERATOR trust domain (a CA cert + key), SEPARATE
#                           from the data-plane edge-internal-ca (cert-manager).
#   - server.crt/key        the edge-secrets custodian TLS server cert (signed by
#                           edge-admin-ca).
#   - operator.crt/key      an operator client cert (signed by edge-admin-ca) used
#                           to authenticate to the custodian.
#   - SECRET_KEK            a random 256-bit AES key (base64) for encryption at rest.
#
# It writes the material to a GITIGNORED dir (0600) and PRINTS the kubectl commands
# to load them. It NEVER runs kubectl and NEVER commits or transmits any material —
# the operator runs the printed commands against their own cluster.
#
# Usage:  scripts/bootstrap-pki.sh [OUTPUT_DIR]      (default: .pki-bootstrap)
#         EDGE_NAMESPACE=edge-infra FORCE=1 scripts/bootstrap-pki.sh
set -euo pipefail

OUT="${1:-.pki-bootstrap}"
NS="${EDGE_NAMESPACE:-edge-infra}"
FORCE="${FORCE:-0}"
DAYS="${CERT_DAYS:-3650}"

if [ -e "$OUT" ] && [ "$FORCE" != "1" ]; then
  echo "ERROR: '$OUT' already exists — refusing to overwrite existing key material." >&2
  echo "       Move it aside, or re-run with FORCE=1 (this DESTROYS the existing material)." >&2
  exit 1
fi
rm -rf "$OUT"
mkdir -p "$OUT"
chmod 700 "$OUT"
umask 077   # every generated file is 0600

ec() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }

echo "==> edge-admin-ca  (operator trust domain — SEPARATE from data-plane edge-internal-ca)"
ec "$OUT/admin-ca.key"
openssl req -x509 -new -key "$OUT/admin-ca.key" -days "$DAYS" -sha256 \
  -subj "/CN=edge-admin-ca/O=edge-infra-admin" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$OUT/admin-ca.crt"

sign() { # csr_subject  out_prefix  ext_lines
  local subj="$1" pfx="$2" ext="$3"
  ec "$OUT/$pfx.key"
  openssl req -new -key "$OUT/$pfx.key" -subj "$subj" -out "$OUT/$pfx.csr"
  printf '%b\n' "$ext" > "$OUT/$pfx.ext"
  openssl x509 -req -in "$OUT/$pfx.csr" -CA "$OUT/admin-ca.crt" -CAkey "$OUT/admin-ca.key" \
    -CAcreateserial -days "$DAYS" -sha256 -extfile "$OUT/$pfx.ext" -out "$OUT/$pfx.crt"
}

echo "==> edge-secrets custodian SERVER cert  (signed by edge-admin-ca)"
sign "/CN=edge-secrets" server \
  "subjectAltName=DNS:edge-secrets,DNS:edge-secrets.$NS.svc,DNS:edge-secrets.$NS.svc.cluster.local,DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature"

echo "==> OPERATOR client cert  (signed by edge-admin-ca — authenticates to the custodian)"
sign "/CN=operator/O=edge-infra-admin" operator \
  "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature"

echo "==> SECRET_KEK  (256-bit AES key, base64)"
KEK="$(openssl rand -base64 32)"
printf '%s' "$KEK" > "$OUT/secret_kek.b64"

rm -f "$OUT"/*.csr "$OUT"/*.ext "$OUT"/*.srl

cat <<BANNER

============================================================================
 Material generated in ./$OUT/ (gitignored, 0600). STORE IT SECURELY — this is
 the admin trust root + the at-rest encryption key. The output below CONTAINS
 SECRETS. This script only GENERATED the material; YOU run the commands against
 your cluster.
============================================================================

# 1) Operator client CA — the custodian verifies operator certs against ONLY this
#    (the CA KEY, $OUT/admin-ca.key, is loaded NOWHERE; keep it OFFLINE):
kubectl -n $NS create secret generic edge-admin-ca \\
  --from-file=ca.crt=$OUT/admin-ca.crt

# 2) Custodian TLS server cert:
kubectl -n $NS create secret tls edge-secrets-tls \\
  --cert=$OUT/server.crt --key=$OUT/server.key

# 3) SECRET_KEK into BOTH services' config secrets — the SAME value both sides, so
#    the control-plane can decrypt what the custodian sealed (add your own DSN /
#    admin key alongside):
kubectl -n $NS create secret generic edge-secrets-config \\
  --from-literal=SECRET_KEK='$KEK' \\
  --from-literal=SECRETS_DATABASE_URL='<shared-DB DSN>' \\
  --from-literal=SECRETS_ADMIN_API_KEY='<optional admin key>'
kubectl -n $NS create secret generic edge-control-plane-postgres \\
  --from-literal=SECRET_KEK='$KEK' \\
  --from-literal=dsn='<shared-DB DSN>'

# The OPERATOR client cert stays LOCAL (never a k8s secret) — use it with the CLI:
#   secrets put --server https://edge-secrets:8082 \\
#     --ca $OUT/admin-ca.crt --client-cert $OUT/operator.crt --client-key $OUT/operator.key ...
============================================================================
BANNER
