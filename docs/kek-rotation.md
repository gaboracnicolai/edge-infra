# Rotating the secrets KEK

The custodian (`edge-secrets`) seals every private key in the `secrets` table
under `SECRET_KEK`, and the control plane opens them to serve them over SDS.
This rotates that key with no gap in what SDS serves. `make kind-e2e` rehearses
it end to end (Phase 33).

## What is stored

A sealed key reads `enc:v2:<kid>:<ciphertext>`. `<kid>` names the KEK it was
sealed under (derived from the KEK, never the KEK itself); the custodian logs its
current one as `kek_id` at start. Keys written before rotation existed read
`enc:v1:…` and still open; a re-seal turns them into `enc:v2`.

## The four steps

1. **Make a new KEK.**

   ```sh
   NEW_KEK="$(openssl rand -base64 32)"
   OLD_KEK="$(kubectl -n infra get secret edge-secrets-config -o jsonpath='{.data.SECRET_KEK}' | base64 -d)"
   ```

2. **Give both services both KEKs**, the new one current. The same values in
   both Secrets, then restart both:

   ```sh
   for s in edge-secrets-config edge-control-plane-postgres; do
     kubectl -n infra patch secret "$s" --type merge \
       -p "{\"stringData\":{\"SECRET_KEK\":\"$NEW_KEK\",\"SECRET_KEK_PREVIOUS\":\"$OLD_KEK\"}}"
   done
   kubectl -n infra rollout restart deploy/edge-control-plane deploy/edge-secrets
   kubectl -n infra rollout status deploy/edge-control-plane
   kubectl -n infra rollout status deploy/edge-secrets
   ```

   New writes are sealed under the new KEK; keys still under the old one open
   with `SECRET_KEK_PREVIOUS`. SDS keeps serving.

3. **Re-seal every key** under the new KEK, as an operator:

   ```sh
   secrets reseal --server https://edge-secrets:8082 \
     --client-cert operator.crt --client-key operator.key --ca admin-ca.crt
   # every key is sealed under KEK 3f9c…: 12 re-sealed, 0 already were
   ```

   It runs in one transaction and changes no key, only how it is sealed. If a
   key cannot be opened by either KEK it stops, names the secret, and changes
   nothing. It is safe to run again.

4. **Drop the old KEK** from both Secrets and restart both:

   ```sh
   for s in edge-secrets-config edge-control-plane-postgres; do
     kubectl -n infra patch secret "$s" --type json \
       -p '[{"op":"remove","path":"/data/SECRET_KEK_PREVIOUS"}]'
   done
   kubectl -n infra rollout restart deploy/edge-control-plane deploy/edge-secrets
   ```

   The control plane turns Ready only after it has published, which opens every
   key. A key the new KEK cannot open fails that load loudly instead of being
   served, so a control plane that is Ready here is serving every cert.

`SECRET_KEK_PREVIOUS` takes a comma-separated list, so a rotation can start
before the last one's old KEK is dropped. Backups taken before step 3 hold keys
sealed under the old KEK: keep it with them.
