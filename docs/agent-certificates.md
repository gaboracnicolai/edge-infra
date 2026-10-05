# Agent certificates (SVIDs)

Every agent pod gets a certificate of its own: an X.509 SVID naming the agent's
SPIFFE ID,

    spiffe://<trust domain>/ns/<namespace>/sa/<service account>

A route set to `auth_policy: mtls` with the agent trust bundle as its client CA
then admits only those pods. A caller with no certificate, or with one the agent
CA did not sign, is refused at the TLS handshake and never sends a request.

`make kind-e2e` runs all of this (Phase 27 of `deploy/local/up.sh`): one pod with
its SVID is served, one with no certificate is refused with `certificate
required`, and one with a certificate for the same SPIFFE ID from another CA is
refused with `unknown ca`.

## What issues them

[cert-manager csi-driver-spiffe](https://cert-manager.io/docs/usage/csi-driver-spiffe/)
runs on every node. When a pod mounts its volume, the driver generates a key on
that node, asks the `edge-spiffe` ClusterIssuer to sign a certificate for the
pod's service account, and writes `tls.crt` and `tls.key` into the volume. The key never leaves the node. The certificate lives an hour and is
renewed in place before it expires.

`edge-spiffe` is a CA of its own (`k8s/spiffe/trust-root.yaml`), separate from
`edge-internal-ca`, so an agent's certificate is never valid as an Edge
component's, and an Edge component's is never accepted as an agent's.

## Install

You need cert-manager. Then:

```bash
kubectl apply -f k8s/spiffe/trust-root.yaml
kubectl -n cert-manager wait --for=condition=Ready certificate/edge-spiffe-ca

helm upgrade --install cert-manager-csi-driver-spiffe cert-manager-csi-driver-spiffe \
  --repo https://charts.jetstack.io --version v0.15.0 \
  -n cert-manager -f k8s/spiffe/csi-driver-spiffe-values.yaml \
  --set app.trustDomain=<your trust domain> --wait
```

cert-manager's own approver approves every CertificateRequest in the cluster.
That includes a request an agent writes itself for another agent's SPIFFE ID. Turn
it off so that only the driver's approver can approve an SVID. The driver's
approver checks that the SPIFFE ID matches the service account that asked. To turn
off cert-manager's approver, install cert-manager with
`--set disableAutoApproval=true`, and either install
[approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/)
for your other issuers or add `--set app.approver.autoApproveNonSPIFFE=true`
above.

## Give Envoy the trust bundle

The trust bundle is the `edge-spiffe` CA certificate. Load it through
`edge-secrets` as a `validation_context`. The control plane serves it to every
Envoy over SDS.

```bash
kubectl -n cert-manager get secret edge-spiffe-ca -o jsonpath='{.data.ca\.crt}' \
  | base64 -d > agent-trust-bundle.pem
kubectl -n <edge namespace> port-forward svc/edge-secrets 8082:8082 &

jq -n --rawfile c agent-trust-bundle.pem '{kind: "validation_context", cert_pem: $c}' \
  | curl --fail -X PUT https://localhost:8082/v1/secrets/agent-trust-bundle \
      --cacert admin-ca.crt --cert operator.crt --key operator.key \
      -H 'Content-Type: application/json' --data-binary @-
```

`admin-ca.crt`, `operator.crt` and `operator.key` are the operator credentials
from `scripts/bootstrap-pki.sh`.

The root lasts ten years and cert-manager renews it 30 days before it expires.
When it does, load the new `ca.crt` the same way.

## Require it on a route

Name the bundle as the route's client CA and set `auth_policy` to `mtls`. Through
the broker:

```json
{
  "auth_policy": "mtls",
  "tls_secret_name": "<the route's server certificate>",
  "client_ca_secret_name": "agent-trust-bundle"
}
```

An `mtls` route needs no token: the certificate is the credential. The control
plane will not publish an `mtls` route that names no client CA.

## Mount it in an agent pod

The driver asks for the certificate as the pod's own service account, so that
account needs permission to create CertificateRequests in its namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: request-svid, namespace: <agent namespace>}
rules:
  - {apiGroups: ["cert-manager.io"], resources: ["certificaterequests"], verbs: ["create"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: my-agent-request-svid, namespace: <agent namespace>}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: request-svid}
subjects: [{kind: ServiceAccount, name: my-agent, namespace: <agent namespace>}]
```

Then mount the volume:

```yaml
spec:
  serviceAccountName: my-agent          # becomes .../sa/my-agent in the SPIFFE ID
  securityContext: {runAsUser: 1000, runAsGroup: 1000}
  containers:
    - name: agent
      volumeMounts:
        - {name: svid, mountPath: /var/run/secrets/spiffe.io, readOnly: true}
  volumes:
    - name: svid
      csi:
        driver: spiffe.csi.cert-manager.io
        readOnly: true
        volumeAttributes:
          spiffe.csi.cert-manager.io/fs-group: "1000"
```

The agent presents `/var/run/secrets/spiffe.io/tls.crt` and `tls.key` as its
client certificate. Re-read them on each new connection, because the driver
replaces them as the certificate renews.
