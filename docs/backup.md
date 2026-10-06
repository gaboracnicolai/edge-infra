# Backup and restore

What to keep so that you can bring Talyvor Edge back after losing its namespace, its volumes or the
whole cluster, and how to bring it back. `make kind-backup` runs the whole drill on a kind cluster:
it backs up, deletes the namespace, installs again empty, restores, and passes only if the control
plane publishes exactly the configuration it published before the loss and every table matches.

## What to keep

| What | Where it is | How |
|---|---|---|
| **The `edge` database** — gateways, routes, services, team key hashes, the sealed TLS keys, the egress decision log | Postgres | the chart's backup, below |
| **The `issuer` database** — your users and their SCIM state | Postgres | the chart's backup, below |
| **Your keys** — the KEK, the admin CA, the issuer's signing key, the transit key, team keys | `.pki-bootstrap/`, from [install step 5](install.md#5-your-keys) | copy it somewhere offline, **apart from** the database backups |
| **The two certificate authorities** | Secrets `edge-root-ca-secret` and `edge-spiffe-ca` in `cert-manager` | export them once, below, and keep them with your keys |
| **Your settings** | the Helm releases | `helm get values <release> -n <namespace>` for each, or the commands you installed with |

**Keep the KEK apart from the database backups.** Every TLS key `edge-secrets` holds is sealed with
it in the database. A backup and its KEK together are your keys in the clear; a backup without the
KEK can never be unsealed. Lose the KEK and the sealed keys are gone: you will have to put every key
in again.

Redis and NATS need no backup. Redis holds rate-limit counters, which start again from zero. NATS
holds broker requests until a worker applies them; the request and its outcome are in Postgres.

### The certificate authorities

If you lose them with the cluster, `edge-pki` makes new ones in the new cluster, every chart's
certificate is issued from them, and Edge works. But anything outside Edge that trusted the old
ones stops trusting it — above all your agents, whose certificates chain to `edge-spiffe-ca`. To
keep them, export the two Secrets with their cert-manager annotations (without them cert-manager
would issue a new CA over the restored one):

```
kubectl -n cert-manager get secret edge-root-ca-secret edge-spiffe-ca -o json \
  | jq '.items[].metadata |= {name, namespace, labels, annotations}' > edge-ca-secrets.json
```

To restore, `kubectl apply -f edge-ca-secrets.json` after installing cert-manager and **before**
`helm upgrade --install edge-pki`.

## Backing up the databases

`edge-datastores` backs up every database it knows on a schedule (03:00 UTC every day unless you set
`backup.schedule`) to an S3-compatible store: AWS S3, or MinIO or similar inside your own network.
Each backup is a `pg_dump` of each database with a checksum manifest, in a folder named for its UTC
time, and a `LATEST` pointer that is written only once the backup is complete.

Make a bucket, and a Secret with credentials that can write to it:

```
kubectl -n infra create secret generic edge-backup-s3 \
  --from-literal=AWS_ACCESS_KEY_ID=… --from-literal=AWS_SECRET_ACCESS_KEY=…
```

Turn the backup on (drop `backup.s3.endpoint` for AWS S3, and set `backup.s3.region` to yours):

```
helm upgrade edge-datastores deploy/helm/edge-datastores -n infra --reset-then-reuse-values \
  --set backup.enabled=true \
  --set backup.s3.bucket=edge-backups \
  --set backup.s3.existingSecret=edge-backup-s3 \
  --set backup.s3.endpoint=http://minio.backup.svc.cluster.local:9000 \
  --wait
```

Run one now, and check it finished:

```
kubectl -n infra create job --from=cronjob/edge-datastores-backup backup-now
kubectl -n infra wait --for=condition=complete job/backup-now --timeout=10m
kubectl -n infra logs job/backup-now --all-containers
```

The databases of something else that should come back with Edge — Lens's, if it runs beside it —
go in the same backup, from a Secret holding each one's `postgres://` URL:

```
--set 'backup.extraDatabases[0].name=lens' \
--set 'backup.extraDatabases[0].secretName=lens-database' \
--set 'backup.extraDatabases[0].key=DATABASE_URL'
```

`pg_dump` and `pg_restore` run from the chart's `postgres` 16 image; your Postgres server must not be
a newer major version than that.

## Restore

The restore is a Job made from the suspended CronJob `edge-datastores-restore`. It downloads the
backup, checks every dump against the manifest, and restores each database in **one transaction**:
a database is restored whole, or left as it was.

**After losing the namespace or the cluster**, in this order:

1. Restore the two certificate authorities, if you exported them, then install cert-manager and
   `edge-pki` ([install steps 2 and 3](install.md#2-cert-manager)).
2. Install `edge-datastores` again ([step 4](install.md#4-datastores)), with the backup settings
   above and the `edge-backup-s3` Secret.
3. Restore, and wait for it:

   ```
   kubectl -n infra create job --from=cronjob/edge-datastores-restore restore-now
   kubectl -n infra wait --for=condition=complete job/restore-now --timeout=15m
   kubectl -n infra logs job/restore-now --all-containers
   ```

4. Create the Secrets again from **the same** `.pki-bootstrap/` ([step 6](install.md#6-secrets)).
   With a new KEK, the restored keys cannot be unsealed.
5. Install the charts again ([step 8](install.md#8-install-edge)). Skip step 7: your teams' keys
   are in the restored database.

The control plane reads the restored database and publishes the configuration it published before
the loss; the gateway serves exactly what it served.

**To restore an older backup** than the latest, set `backup.restoreFrom` to its folder name — the
time each backup prints, such as `20261006T030000Z` — then create the Job:

```
helm upgrade edge-datastores deploy/helm/edge-datastores -n infra --reset-then-reuse-values \
  --set backup.restoreFrom=20261006T030000Z --wait
```

A restore replaces what is in each database. To go back to an earlier state of a running install,
take a backup first, so you can undo the restore too.
