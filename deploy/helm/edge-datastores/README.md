# edge-datastores

Postgres, Redis and NATS (JetStream) for Talyvor Edge — run by the chart, or
your own. Each of the three is an optional dependency (`charts/postgres`,
`charts/redis`, `charts/nats`, switched by `<store>.enabled`).

Either way the release gives you two things:

- **One connection Secret** (`edge-datastores` by default) with `POSTGRES_DSN`,
  `ISSUER_DATABASE_URL`, `REDIS_ADDR`, `REDIS_PASSWORD` and `NATS_URL`.
- **A migrated edge database.** After install and after every upgrade a Job
  applies the control-plane and OSB migrations (a no-op when nothing is new).

## Bundled

```sh
helm install edge-datastores deploy/helm/edge-datastores -n infra --create-namespace --wait
```

Postgres (with an `edge` and an `issuer` database), Redis and NATS each run as
a single replica on its own volume. The passwords and the NATS token are
generated on first install and kept on upgrade. Uninstalling keeps the volumes
and the connection Secret, so reinstalling the same release finds its data.

Under Argo CD, which renders with `helm template` and so cannot see the existing
Secret, set `postgres.auth.password`, `redis.auth.password` and
`nats.auth.token`, or create the Secret yourself and set
`global.datastores.createSecret=false`.

## External

Switch a store off and point the chart at yours:

```yaml
postgres: { enabled: false }
redis: { enabled: false }
nats: { enabled: false }
external:
  postgres:
    dsn: postgres://edge:…@db.example.com:5432/edge?sslmode=verify-full
    issuerDsn: postgres://issuer:…@db.example.com:5432/issuer?sslmode=verify-full
  redis:
    addr: cache.example.com:6379
    password: …
  nats:
    url: nats://token@nats.example.com:4222
```

Only `external.postgres.dsn` is required. Mixing modes is fine — for example
your managed Postgres with the bundled Redis and NATS.

## Backup and restore

Switch the backup on and point it at a bucket — AWS S3, MinIO or any
S3-compatible store:

```sh
kubectl -n infra create secret generic edge-backup-s3 \
  --from-literal=AWS_ACCESS_KEY_ID=… --from-literal=AWS_SECRET_ACCESS_KEY=…
helm upgrade edge-datastores deploy/helm/edge-datastores -n infra --reuse-values \
  --set backup.enabled=true \
  --set backup.s3.bucket=edge-backups \
  --set backup.s3.endpoint=https://minio.example.com \
  --set backup.s3.existingSecret=edge-backup-s3
```

Every night (`backup.schedule`, 03:00 by the cluster's clock by default) a Job dumps the `edge`
database (control plane and OSB) and the `issuer` database, uploads the dumps
with a sha256 `MANIFEST` to `s3://<bucket>/<prefix><timestamp>/`, and only then
points `<prefix>LATEST` at that timestamp. Expire old backups with a lifecycle
rule on the bucket.

To keep Lens's own database in the same backup, add it with the Secret key
that holds its URL:

```yaml
backup:
  extraDatabases:
    - name: lens
      secretName: lens-database
      key: DATABASE_URL
```

Back up now, outside the schedule:

```sh
kubectl -n infra create job --from=cronjob/edge-datastores-backup backup-$(date +%s)
```

Restore — onto the same install, or onto a fresh install of the same version
after you lost the volumes (apply the bucket's Secret again first):

```sh
kubectl -n infra create job --from=cronjob/edge-datastores-restore restore-$(date +%s)
kubectl -n infra logs -f job/<that job> --all-containers
```

The restore Job takes the backup `LATEST` names (or the timestamp in
`backup.restoreFrom`), refuses to start if any dump differs from its
`MANIFEST`, and restores each database in a single transaction — all of it or
none of it. The control plane picks the restored config up on its next
reconcile; nothing needs restarting.

The backup holds SDS keys as they are stored, sealed under `SECRET_KEK` when
you set one. Keep that key apart from the bucket: a restore without it serves
nothing that is sealed.

`pg_dump` and `pg_restore` must be at least your Postgres server's major
version; with your own Postgres, set `backup.images.postgres` to match it.

## Tried on kind

`make kind-datastores` installs the chart both ways on a throwaway kind cluster.
Each must reach Ready with every migration recorded, and a pod holding only the
connection Secret must reach all three stores. The cluster is then deleted.

`make kind-backup` is the restore drill: the backup on and pointed at MinIO,
the edge, issuer and a stand-in Lens database backed up, the namespace deleted
(release, volumes, passwords) and the chart installed again empty, then the
restore Job run. It passes only if the control plane publishes the same config
hash as before the loss and every table holds what it held at the backup.
