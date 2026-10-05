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

## Tried on kind

`make kind-datastores` installs the chart both ways on a throwaway kind cluster.
Each must reach Ready with every migration recorded, and a pod holding only the
connection Secret must reach all three stores. The cluster is then deleted.
