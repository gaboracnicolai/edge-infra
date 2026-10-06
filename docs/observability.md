# Observability: the `edge-observability` chart

One release gives a Talyvor Edge cluster Prometheus, Loki, Tempo, an OpenTelemetry collector and
Grafana. Grafana comes with the gateway's dashboards, and Prometheus with its alert and recording
rules.

```bash
helm install edge-observability deploy/helm/edge-observability -n monitoring --create-namespace

kubectl -n monitoring get secret edge-observability-grafana \
  -o jsonpath='{.data.admin-password}' | base64 -d          # user: admin
kubectl -n monitoring port-forward svc/grafana 3000:3000    # http://localhost:3000
```

Grafana opens on **Request Traffic**: the gateway's requests per second and per upstream cluster,
latency percentiles, the 5xx ratio and edge-proxy's error log lines. The folder *Talyvor Edge* also
holds Edge Fleet Overview, Control Plane Health, Auth / AuthZ and OSB Activity.

## What it collects, and from where

| Signal | How it gets in | Where it is kept |
|---|---|---|
| Metrics | Prometheus scrapes every pod annotated `prometheus.io/scrape: "true"` on `prometheus.io/port` at `prometheus.io/path`. edge-proxy, edge-egress, edge-control-plane, auth-service and edge-osb carry these annotations out of the box. edge-proxy and edge-egress are scraped on their stats listener (`:9903`), never on the admin port. | Prometheus, 15 days (`prometheus.retention`) |
| Traces | OTLP to `otel-collector.monitoring.svc.cluster.local:4317`, the address edge-control-plane's `telemetry.otel.address` already defaults to. Turn on `telemetry.otel.enabled` there and every listener's spans arrive. | Tempo, 14 days (`tempo.retention`) |
| Logs | OTLP the same way: edge-control-plane's `telemetry.otel` sends every listener's access record too. Loki takes OTLP natively, labelled by `service_name`. | Loki, 14 days (`loki.retention`) |
| Metrics over OTLP | Through the collector into Prometheus (remote write). | Prometheus |

The alert and recording rules are in `deploy/helm/edge-observability/rules/`. CI runs `promtool check
rules` on them (`make observability-rules`), and the kind drill checks that Prometheus loads and
evaluates every one of them.

## Choices

- **Your own Prometheus Operator** (kube-prometheus-stack): `--set prometheus.enabled=false
  --set prometheusOperator.enabled=true --set prometheusOperator.labels.release=<your release>`.
  The chart then renders a PodMonitor for each Edge component and a PrometheusRule for each rules
  file instead. Point Grafana at your Prometheus with `grafana.datasources.prometheusUrl`, or switch
  Grafana off too.
- **NetworkPolicies on**: an Edge chart with `networkPolicy.enabled` refuses Prometheus until you
  open the metrics port to `monitoring` in that chart's `networkPolicy.extraIngress`, e.g.
  `[{from: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: monitoring}}}], ports: [{port: metrics}]}]`.
- **Your own Grafana admin Secret**: `grafana.admin.existingSecret` (keys `admin-user`,
  `admin-password`). Otherwise the chart makes one with a random password, keeps it across
  upgrades, and leaves it in place on uninstall.
- **Air-gapped / mirror**: `global.imageRegistry=registry.internal:5000` pulls all five images from
  there, paths kept. Nothing in the release calls out: Loki's and Tempo's usage reports, Grafana's
  update checks, news feed and plugin downloads are all off.
- **Storage**: Prometheus, Loki and Tempo each claim a 20Gi volume (`<component>.persistence`).
  Grafana needs none — its dashboards and datasources are provisioned on every start.

## The drill

`make kind-observability` (`deploy/local/observability.sh`) runs the chart on a kind cluster it
creates and deletes, and CI runs it on every change to the chart
(`.github/workflows/kind-observability.yaml`):

1. The chart is installed as above; all five components become Ready.
2. Prometheus, asked through Grafana, has loaded every rule group and evaluated every rule with
   health `ok`.
3. An Envoy labelled and annotated like edge-proxy, with its stats listener, is placed in front of a
   tenant backend. Prometheus finds it with no extra configuration. Before any request, the Request
   Traffic dashboard's *RPS by cluster* panel shows no rate for the tenant.
4. 300 requests go through Envoy, and every one is answered 200.
5. The same panel query, run through Grafana, shows the tenant above zero requests per second. The
   Envoy counter it reads holds exactly 300.
6. A log record and a span sent to the collector come back out of Loki and Tempo through Grafana.
