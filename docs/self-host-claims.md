# Self-host page claims → the `make kind-e2e` step that runs them

The self-host page is the marketing landing at `https://talyvor.com` (served from
`app.talyvor.com/marketing`; source `talyvor-suite` `apps/web/src/areas/marketing/Landing.tsx`
at `e06e0fc`). This table takes every self-hosting claim on it and names the phase of
`deploy/local/up.sh` that exercises it when `make kind-e2e` runs — on this repo's charts,
on a kind cluster it creates and deletes.

A claim marked **not run** is not exercised by any step, because the thing it is about is
not in any chart in this repository. Saying so is the point of the table: those claims are
not verified in a running system yet.

| # | Claim on the page (line) | Step that runs it | What the step asserts |
|---|---|---|---|
| 1 | "Self-hosted · pre-launch" (407); "Talyvor runs on your infrastructure" (654); footer "self-hosted AI development" (708) | Phases 1–7 | A cluster you create (kind, Calico, cert-manager, Kyverno, Postgres, NATS), images built from this repo, and all seven charts (`edge-control-plane`, `edge-issuer`, `auth-service`, `edge-osb`, `edge-proxy`, `edge-ratelimit`, `edge-secrets`) installed and Ready via `helm --wait`, after the `edge-pki` chart's CAs. Each chart issues its own certificate; Phase 7 fails on any Certificate no helm release owns, so none is applied by hand. Nothing is pulled from a Talyvor-run service. |
| 2 | "You run the gateway" (658) | Phases 7–9 | Envoy (`edge-proxy`) takes its config over mTLS xDS from your control-plane; a request for each tenant through the node's :443 returns 200 from **that** tenant's own backend, and an unknown host returns 404. |
| 3 | "Nobody proxies your traffic but you" / "requests leave from your machines" (216) | Phases 9, 12, 15 | Every request in the run goes host → your Envoy → a stub upstream inside the same cluster, and the stub's fingerprint (`TENANT-A-BACKEND`, `TENANT-B-BACKEND`, whoami's echoed headers, `OSB-PROVISIONED-BACKEND`) comes back. No hop leaves the cluster. |
| 4 | Gateway identity and access (implied by "you run the gateway" for a gated route) | Phases 25, 12, 23 | Phase 25, on the fresh install before anything is switched: ext_authz is on by default, and an OSB service provisioned without naming an `auth_policy` (so `jwt`) answers 401 with no token and 200 with a JWT from your `edge-issuer`. Phase 12 then switches ext_authz off and on live: a real JWT minted by your `edge-issuer` → 200 with identity headers injected and a forged `x-user-email` overwritten; no / garbage token → 401; `auth-service` down → refused (fail-closed), recovers when it returns. Before the switch, a `jwt` route is refused rather than served open. Phase 23 puts an open `/public` route beside the `jwt` one: forged `x-user-id`, `x_user_id`, `x-user-email`, `x-gateway-auth` and `x-auth-iss` sent to it never reach the backend, Envoy appends the real peer after a forged `X-Forwarded-For`, and `/public/../admin`, `/public/%2e%2e/admin` and `/public/..%2Fadmin` without a token are routed as `/admin` and refused with 401. |
| 5 | "your data stays in your Postgres" (658) — for the gateway's own state | Phases 2, 6, 8, 15 | Routes, gateways, clusters, endpoints, tenant keys and provisioning requests are rows in the Postgres inside your cluster; Envoy serves only what is written there (Phase 8 seeds rows, Phase 15 has the broker write them). `make kind-datastores` installs the `edge-datastores` chart twice — running Postgres itself, and pointed at a Postgres it did not create — and each time every migration lands in that database. |
| 6 | Services are provisioned on your gateway (the OSB broker the stack ships) | Phase 15 | `edge-osb` answers `/healthz`; `POST /v1/services` with a tenant key → 202, the worker completes it over NATS, and the new host is served through Envoy :80 by the stub; `DELETE` → completed and the host is no longer served. |
| 7 | Isolation between tenants on your cluster | Phases 10–11, 16 | Kyverno refuses an open NetworkPolicy and a NodePort backend; with the backend policy applied, a pod-network attacker is dropped while the gateway path stays 200. Phase 16 pins each tenant's HTTPS gateway to its own node (`node_selector`): each node's live Envoy SDS holds only its own tenant's TLS key, serves that tenant with its cert and cannot present the other tenant's cert, and after a control-plane restart a freshly restarted edge-proxy is caught up with the same scope. |
| 8 | A bad config never reaches the gateway | Phases 13–14, 22 | A dangling route is refused, Envoy keeps the last good config and keeps serving, and `xds_snapshots_blocked_total{reason="inconsistent"}` rises on the live `/metrics`. Phase 22 adds a second gateway on :443: it is refused, never reaches Envoy, `xds_snapshots_blocked_total{reason="listener_collision"}` rises, and :443 keeps returning 200. |
| 9 | "with your provider keys" (654); "Provider keys live in your environment" (216) | **not run** | Provider keys are held by Lens. No chart here installs Lens. |
| 10 | "Prompts, issues, pages, and spend records sit in your Postgres" (220) | **not run** | Those records belong to Lens and the suite. No chart here installs either; only the gateway's own state (row 5) is exercised. |
| 11 | "Retention is a per-workspace policy you set — including 'log nothing'" (220) | **not run** | A Lens setting. Not in these charts. |
| 12 | "Per-workspace keys, budgets that block at the limit, and a ledger of what every request cost" (224, 190) | **not run** | Lens metering. Not in these charts. (`edge-ratelimit` is installed in Phase 7 but no step asserts a limit.) |
| 13 | "The gateway writes an audit log you can stream out as NDJSON" (228) | **not run** | Lens's audit export. Not in these charts. |
| 14 | "the pool is something you opt into rather than something you are inside by default" (659) | **not run** | Lens / suite sharing setting. Not in these charts. |
| 15 | "Every model call from every tool goes through one self-hosted gateway" (190) | **partly** — rows 2–3 | The Envoy gateway is self-hosted and serves every request in the run. The model-routing gateway the sentence names is Lens, which these charts do not install. |

Rows 9–14 need a Lens chart (or a Lens deployment in this stack) before a step can run them.

Not a claim on the page, but run too: Phase 19 runs the auth-service chart's
confidential-node option — a workload refused without a verified attestation and
started with one, against a mock TEE (real attestation needs confidential VMs).
See [self-host-confidential-compute.md](self-host-confidential-compute.md).

Phase 20 runs one HTTPS port for several hosts, each with its own cert: two routes
on one shared `:9443` gateway each carry a cert, and each host is served its own
cert and backend by SNI, a Host from another SNI finds no route, and an SNI no
route names fails the handshake.

Phase 21 provisions an HTTPS service through the OSB broker with a public host
(`shop.e2e.local`) separate from its upstream (the stub's Service DNS name), on
the broker's configurable shared HTTPS port (`:10443` here, `sharedHttpsPort`):
the host is served its own cert and the stub's body, Envoy holds the upstream as
a STRICT_DNS cluster, and no edge-proxy's `update_rejected` counter moves.

Phase 24 runs access logs and tracing. Every listener writes a JSON access line
per request to the edge-proxy's stdout (`request_id`, `trace_id`, status, route,
upstream, duration, and the path without its query string), and every response
carries the `x-request-id` it was logged under. With `telemetry.otel.enabled` on
the control-plane chart, every listener also sends that record and an
OpenTelemetry span to a collector over OTLP/gRPC. The run reads Envoy's
config_dump on every edge-proxy to check that each connection manager has both
access logs and the tracer. It then curls through :443 and finds the
`x-request-id` curl received in the collector, both as an access-log record and
as a span tagged `guid:x-request-id`. Before the switch, the same request is in
the stdout log and not in the collector. One limit: Envoy's own `http.url` span
tag includes the query string, so strip it in the collector if your clients put
credentials in URLs.

Phase 28 runs the egress gateway agents call out through
([agent-egress.md](agent-egress.md)). A mock TLS provider with a CA of its own
admits only `edge-egress` pods, and the agent's direct call to it, served before
that NetworkPolicy, times out after. Through `edge-egress` the same call is
served twice over: as a CONNECT tunnel with the agent's own TLS, and as plain
HTTP that `edge-egress` sends on over TLS it verifies against the provider's CA.
A host that is not in `egress_destinations` gets 403, CONNECT included, and a
listed host whose certificate does not name it gets 503 while Envoy's
`ssl.fail_verify_san` counter rises.

Phase 29 locks an agent namespace to `edge-egress`
([agent-egress.md](agent-egress.md#locking-agents-in)). The mock provider's own
NetworkPolicy is removed first, so it answers any pod. An agent in a new
namespace calls it directly and is served. Once the namespace is labelled
`talyvor.io/agents=true`, Kyverno writes the `agent-egress-lockdown`
NetworkPolicy into it, the same direct call times out, and the same call through
`edge-egress` is served. Deleted, the NetworkPolicy is written back by Kyverno
and the direct call is dropped again.

Phase 30 makes the mock provider keyless
([agent-egress.md](agent-egress.md#keyless-agents)). An agent in the locked
namespace has a provider key planted in its environment and sends it as
`Authorization`, `x-api-key`, `api-key` and `?key=`. Before the destination is
keyless the provider echoes the key back. Once it is keyless, the key alone gets
407 from `edge-egress`; with the agent's ServiceAccount token as
`Proxy-Authorization` the call is served, the provider's echo holds no key and
no token, and it holds an `x-gateway-auth` assertion naming the agent's
ServiceAccount that verifies against auth-service's published transit key.
CONNECT to the keyless host gets 403, and the direct call is dropped.

Phase 31 gives each agent a rate limit of its own and checks the decision log
([agent-egress.md](agent-egress.md#rate-limits-per-agent)). The control plane is
set to 5 requests a minute per agent. Two pods sharing the ServiceAccount
`rl-alpha` are one agent: the first sends a burst and is served 5 times, then
gets 429; the second, from its own address, gets 429 at once, with
`x-ratelimit-limit: 5` and `retry-after: 60`. A pod of another agent, `rl-beta`,
is served at the same moment. The `edge-egress` access log names the agent of the
429 with `RL` / `local_rate_limited`. The decision log exported from the admin
API holds the 429s, `rl-beta`'s 200 and Phase 30's 407s, all from
`edge-egress`, and `scripts/verify-decisions.sh` verifies the chain from its
first record. Rewritten from `rate_limited` to `allowed` in one record, the same
export no longer verifies.

Phase 34 runs every chart's own `helm test`. Each chart carries a test pod that
reaches what it installs the way a client does — through its Service, past the
chart's NetworkPolicy, which lets exactly that pod in on exactly that port. For
each release this run installed it must pass: the control plane's metrics report
a reconcile, the issuer serves its JWKS over TLS, auth-service and the broker
answer their health checks, the rate-limit service answers a gRPC call, the
secrets custodian refuses a client with neither an operator certificate nor the
admin key, each node's Envoy is
LIVE and connected to its control plane, and `edge-egress` refuses a destination off its allow-list with 403.
`make kind-datastores` runs the `edge-datastores` test (a pod holding only the
connection Secret reaches Postgres, Redis and NATS) and `make kind-observability`
the `edge-observability` one (every component answers on its Service). `make
kubeconform` validates everything the charts render, for every overlay, against
the Kubernetes version kind runs.
