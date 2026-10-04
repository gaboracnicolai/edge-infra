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
| 1 | "Self-hosted · pre-launch" (407); "Talyvor runs on your infrastructure" (654); footer "self-hosted AI development" (708) | Phases 1–7 | A cluster you create (kind, Calico, cert-manager, Kyverno, Postgres, NATS), images built from this repo, and all seven charts (`edge-control-plane`, `edge-issuer`, `auth-service`, `edge-osb`, `edge-proxy`, `edge-ratelimit`, `edge-secrets`) installed and Ready via `helm --wait`. Nothing is pulled from a Talyvor-run service. |
| 2 | "You run the gateway" (658) | Phases 7–9 | Envoy (`edge-proxy`) takes its config over mTLS xDS from your control-plane; a request for each tenant through the node's :443 returns 200 from **that** tenant's own backend, and an unknown host returns 404. |
| 3 | "Nobody proxies your traffic but you" / "requests leave from your machines" (216) | Phases 9, 12, 15 | Every request in the run goes host → your Envoy → a stub upstream inside the same cluster, and the stub's fingerprint (`TENANT-A-BACKEND`, `TENANT-B-BACKEND`, whoami's echoed headers, `OSB-PROVISIONED-BACKEND`) comes back. No hop leaves the cluster. |
| 4 | Gateway identity and access (implied by "you run the gateway" for a gated route) | Phase 12 | ext_authz switched on live: a real JWT minted by your `edge-issuer` → 200 with identity headers injected and a forged `x-user-email` overwritten; no / garbage token → 401; `auth-service` down → refused (fail-closed), recovers when it returns. Before the switch, a `jwt` route is refused rather than served open. |
| 5 | "your data stays in your Postgres" (658) — for the gateway's own state | Phases 2, 6, 8, 15 | Routes, gateways, clusters, endpoints, tenant keys and provisioning requests are rows in the Postgres inside your cluster; Envoy serves only what is written there (Phase 8 seeds rows, Phase 15 has the broker write them). |
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
