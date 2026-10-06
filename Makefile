.PHONY: observe observe-down helm-lint helm-template-dry-run verify-xds-mtls verify-image-pins verify-image-registry verify-images scan-images release-version-test test-integration argocd-apply argocd-diff docker-build-local kind-e2e release-e2e kind-cutover kind-rollback kind-datastores kind-backup kind-observability observability-rules

# Apply the unified observability stack to the active kubeconfig context.
# Generates the grafana-dashboards ConfigMap from the JSON files on disk so
# Grafana provisioning picks them up automatically.
observe:
	kubectl apply -f observability/k8s/namespace.yaml
	kubectl apply -f observability/k8s/otel-collector/
	kubectl apply -f observability/k8s/prometheus/
	kubectl apply -f observability/k8s/loki/
	kubectl apply -f observability/k8s/tempo/
	kubectl apply -f observability/k8s/grafana/
	kubectl create configmap grafana-dashboards \
	    --from-file=observability/grafana/dashboards/ \
	    -n monitoring \
	    --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n monitoring rollout status deployment/grafana

# Tear down the monitoring namespace and all components.
observe-down:
	kubectl delete -f observability/k8s/grafana/ --ignore-not-found
	kubectl delete -f observability/k8s/tempo/   --ignore-not-found
	kubectl delete -f observability/k8s/loki/    --ignore-not-found
	kubectl delete -f observability/k8s/prometheus/ --ignore-not-found
	kubectl delete -f observability/k8s/otel-collector/ --ignore-not-found
	kubectl delete configmap grafana-dashboards -n monitoring --ignore-not-found
	kubectl delete -f observability/k8s/namespace.yaml --ignore-not-found

# Lint every Helm chart with --strict.
helm-lint:
	helm lint --strict deploy/helm/edge-control-plane
	helm lint --strict deploy/helm/edge-proxy
	helm lint --strict deploy/helm/edge-osb
	helm lint --strict deploy/helm/auth-service
	helm lint --strict deploy/helm/edge-issuer
	helm lint --strict deploy/helm/edge-ratelimit
	helm lint --strict deploy/helm/edge-datastores

# Render each chart with its staging values to verify templates produce valid YAML.
helm-template-dry-run:
	helm template edge-control-plane deploy/helm/edge-control-plane \
	  --values deploy/envs/staging/values-control-plane.yaml
	helm template edge-proxy deploy/helm/edge-proxy \
	  --values deploy/envs/staging/values-proxy.yaml
	helm template edge-osb deploy/helm/edge-osb \
	  --values deploy/envs/staging/values-osb.yaml
	helm template auth-service deploy/helm/auth-service \
	  --values deploy/envs/staging/values-auth-service.yaml
	helm template edge-issuer deploy/helm/edge-issuer \
	  --values deploy/envs/staging/values-issuer.yaml
	helm template edge-ratelimit deploy/helm/edge-ratelimit \
	  --values deploy/envs/staging/values-ratelimit.yaml

# Invariant lock: assert the edge-proxy bootstrap renders xDS mutual TLS with
# peer pinning (SNI + SAN==controlPlaneHost) for base + every env overlay.
# Fails if anyone reverts xDS to plaintext or drops the SAN pin.
verify-xds-mtls:
	bash deploy/hack/verify-xds-mtls.sh

# Render every chart for base + every env overlay and fail if any image runs on
# :latest or no tag. Pin images to the SHA you pushed, as the server does.
verify-image-pins:
	bash deploy/hack/verify-image-pins.sh

# Every chart rendered with global.imageRegistry set pulls every image it runs
# from that registry (a mirror, or an air-gapped install's local registry).
verify-image-registry:
	IMAGE_REGISTRY=registry.internal:5000 bash deploy/hack/verify-image-pins.sh

# Before you install: every image the charts pull at :$(TAG) (a release such as
# 1.2.3, or a commit sha) carries a cosign signature, an SPDX SBOM and SLSA
# provenance, all made by this repo's images.yaml. Needs cosign and jq.
verify-images:
	@test -n "$(TAG)" || { echo "usage: make verify-images TAG=<release or sha>"; exit 2; }
	bash deploy/hack/supply-chain.sh verify $(TAG)

# Before you install: no image the charts pull at :$(TAG) carries a known HIGH or
# CRITICAL vulnerability that has a fix. Needs trivy
# (bash deploy/hack/image-scan.sh install <dir> fetches the pinned one).
scan-images:
	@test -n "$(TAG)" || { echo "usage: make scan-images TAG=<release or sha>"; exit 2; }
	bash deploy/hack/image-scan.sh scan $(TAG)

# A v<SemVer> git tag packages every chart at that version: the release version
# script and its packaged-chart check, on a throwaway tag. Needs helm.
release-version-test:
	bash deploy/hack/release-version-test.sh

# Cross-language integration test for the OSB -> data-plane translator: stands up
# a throwaway Postgres with BOTH schemas and proves an OSB provision surfaces in
# a snapshot the Go reconciler serves. Requires docker + go + python3.
test-integration:
	bash test/integration/run.sh

# The self-host stack end to end on a throwaway kind cluster: create it, install
# every chart, send requests through Envoy, ext_authz and stub upstreams, check
# the OSB broker answers and provisions a served route, then delete the cluster.
# Needs docker, kind, kubectl, helm, jq, openssl, curl and free host ports 80/443.
# What each step proves: docs/self-host-claims.md.
kind-e2e:
	bash deploy/local/e2e.sh

# kind-e2e on the RELEASE instead of the working tree: nothing is built; every
# first-party image is pulled from the registry at the one tag the charts pin
# (bash deploy/hack/release-pin.sh <tag> first). Same tools and host ports as
# kind-e2e, plus a login to the registry for its private packages.
release-e2e:
	IMAGE_SOURCE=registry bash deploy/local/e2e.sh

# The CFG-1 launch-day cutover rehearsed in order on a throwaway kind cluster:
# main as committed (the image pin serves nothing) -> image bump -> auth-service
# with JWKS and mTLS -> client certificate -> enable, with a check after each
# step, then the cluster deleted. Same tools and host ports as kind-e2e.
# Real-cluster steps: docs/ext-authz-launch-runbook.md.
kind-cutover:
	bash deploy/local/cutover.sh

# The ext_authz rollback rehearsed on a throwaway kind cluster: from the cutover
# state, with the auth-service down, flipping extAuthz.enabled back alone is shown
# to leave every gated request denied, and the full revert (jwt routes out, then
# the control-plane release back to its pre-enable revision) to restore exactly
# the pre-enable traffic. Same tools and host ports as kind-e2e.
# Real-cluster rollback: docs/ext-authz-cutover-and-rollback.md §2.
kind-rollback:
	bash deploy/local/rollback.sh

# The edge-datastores chart in both modes on a throwaway kind cluster: bundled
# (Postgres, Redis and NATS from the chart) and external (all three switched off,
# pointed at datastores it did not create). Each must reach Ready with every
# migration recorded and be reachable through the connection Secret alone; then
# the cluster is deleted. Needs docker, kind, kubectl, helm and jq.
kind-datastores:
	bash deploy/local/datastores.sh

# The backup and restore drill on a throwaway kind cluster: edge-datastores with
# its backup on, pointed at MinIO; the edge, issuer and a stand-in Lens database
# backed up; the namespace deleted and the chart installed again empty; then the
# chart's restore Job run. Passes only if the control plane publishes the same
# config hash as before the loss and every table matches the backup. Then the
# cluster is deleted. Needs docker, kind, kubectl, helm and jq.
kind-backup:
	bash deploy/local/backup.sh

# The edge-observability chart on a throwaway kind cluster: installed as its
# values.yaml says, every rule file loaded and evaluated by Prometheus, then
# requests through an Envoy set up like edge-proxy. Passes only if Grafana's
# Request Traffic dashboard shows that Envoy's request rate (none before the
# requests, above zero after, the counter equal to the requests sent), and a
# log record and a span sent to the collector come back out of Loki and Tempo.
# Then the cluster is deleted. Needs docker, kind, kubectl, helm, jq and curl.
kind-observability:
	bash deploy/local/observability.sh

# Every alert and recording rule edge-observability loads (its rules/ directory,
# mounted into Prometheus and turned into PrometheusRules) passes promtool.
observability-rules:
	promtool check rules deploy/helm/edge-observability/rules/*.yaml

# Install Argo CD itself, then register the AppProject and all Applications.
argocd-apply:
	kubectl apply -n argocd -f deploy/argocd/install/argocd-install.yaml
	kubectl apply -f deploy/argocd/projects/
	kubectl apply -f deploy/argocd/applications/

# Build all three custom images locally for smoke testing.
docker-build-local:
	docker build -f Dockerfile.control-plane \
	  --target server -t edge-control-plane:local .
	docker build -f osb/Dockerfile \
	  -t edge-osb:local .
	cd auth-service && \
	  cargo build --release && \
	  mkdir -p dist && \
	  cp target/release/auth-service dist/auth-service && \
	  docker build -f Dockerfile \
	    --build-arg BUILD_MODE=local \
	    -t auth-service:local .

# Diff every managed Application against its in-cluster state.
argocd-diff:
	@for app in edge-control-plane edge-proxy \
	            edge-osb auth-service edge-issuer edge-ratelimit edge-policies monitoring; do \
	    argocd app diff $$app --local; \
	done
