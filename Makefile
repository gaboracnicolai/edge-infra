.PHONY: observe observe-down helm-lint helm-template-dry-run verify-xds-mtls verify-image-pins test-integration argocd-apply argocd-diff docker-build-local kind-e2e release-e2e kind-cutover kind-rollback

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
