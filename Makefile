.PHONY: observe observe-down helm-lint helm-template-dry-run argocd-apply argocd-diff docker-build-local

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
	helm lint --strict deploy/helm/edge-controller
	helm lint --strict deploy/helm/edge-proxy
	helm lint --strict deploy/helm/edge-osb
	helm lint --strict deploy/helm/auth-service

# Render each chart with its staging values to verify templates produce valid YAML.
helm-template-dry-run:
	helm template edge-control-plane deploy/helm/edge-control-plane \
	  --values deploy/envs/staging/values-control-plane.yaml
	helm template edge-controller deploy/helm/edge-controller \
	  --values deploy/envs/staging/values-controller.yaml
	helm template edge-proxy deploy/helm/edge-proxy \
	  --values deploy/envs/staging/values-proxy.yaml
	helm template edge-osb deploy/helm/edge-osb \
	  --values deploy/envs/staging/values-osb.yaml
	helm template auth-service deploy/helm/auth-service \
	  --values deploy/envs/staging/values-auth-service.yaml

# Install Argo CD itself, then register the AppProject and all Applications.
argocd-apply:
	kubectl apply -n argocd -f deploy/argocd/install/argocd-install.yaml
	kubectl apply -f deploy/argocd/projects/
	kubectl apply -f deploy/argocd/applications/

# Build all three custom images locally for smoke testing.
docker-build-local:
	docker build -f Dockerfile.control-plane \
	  --target server -t edge-control-plane:local .
	docker build -f Dockerfile.control-plane \
	  --target controller -t edge-controller:local .
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
	@for app in edge-control-plane edge-controller edge-proxy \
	            edge-osb auth-service monitoring; do \
	    argocd app diff $$app --local; \
	done
