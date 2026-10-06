{{- define "edge-observability.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Labels for one component. Call with (dict "ctx" $ "component" "prometheus").
The Service names are the components' own (prometheus, loki, tempo,
otel-collector, grafana) so the other charts' defaults reach them.
*/}}
{{- define "edge-observability.labels" -}}
helm.sh/chart: {{ include "edge-observability.chart" .ctx }}
{{ include "edge-observability.selectorLabels" . }}
{{- if .ctx.Chart.AppVersion }}
app.kubernetes.io/version: {{ .ctx.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
app.kubernetes.io/part-of: edge-observability
{{- end -}}

{{- define "edge-observability.selectorLabels" -}}
app.kubernetes.io/name: {{ .component }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app: {{ .component }}
{{- end -}}

{{/*
Every container here runs as a non-root user with nothing it does not need.
*/}}
{{- define "edge-observability.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}

{{/*
A pod security context for an image's own non-root uid; fsGroup makes the
data volume writable by it. Call with the uid.
*/}}
{{- define "edge-observability.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ . }}
runAsGroup: {{ . }}
fsGroup: {{ . }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
A data volume: a PVC when persistence is on, an emptyDir otherwise.
Call with (dict "name" <claim name> "persistence" <persistence block>).
*/}}
{{- define "edge-observability.dataVolume" -}}
- name: data
{{- if .persistence.enabled }}
  persistentVolumeClaim:
    claimName: {{ .name }}
{{- else }}
  emptyDir: {}
{{- end }}
{{- end -}}

{{/*
A PVC for a component whose persistence is on.
Call with (dict "ctx" $ "component" <name> "persistence" <persistence block>).
*/}}
{{- define "edge-observability.pvc" -}}
{{- if .persistence.enabled }}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ .component }}-data
  namespace: {{ .ctx.Release.Namespace }}
  labels:
    {{- include "edge-observability.labels" (dict "ctx" .ctx "component" .component) | nindent 4 }}
spec:
  accessModes: [ReadWriteOnce]
  {{- with .persistence.storageClass }}
  storageClassName: {{ . | quote }}
  {{- end }}
  resources:
    requests:
      storage: {{ .persistence.size }}
{{- end }}
{{- end -}}

{{/*
An image reference. With global.imageRegistry set, the image is pulled from that
registry instead, its path kept: grafana/grafana becomes <registry>/grafana/grafana
and a single-name Docker Hub image <registry>/library/<name>.
Call with (dict "image" <an image: block> "global" $.Values.global).
*/}}
{{- define "edge-observability.image" -}}
{{- $repo := toString .image.repository -}}
{{- with .global.imageRegistry -}}
{{- $parts := splitList "/" $repo -}}
{{- $host := "docker.io" -}}
{{- if and (gt (len $parts) 1) (regexMatch "[.:]|^localhost$" (first $parts)) -}}
{{- $host = first $parts -}}
{{- $parts = rest $parts -}}
{{- end -}}
{{- if and (eq $host "docker.io") (eq (len $parts) 1) -}}
{{- $parts = prepend $parts "library" -}}
{{- end -}}
{{- $repo = printf "%s/%s" (trimSuffix "/" .) (join "/" $parts) -}}
{{- end -}}
{{- printf "%s:%s" $repo (toString .image.tag) -}}
{{- end -}}
