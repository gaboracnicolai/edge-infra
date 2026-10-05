{{- define "edge-datastores.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "edge-datastores.labels" -}}
helm.sh/chart: {{ include "edge-datastores.chart" . }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* The in-cluster host of a bundled store. The subcharts name their Service
<release>-<chart>, so this is the same name. */}}
{{- define "edge-datastores.host" -}}
{{- printf "%s-%s.%s.svc.cluster.local" .root.Release.Name .store .root.Release.Namespace -}}
{{- end -}}

{{/* A credential for a bundled store: the value set in values.yaml, else the one
already in the connection Secret (so an upgrade keeps it), else a new random
one. Args: (list $ $existingSecret "KEY" $setValue). */}}
{{- define "edge-datastores.credential" -}}
{{- $existing := index . 1 -}}
{{- $key := index . 2 -}}
{{- $set := index . 3 -}}
{{- if $set -}}
{{- $set -}}
{{- else if and $existing $existing.data (hasKey $existing.data $key) -}}
{{- index $existing.data $key | b64dec -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}
