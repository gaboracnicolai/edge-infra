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

{{/*
An image reference. With global.imageRegistry set, the image is pulled from that
registry instead, its path kept: ghcr.io/gaboracnicolai/edge-osb becomes
<registry>/gaboracnicolai/edge-osb, envoyproxy/envoy <registry>/envoyproxy/envoy
and redis <registry>/library/redis.
Call with (dict "image" <an image: block> "global" $.Values.global).
*/}}
{{- define "edge-datastores.image" -}}
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
