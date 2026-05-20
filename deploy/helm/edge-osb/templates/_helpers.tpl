{{- define "edge-osb.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "edge-osb.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "edge-osb.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "edge-osb.labels" -}}
helm.sh/chart: {{ include "edge-osb.chart" . }}
{{ include "edge-osb.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "edge-osb.selectorLabels" -}}
app.kubernetes.io/name: {{ include "edge-osb.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: edge-osb
{{- end -}}

{{- define "edge-osb.apiSelectorLabels" -}}
{{ include "edge-osb.selectorLabels" . }}
component: api
{{- end -}}

{{- define "edge-osb.workerSelectorLabels" -}}
{{ include "edge-osb.selectorLabels" . }}
component: worker
{{- end -}}

{{- define "edge-osb.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "edge-osb.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
