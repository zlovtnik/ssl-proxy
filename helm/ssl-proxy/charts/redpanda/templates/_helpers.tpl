{{/* Local helpers keep names and labels stable across the umbrella split. */}}
{{- define "ssl-proxy.redpanda.name" -}}
{{- default "ssl-proxy" .Values.global.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ssl-proxy.redpanda.fullname" -}}
{{- if .Values.global.fullnameOverride }}
{{- .Values.global.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default "ssl-proxy" .Values.global.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "ssl-proxy.redpanda.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssl-proxy.redpanda.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "ssl-proxy.redpanda.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "ssl-proxy.redpanda.selectorLabels" . }}
app.kubernetes.io/version: "1.0.0"
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "ssl-proxy.redpanda.image" -}}
{{- $repository := .image.repository -}}
{{- with .root.Values.global.image.registry -}}
{{- $repository = printf "%s/%s" (trimSuffix "/" .) $repository -}}
{{- end -}}
{{- printf "%s:%s" $repository .image.tag -}}
{{- end }}

{{- define "ssl-proxy.redpanda.serviceAccountName" -}}
{{- if .Values.global.serviceAccount.create }}
{{- default (include "ssl-proxy.redpanda.fullname" .) .Values.global.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.global.serviceAccount.name }}
{{- end }}
{{- end }}
