{{/* Local helpers keep names and labels stable across the umbrella split. */}}
{{- define "ssl-proxy.telemetry.name" -}}
{{- default "ssl-proxy" .Values.global.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ssl-proxy.telemetry.fullname" -}}
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

{{- define "ssl-proxy.telemetry.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssl-proxy.telemetry.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "ssl-proxy.telemetry.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "ssl-proxy.telemetry.selectorLabels" . }}
app.kubernetes.io/version: "1.0.0"
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "ssl-proxy.telemetry.image" -}}
{{- $repository := .image.repository -}}
{{- with .root.Values.global.image.registry -}}
{{- $repository = printf "%s/%s" (trimSuffix "/" .) $repository -}}
{{- end -}}
{{- printf "%s:%s" $repository .image.tag -}}
{{- end }}

{{- define "ssl-proxy.telemetry.serviceAccountName" -}}
{{- if .Values.global.serviceAccount.create }}
{{- default (include "ssl-proxy.telemetry.fullname" .) .Values.global.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.global.serviceAccount.name }}
{{- end }}
{{- end }}
