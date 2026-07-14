{{/* Local helpers keep names and labels stable across the umbrella split. */}}
{{- define "ssl-proxy.redis.name" -}}
{{- default "ssl-proxy" .Values.global.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ssl-proxy.redis.fullname" -}}
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

{{- define "ssl-proxy.redis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssl-proxy.redis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "ssl-proxy.redis.labels" -}}
helm.sh/chart: ssl-proxy-0.2.0
{{ include "ssl-proxy.redis.selectorLabels" . }}
app.kubernetes.io/version: "1.0.0"
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "ssl-proxy.redis.image" -}}
{{- $repository := .image.repository -}}
{{- with .root.Values.global.image.registry -}}
{{- $repository = printf "%s/%s" (trimSuffix "/" .) $repository -}}
{{- end -}}
{{- printf "%s:%s" $repository .image.tag -}}
{{- end }}

{{- define "ssl-proxy.redis.serviceAccountName" -}}
{{- if .Values.global.serviceAccount.create }}
{{- default (include "ssl-proxy.redis.fullname" .) .Values.global.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.global.serviceAccount.name }}
{{- end }}
{{- end }}

