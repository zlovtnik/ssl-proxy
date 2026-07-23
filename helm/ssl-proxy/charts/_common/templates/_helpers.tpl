{{/*
Shared name helper. Usage:
  {{ include "ssl-proxy-common.name" (dict "root" . "component" "proxy") }}
Uses .root.Values.global.nameOverride, default "ssl-proxy".
*/}}
{{- define "ssl-proxy-common.name" -}}
{{- default "ssl-proxy" .root.Values.global.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Shared fullname helper. Usage:
  {{ include "ssl-proxy-common.fullname" (dict "root" . "component" "proxy") }}
*/}}
{{- define "ssl-proxy-common.fullname" -}}
{{- if .root.Values.global.fullnameOverride }}
{{- .root.Values.global.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default "ssl-proxy" .root.Values.global.nameOverride }}
{{- if contains $name .root.Release.Name }}
{{- .root.Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .root.Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Shared selector labels. Usage:
  {{ include "ssl-proxy-common.selectorLabels" (dict "root" . "component" "proxy") }}
*/}}
{{- define "ssl-proxy-common.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssl-proxy-common.name" . }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end }}

{{/*
Shared labels. Usage:
  {{ include "ssl-proxy-common.labels" (dict "root" . "component" "proxy") }}
*/}}
{{- define "ssl-proxy-common.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "ssl-proxy-common.selectorLabels" . }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
{{- with .root.Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Shared image reference, optionally prefixed by global registry. Usage:
  {{ include "ssl-proxy-common.image" (dict "root" . "image" .Values.image) }}
*/}}
{{- define "ssl-proxy-common.image" -}}
{{- $repository := .image.repository -}}
{{- with .root.Values.global.image.registry -}}
{{- $repository = printf "%s/%s" (trimSuffix "/" .) $repository -}}
{{- end -}}
{{- printf "%s:%s" $repository .image.tag -}}
{{- end }}

{{/*
Shared service account name. Usage:
  {{ include "ssl-proxy-common.serviceAccountName" (dict "root" . "component" "proxy") }}
*/}}
{{- define "ssl-proxy-common.serviceAccountName" -}}
{{- if .root.Values.global.serviceAccount.create }}
{{- default (include "ssl-proxy-common.fullname" .) .root.Values.global.serviceAccount.name }}
{{- else }}
{{- default "default" .root.Values.global.serviceAccount.name }}
{{- end }}
{{- end }}
