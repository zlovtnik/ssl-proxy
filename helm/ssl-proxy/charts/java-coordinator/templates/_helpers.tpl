{{/* Local helpers keep names and labels stable across the umbrella split. */}}
{{- define "ssl-proxy.javaCoordinator.name" -}}
{{- default "ssl-proxy" .Values.global.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ssl-proxy.javaCoordinator.fullname" -}}
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

{{- define "ssl-proxy.javaCoordinator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssl-proxy.javaCoordinator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "ssl-proxy.javaCoordinator.labels" -}}
helm.sh/chart: ssl-proxy-0.2.0
{{ include "ssl-proxy.javaCoordinator.selectorLabels" . }}
app.kubernetes.io/version: "1.0.0"
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "ssl-proxy.javaCoordinator.image" -}}
{{- $repository := .image.repository -}}
{{- with .root.Values.global.image.registry -}}
{{- $repository = printf "%s/%s" (trimSuffix "/" .) $repository -}}
{{- end -}}
{{- printf "%s:%s" $repository .image.tag -}}
{{- end }}

{{- define "ssl-proxy.javaCoordinator.serviceAccountName" -}}
{{- if .Values.global.serviceAccount.create }}
{{- default (include "ssl-proxy.javaCoordinator.fullname" .) .Values.global.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.global.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "ssl-proxy.javaCoordinator.postgresUrl" -}}
jdbc:postgresql://{{ .Values.global.shared.postgres.host }}:{{ .Values.global.shared.postgres.port }}/{{ .Values.global.shared.postgres.database }}
{{- end }}
