{{/*
Expand the name of the chart.
*/}}
{{- define "ssl-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ssl-proxy.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ssl-proxy.labels" -}}
helm.sh/chart: {{ include "ssl-proxy.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "ssl-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ssl-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssl-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Redpanda bootstrap servers connection string
*/}}
{{- define "ssl-proxy.redpandaBootstrapServers" -}}
{{- .Values.redpanda.bootstrapServers }}
{{- end }}

{{/*
Postgres connection URL
*/}}
{{- define "ssl-proxy.postgresUrl" -}}
postgres://{{ .Values.postgres.user }}:$(POSTGRES_PASSWORD)@{{ .Values.postgres.host }}:{{ .Values.postgres.port }}/{{ .Values.postgres.database }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "ssl-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ssl-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}