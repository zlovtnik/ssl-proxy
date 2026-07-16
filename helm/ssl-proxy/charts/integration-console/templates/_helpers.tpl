{{/* Local helpers keep names and labels stable across the umbrella split. */}}
{{- define "ssl-proxy.integrationConsole.name" -}}
{{- default "ssl-proxy" .Values.global.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ssl-proxy.integrationConsole.fullname" -}}
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

{{- define "ssl-proxy.integrationConsole.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssl-proxy.integrationConsole.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "ssl-proxy.integrationConsole.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "ssl-proxy.integrationConsole.selectorLabels" . }}
app.kubernetes.io/version: "1.0.0"
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "ssl-proxy.integrationConsole.image" -}}
{{- $repository := .image.repository -}}
{{- with .root.Values.global.image.registry -}}
{{- $repository = printf "%s/%s" (trimSuffix "/" .) $repository -}}
{{- end -}}
{{- printf "%s:%s" $repository .image.tag -}}
{{- end }}

{{- define "ssl-proxy.integrationConsole.serviceAccountName" -}}
{{- if .Values.global.serviceAccount.create }}
{{- default (include "ssl-proxy.integrationConsole.fullname" .) .Values.global.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.global.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "ssl-proxy.integrationConsole.integrationConsoleEnv" -}}
- name: RAILS_ENV
  value: {{ .Values.railsEnv | quote }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.global.shared.postgres.passwordSecret.name }}
      key: {{ .Values.global.shared.postgres.passwordSecret.key }}
- name: PGPASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.global.shared.postgres.passwordSecret.name }}
      key: {{ .Values.global.shared.postgres.passwordSecret.key }}
- name: DATABASE_URL
  value: "postgres://{{ .Values.global.shared.postgres.user }}@{{ .Values.global.shared.postgres.host }}:{{ .Values.global.shared.postgres.port }}/{{ .Values.global.shared.postgres.database }}"
- name: SYNC_DATABASE_URL
  value: "postgres://{{ .Values.global.shared.postgres.user }}@{{ .Values.global.shared.postgres.host }}:{{ .Values.global.shared.postgres.port }}/{{ .Values.global.shared.postgres.database }}"
- name: SYNC_REDPANDA_BOOTSTRAP_SERVERS
  value: {{ .Values.global.shared.redpanda.bootstrapServers | quote }}
- name: INTEGRATION_CONSOLE_REDIS_URL
  value: {{ .Values.global.shared.redis.url | quote }}
- name: INTEGRATION_CONSOLE_REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.global.shared.redis.passwordSecret.name }}
      key: {{ .Values.global.shared.redis.passwordSecret.key }}
- name: MINIO_ENDPOINT
  value: {{ .Values.global.shared.minio.endpoint | quote }}
- name: MINIO_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ .Values.global.shared.minio.accessKeySecret.name }}
      key: {{ .Values.global.shared.minio.accessKeySecret.key }}
- name: MINIO_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.global.shared.minio.secretKeySecret.name }}
      key: {{ .Values.global.shared.minio.secretKeySecret.key }}
- name: MINIO_BUCKET
  value: {{ .Values.global.shared.minio.bucket | quote }}
- name: LOG_FORMAT
  value: {{ .Values.logFormat | quote }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .Values.otlpEndpoint | quote }}
- name: OTEL_EXPORTER_OTLP_PROTOCOL
  value: "grpc"
{{- end }}
