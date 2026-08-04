{{/* Schema Migrator chart-specific helpers (not provided by ssl-proxy-common). */}}

{{- define "ssl-proxy.schemaMigrator.componentName" -}}
{{- printf "%s-schema-migrator-%s" (include "ssl-proxy-common.fullname" (dict "root" .root "component" "schemaMigrator")) .component | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ssl-proxy.schemaMigrator.publicOrigin" -}}
{{- printf "https://%s" .Values.publicHostname -}}
{{- end }}

{{- define "ssl-proxy.schemaMigrator.uiOrigin" -}}
{{- if .Values.ui.browserOrigin -}}
{{- .Values.ui.browserOrigin -}}
{{- else -}}
{{- include "ssl-proxy.schemaMigrator.publicOrigin" . -}}
{{- end -}}
{{- end }}

{{- define "ssl-proxy.schemaMigrator.keycloakOrigin" -}}
{{- if .Values.keycloak.browserOrigin -}}
{{- .Values.keycloak.browserOrigin -}}
{{- else -}}
{{- include "ssl-proxy.schemaMigrator.publicOrigin" . -}}
{{- end -}}
{{- end }}
