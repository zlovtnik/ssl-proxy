{{- define "ssl-proxy.integrationConsole.fullname" -}}
{{- printf "%s-integration-console" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "ssl-proxy.integrationConsole.image" -}}
{{- $registry := trimSuffix "/" .Values.global.image.registry -}}
{{- if $registry }}{{ printf "%s/%s:%s" $registry .Values.image.repository .Values.image.tag }}{{ else }}{{ printf "%s:%s" .Values.image.repository .Values.image.tag }}{{ end -}}
{{- end -}}
