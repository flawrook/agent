{{/* The release's full name, at most 63 characters: the release name alone when it already holds the chart's. */}}
{{- define "flawrook-agent.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "flawrook-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "flawrook-agent.labels" -}}
{{ include "flawrook-agent.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "flawrook-agent.serviceAccountName" -}}
{{- .Values.serviceAccount.name | default (include "flawrook-agent.fullname" .) -}}
{{- end -}}

{{/* By tag (the chart's appVersion by default) and, when one is given, by digest, which then decides. */}}
{{- define "flawrook-agent.image" -}}
{{- $ref := printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $ref .Values.image.digest -}}
{{- else -}}
{{- $ref -}}
{{- end -}}
{{- end -}}

{{/* The token's Secret and key: the chart's own, or the one named in flawrook.existingSecret. */}}
{{- define "flawrook-agent.tokenSecret" -}}
{{- .Values.flawrook.existingSecret | default (include "flawrook-agent.fullname" .) -}}
{{- end -}}
{{- define "flawrook-agent.tokenKey" -}}
{{- if .Values.flawrook.existingSecret -}}{{ .Values.flawrook.existingSecretKey }}{{- else -}}token{{- end -}}
{{- end -}}
