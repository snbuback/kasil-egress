{{- define "egress.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "egress.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "egress.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "egress.labels" -}}
helm.sh/chart: {{ include "egress.chart" . }}
{{ include "egress.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: egress
{{- end -}}

{{- define "egress.selectorLabels" -}}
app.kubernetes.io/name: {{ include "egress.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "egress.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "egress.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "egress.collectorImage" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "egress.cliImage" -}}
{{- printf "%s:%s" .Values.cliImage.repository (default .Chart.AppVersion .Values.cliImage.tag) -}}
{{- end -}}

{{- define "egress.dsnEnv" -}}
- name: EGRESS_DSN_FILE
  value: /etc/egress/dsn/{{ .Values.postgres.dsnSecretKey }}
{{- end -}}

{{- define "egress.dsnVolume" -}}
- name: dsn
  secret:
    secretName: {{ .Values.postgres.dsnSecretName }}
    optional: false
{{- end -}}

{{- define "egress.dsnVolumeMount" -}}
- name: dsn
  mountPath: /etc/egress/dsn
  readOnly: true
{{- end -}}
