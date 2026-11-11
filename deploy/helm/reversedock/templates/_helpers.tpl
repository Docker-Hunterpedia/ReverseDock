{{/* Names, labels and the rdock.yaml the chart renders. */}}

{{- define "reversedock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "reversedock.fullname" -}}
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

{{- define "reversedock.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Labels that select the pods. They are also `pod_selector` in rdock.yaml and must never change. */}}
{{- define "reversedock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "reversedock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "reversedock.labels" -}}
helm.sh/chart: {{ include "reversedock.chart" . }}
{{ include "reversedock.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: controller
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "reversedock.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "reversedock.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "reversedock.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end }}

{{/* Seconds the pod may take to stop: the drain timeout plus 15. */}}
{{- define "reversedock.terminationGracePeriod" -}}
{{- add (int .Values.drainTimeoutSeconds) 15 -}}
{{- end }}

{{/* Name of the Service that exposes Ingress traffic, and the default `ingress.publish_service`. */}}
{{- define "reversedock.ingressServiceName" -}}
{{- printf "%s-ingress" (include "reversedock.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "reversedock.adminServiceName" -}}
{{- printf "%s-admin" (include "reversedock.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Release namespace Role name for the Lease and the per-Gateway Services. */}}
{{- define "reversedock.controlRoleName" -}}
{{- printf "%s-control" (include "reversedock.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* True when the admin API listens on the pod address (needs a TLS Secret). */}}
{{- define "reversedock.adminNetwork" -}}
{{- if .Values.admin.network.enabled }}true{{ end }}
{{- end }}

{{/* The rdock.yaml. `config.extra` is merged over it (maps merge, lists and scalars replace). */}}
{{- define "reversedock.config" -}}
{{- $selector := fromYaml (include "reversedock.selectorLabels" .) -}}
{{- $ingress := dict "enabled" .Values.ingress.enabled "class" .Values.ingress.class "claim_without_class" .Values.ingress.claimWithoutClass "nginx_annotations" .Values.ingress.nginxAnnotations -}}
{{- $publishService := .Values.ingress.publishService -}}
{{- if and (not $publishService) (not .Values.ingress.publishAddress) .Values.ingress.enabled .Values.ingress.service.enabled -}}
{{- $publishService = printf "%s/%s" .Release.Namespace (include "reversedock.ingressServiceName" .) -}}
{{- end -}}
{{- if $publishService }}{{ $_ := set $ingress "publish_service" $publishService }}{{ end -}}
{{- if .Values.ingress.publishAddress }}{{ $_ := set $ingress "publish_address" .Values.ingress.publishAddress }}{{ end -}}
{{- $gateway := dict "enabled" .Values.gateway.enabled "service_type" .Values.gateway.serviceType "service_namespace" .Release.Namespace "pod_selector" $selector "port_range" .Values.gateway.portRange "allow_external_name" .Values.gateway.allowExternalName -}}
{{- $kubernetes := dict "namespaces" .Values.watchNamespaces "controller_name" .Values.gatewayClass.controllerName "gateway" $gateway "ingress" $ingress "leader_election" (dict "enabled" .Values.leaderElection.enabled "lease" .Values.leaderElection.lease) "allow_acme" .Values.allowAcme -}}
{{- if .Values.kubeconfig }}{{ $_ := set $kubernetes "kubeconfig" .Values.kubeconfig }}{{ end -}}
{{- $admin := dict "enabled" true "dashboard" false "api_writes" false -}}
{{- if .Values.admin.network.enabled -}}
{{- $hosts := list "localhost" (include "reversedock.adminServiceName" .) (printf "%s.%s" (include "reversedock.adminServiceName" .) .Release.Namespace) (printf "%s.%s.svc" (include "reversedock.adminServiceName" .) .Release.Namespace) (printf "%s.%s.svc.cluster.local" (include "reversedock.adminServiceName" .) .Release.Namespace) -}}
{{- $_ := set $admin "listener" (printf "0.0.0.0:%d" (int .Values.admin.port)) -}}
{{- $_ := set $admin "tls" (dict "cert_file" "/etc/rdock-admin-tls/tls.crt" "key_file" "/etc/rdock-admin-tls/tls.key") -}}
{{- $_ := set $admin "allowed_hosts" (concat $hosts .Values.admin.network.allowedHosts) -}}
{{- else -}}
{{- $_ := set $admin "listener" (printf "127.0.0.1:%d" (int .Values.admin.port)) -}}
{{- end -}}
{{- $listeners := dict -}}
{{- $defaults := dict -}}
{{- if .Values.ingress.enabled -}}
{{- $_ := set $listeners "web" (dict "address" (printf "0.0.0.0:%d" (int .Values.ingress.ports.http))) -}}
{{- $_ := set $listeners "websecure" (dict "address" (printf "0.0.0.0:%d" (int .Values.ingress.ports.https)) "tls" (dict "policy" "intermediate")) -}}
{{- $_ := set $defaults "listeners" (list "web" "websecure") -}}
{{- $_ := set $defaults "tls" "off" -}}
{{- $_ := set $defaults "redirect_http_to_https" false -}}
{{- end -}}
{{- $config := dict "admin" $admin "lifecycle" (dict "drain_timeout" (printf "%ds" (int .Values.drainTimeoutSeconds))) "observability" (dict "metrics" (dict "prometheus" true)) "providers" (dict "kubernetes" $kubernetes) -}}
{{- /* Automatic HTTPS is on by default in rdock and refused in a cluster unless allow_acme is set (ADR-0029). */ -}}
{{- if not .Values.allowAcme -}}
{{- $_ := set $config "acme" false -}}
{{- end -}}
{{- if $listeners }}{{ $_ := set $config "listeners" $listeners }}{{ $_ := set $config "defaults" $defaults }}{{ end -}}
{{- mustMergeOverwrite $config (deepCopy .Values.config.extra) | toYaml -}}
{{- end }}
