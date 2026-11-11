{{/* The pod template shared by the Deployment and the DaemonSet. */}}
{{- define "reversedock.podTemplate" -}}
metadata:
  labels:
    {{- include "reversedock.labels" . | nindent 4 }}
    {{- with .Values.podLabels }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  annotations:
    checksum/config: {{ include "reversedock.config" . | sha256sum }}
    {{- with .Values.podAnnotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  serviceAccountName: {{ include "reversedock.serviceAccountName" . }}
  automountServiceAccountToken: true
  terminationGracePeriodSeconds: {{ include "reversedock.terminationGracePeriod" . }}
  {{- with .Values.imagePullSecrets }}
  imagePullSecrets:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.priorityClassName }}
  priorityClassName: {{ . | quote }}
  {{- end }}
  securityContext:
    {{- toYaml .Values.podSecurityContext | nindent 4 }}
    {{- if and (eq .Values.kind "DaemonSet") (eq .Values.daemonSet.privilegedPorts "sysctl") }}
    sysctls:
      - name: net.ipv4.ip_unprivileged_port_start
        value: "0"
    {{- end }}
  containers:
    - name: rdock
      image: {{ include "reversedock.image" . | quote }}
      imagePullPolicy: {{ .Values.image.pullPolicy }}
      args: ["run"]
      env:
        - name: RDOCK_CONFIG
          value: /etc/rdock/rdock.yaml
        - name: RDOCK_DATA_DIR
          value: /var/lib/rdock
        - name: RDOCK_LOG
          value: {{ .Values.logLevel | quote }}
        - name: RDOCK_LOG_FORMAT
          value: {{ .Values.logFormat | quote }}
        - name: RDOCK_POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: RDOCK_POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        {{- with .Values.extraEnv }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      {{- if or .Values.ingress.enabled .Values.admin.network.enabled }}
      ports:
        {{- if .Values.ingress.enabled }}
        - name: http
          containerPort: {{ .Values.ingress.ports.http }}
          protocol: TCP
          {{- if and (eq .Values.kind "DaemonSet") .Values.daemonSet.hostPorts.enabled }}
          hostPort: {{ .Values.daemonSet.hostPorts.http }}
          {{- end }}
        - name: https
          containerPort: {{ .Values.ingress.ports.https }}
          protocol: TCP
          {{- if and (eq .Values.kind "DaemonSet") .Values.daemonSet.hostPorts.enabled }}
          hostPort: {{ .Values.daemonSet.hostPorts.https }}
          {{- end }}
        {{- end }}
        {{- if .Values.admin.network.enabled }}
        - name: admin
          containerPort: {{ .Values.admin.port }}
          protocol: TCP
        {{- end }}
      {{- end }}
      {{- if .Values.admin.network.enabled }}
      {{- /* The admin API answers only to its configured host names; `localhost` is one of them. */}}
      startupProbe:
        httpGet:
          path: /readyz
          port: admin
          scheme: HTTPS
          httpHeaders:
            - name: Host
              value: localhost
        periodSeconds: {{ .Values.probes.startup.periodSeconds }}
        failureThreshold: {{ .Values.probes.startup.failureThreshold }}
        timeoutSeconds: {{ .Values.probes.startup.timeoutSeconds }}
      readinessProbe:
        httpGet:
          path: /readyz
          port: admin
          scheme: HTTPS
          httpHeaders:
            - name: Host
              value: localhost
        periodSeconds: {{ .Values.probes.readiness.periodSeconds }}
        failureThreshold: {{ .Values.probes.readiness.failureThreshold }}
        timeoutSeconds: {{ .Values.probes.readiness.timeoutSeconds }}
      livenessProbe:
        httpGet:
          path: /healthz
          port: admin
          scheme: HTTPS
          httpHeaders:
            - name: Host
              value: localhost
        periodSeconds: {{ .Values.probes.liveness.periodSeconds }}
        failureThreshold: {{ .Values.probes.liveness.failureThreshold }}
        timeoutSeconds: {{ .Values.probes.liveness.timeoutSeconds }}
      {{- else }}
      {{- /* Loopback admin listener: the probe is `rdock healthcheck`, which asks /readyz on the local admin socket. */}}
      startupProbe:
        exec:
          command: [/usr/local/bin/rdock, healthcheck]
        periodSeconds: {{ .Values.probes.startup.periodSeconds }}
        failureThreshold: {{ .Values.probes.startup.failureThreshold }}
        timeoutSeconds: {{ .Values.probes.startup.timeoutSeconds }}
      readinessProbe:
        exec:
          command: [/usr/local/bin/rdock, healthcheck]
        periodSeconds: {{ .Values.probes.readiness.periodSeconds }}
        failureThreshold: {{ .Values.probes.readiness.failureThreshold }}
        timeoutSeconds: {{ .Values.probes.readiness.timeoutSeconds }}
      livenessProbe:
        exec:
          command: [/usr/local/bin/rdock, healthcheck]
        periodSeconds: {{ .Values.probes.liveness.periodSeconds }}
        failureThreshold: {{ .Values.probes.liveness.failureThreshold }}
        timeoutSeconds: {{ .Values.probes.liveness.timeoutSeconds }}
      {{- end }}
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
      securityContext:
        {{- $sc := deepCopy .Values.securityContext }}
        {{- if and (eq .Values.kind "DaemonSet") (eq .Values.daemonSet.privilegedPorts "capability") }}
        {{- $_ := set $sc "capabilities" (dict "drop" (list "ALL") "add" (list "NET_BIND_SERVICE")) }}
        {{- end }}
        {{- toYaml $sc | nindent 8 }}
      volumeMounts:
        - name: config
          mountPath: /etc/rdock
          readOnly: true
        - name: data
          mountPath: /var/lib/rdock
        - name: tmp
          mountPath: /tmp
        {{- if .Values.admin.network.enabled }}
        - name: admin-tls
          mountPath: /etc/rdock-admin-tls
          readOnly: true
        {{- end }}
        {{- with .Values.extraVolumeMounts }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
  volumes:
    - name: config
      configMap:
        name: {{ include "reversedock.fullname" . }}
    - name: data
      {{- if .Values.data.existingClaim }}
      persistentVolumeClaim:
        claimName: {{ .Values.data.existingClaim }}
      {{- else }}
      emptyDir:
        {{- with .Values.data.medium }}
        medium: {{ . }}
        {{- end }}
        sizeLimit: {{ .Values.data.sizeLimit }}
      {{- end }}
    - name: tmp
      emptyDir:
        sizeLimit: 16Mi
    {{- if .Values.admin.network.enabled }}
    - name: admin-tls
      secret:
        secretName: {{ required "admin.network.tlsSecretName is required when admin.network.enabled is true" .Values.admin.network.tlsSecretName }}
        defaultMode: 0440
    {{- end }}
    {{- with .Values.extraVolumes }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  {{- with .Values.nodeSelector }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.affinity }}
  affinity:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.tolerations }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- if and (eq .Values.kind "Deployment") .Values.topologySpread.enabled }}
  topologySpreadConstraints:
    - maxSkew: {{ .Values.topologySpread.maxSkew }}
      topologyKey: {{ .Values.topologySpread.topologyKey }}
      whenUnsatisfiable: {{ .Values.topologySpread.whenUnsatisfiable }}
      labelSelector:
        matchLabels:
          {{- include "reversedock.selectorLabels" . | nindent 10 }}
  {{- end }}
{{- end }}
