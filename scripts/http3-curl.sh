#!/usr/bin/env bash
# HTTP/3 interop with curl (ADR-0032), for the non-required `http3` CI job: starts the rdock
# built with `--features http3` (target/debug/rdock) on 127.0.0.1:8443 with a throw-away
# certificate and a local backend, then runs curl with `--http3-only` from a pinned Debian image
# (its curl is built with nghttp3 and OpenSSL's QUIC API, debian/rules of 8.14.1-2+deb13u7,
# read 2026-11-13). Needs Docker, openssl and python3.
set -euo pipefail

# trixie-20261027-slim (multi-arch index digest from Docker Hub, read 2026-11-13).
IMAGE="debian:trixie-20261027-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4"
RDOCK="${RDOCK:-target/debug/rdock}"
work="$(mktemp -d)"
# shellcheck disable=SC2329 # called by the EXIT trap
cleanup() {
  [ -n "${rdock_pid:-}" ] && kill "$rdock_pid" 2>/dev/null || true
  [ -n "${backend_pid:-}" ] && kill "$backend_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj "/CN=app.test" -addext "subjectAltName=DNS:app.test" \
  -keyout "$work/app.key" -out "$work/app.crt" 2>/dev/null
mkdir -p "$work/www" && echo "hello over http3" > "$work/www/index.html"
python3 -m http.server 8081 --bind 127.0.0.1 --directory "$work/www" >"$work/backend.log" 2>&1 &
backend_pid=$!

cat > "$work/rdock.yaml" <<YAML
acme: false
certificates:
  app: { cert_file: "$work/app.crt", key_file: "$work/app.key" }
listeners:
  websecure: { address: "127.0.0.1:8443", tls: {}, http3: { enabled: true } }
defaults: { tls: off }
routes:
  app: { match: "Host(\`app.test\`)", service: app, listeners: [websecure], tls: { certificate: app } }
services:
  app: { backends: [{ address: "127.0.0.1:8081" }] }
admin: { listener: "127.0.0.1:2080" }
YAML
"$RDOCK" run -c "$work/rdock.yaml" --data-dir "$work/data" >"$work/access.log" 2>"$work/rdock.log" &
rdock_pid=$!
for _ in $(seq 1 100); do
  if curl -sf --noproxy "*" -o /dev/null http://127.0.0.1:2080/readyz; then break; fi
  sleep 0.2
done

status=0
docker run --rm --network host -v "$work/app.crt:/ca.crt:ro" "$IMAGE" sh -euc '
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends curl ca-certificates >/dev/null
  curl -V
  curl -V | grep -q HTTP3 || { echo "this curl has no HTTP/3" >&2; exit 2; }
  out=$(curl -sS --noproxy "*" --http3-only --cacert /ca.crt --resolve app.test:8443:127.0.0.1 -o - -w "\n%{http_version} %{http_code}\n" https://app.test:8443/)
  echo "$out"
  echo "$out" | grep -q "hello over http3"
  echo "$out" | tail -n 1 | grep -qx "3 200"
' || status=$?

# The HTTPS answer advertises HTTP/3.
curl -sS --noproxy "*" --cacert "$work/app.crt" --resolve app.test:8443:127.0.0.1 -D - -o /dev/null https://app.test:8443/ \
  | tr -d '\r' | grep -i '^alt-svc: h3=":8443"; ma=3600$' || status=1
grep -q '"proto":"HTTP/3"' "$work/access.log" || { echo "no HTTP/3 line in the access log" >&2; status=1; }
if [ "$status" -ne 0 ]; then
  echo "--- rdock log ---"; cat "$work/rdock.log"
  echo "--- access log ---"; cat "$work/access.log"
fi
exit "$status"
