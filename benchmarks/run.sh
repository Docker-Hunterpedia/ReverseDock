#!/usr/bin/env bash
# Runs every proxy at every rate and writes results/<version>/<proxy>-<rate>.json and
# results/<version>/report.md.
#   ./run.sh                        # all proxies, default rates, one backend
#   PROXIES="rdock nginx" RATES="5000 20000" DURATION=60s ./run.sh
#   SCENARIO=lb ./run.sh            # results/<version>/<scenario>/
#   CONFIG=tuned SCENARIO=h2 ./run.sh   # results/<version>/<scenario>-tuned/
#   PIN=1 ./run.sh                  # pin cores (compose.pinned.yaml), for hosted runners
# Scenarios: single (default) one backend; lb round-robin over three backends; tls HTTPS with
# kept-alive connections on HTTP/1.1; tls-ramped the same with the rate reached over RAMP (2 s)
# instead of at once; tls-new a TLS handshake for every request; h2 HTTPS with kept-alive
# connections on HTTP/2; slow a backend that takes 100 ms; routes 1,000 hosts, each with its own
# route; large and huge 100 KiB and 1 MiB answers.
# CONFIG=default (the default) uses configs/ (configs/<scenario>/); CONFIG=tuned uses
# configs/tuned/ for single, large, huge and slow and configs/tuned/tls/ for the TLS scenarios
# (README "Default and tuned configurations"). The proxy `direct` sends k6 straight to the backend,
# the ceiling the generator and backend reach without a proxy (plain HTTP scenarios only).
# Every TLS scenario checks what each proxy negotiated (README "TLS parity"); a mismatch is shown
# in report.md and makes the script exit 3 after the report is written.
# CPU_STAT=1 also records the proxy's cgroup CPU time over each rate (cpu-stat.sh) in
# <proxy>-<rate>.cpu next to the k6 result; compare.py and cpu-ladder.sh read it.
set -euo pipefail
cd "$(dirname "$0")"
PROXIES=${PROXIES:-"rdock nginx haproxy caddy traefik"}
RATES=${RATES:-"5000 10000 20000 40000"}
DURATION=${DURATION:-30s}
VERSION=${VERSION:-dev}
SCENARIO=${SCENARIO:-single}
CONFIG=${CONFIG:-default}
CPU_STAT=${CPU_STAT:-0}
PIN=${PIN:-0}
SCHEME=http; URLPATH=/; BACKENDS="backend"; OUT="results/$VERSION/$SCENARIO"; EXTRA=()
COMPOSE=(docker compose -f compose.yaml)
if [ "$PIN" = 1 ]; then
  COMPOSE+=(-f compose.pinned.yaml)
  cpus=$(nproc)
  # compose.pinned.yaml's defaults need four CPUs: 0-1 for the proxy, 2-3 for backend and k6.
  if [ -z "${PROXY_CPUSET:-}" ] && [ "$cpus" -lt 4 ]; then
    echo "PIN=1 needs 4 CPUs (this machine has $cpus); set PROXY_CPUSET and LOAD_CPUSET" >&2
    exit 2
  fi
fi
# Go clients (k6) offer the hybrid post-quantum group X25519MLKEM768 by default since Go 1.24,
# and SecP256r1MLKEM768/SecP384r1MLKEM1024 since Go 1.26 (https://go.dev/doc/godebug, read
# 2026-11-14); the proxies support different groups, so k6 is told to offer the classic groups
# only and every proxy that allows it is set to X25519 (README "TLS parity").
TLS_GODEBUG="tlsmlkem=0,tlssecpmlkem=0"
EXPECT=()
export CONFIGS=./configs BACKEND_CPUS=4 TRAEFIK_STATIC=./configs/traefik.yml
TUNED=./configs/tuned
case $SCENARIO in
  single) OUT="results/$VERSION"; [ "$CONFIG" = tuned ] && CONFIGS=$TUNED ;;
  lb) BACKENDS="backend backend-2 backend-3"; CONFIGS=./configs/lb; BACKEND_CPUS=1.33 ;;
  tls | tls-new | tls-ramped | h2)
    SCHEME=https; CONFIGS=./configs/tls
    [ "$CONFIG" = tuned ] && CONFIGS=$TUNED/tls
    if [ "$SCENARIO" = h2 ]; then
      # HTTP/2 over TLS, negotiated by ALPN; k6 sends one request at a time per connection.
      EXTRA=(-e "GODEBUG=$TLS_GODEBUG")
      EXPECT=(-e EXPECT_PROTO=HTTP/2.0)
    else
      # HTTP/1.1 for everyone in the other TLS scenarios.
      EXTRA=(-e "GODEBUG=http2client=0,$TLS_GODEBUG")
      EXPECT=(-e EXPECT_PROTO=HTTP/1.1)
    fi
    EXPECT+=(-e EXPECT_TLS=1.3 -e EXPECT_CIPHER=TLS_AES_128_GCM_SHA256)
    [ "$SCENARIO" = tls-new ] && EXTRA+=(-e NEW_CONNECTIONS=1)
    # k6 opens a connection per virtual user on its first request; reaching the rate over
    # RAMP spreads those handshakes instead of opening them all in the first 50 ms (issue 181).
    [ "$SCENARIO" = tls-ramped ] && EXTRA+=(-e "RAMP=${RAMP:-2s}")
    ;;
  slow) BACKENDS="backend-slow"; URLPATH="/?wait=100ms"; [ "$CONFIG" = tuned ] && CONFIGS=$TUNED ;;
  large | huge)
    # Response bodies of 100 KiB and 1 MiB instead of 1 KiB; lower rates, see README.
    mkdir -p backend/bodies
    [ -f backend/bodies/100k.bin ] || head -c 102400 /dev/urandom > backend/bodies/100k.bin
    [ -f backend/bodies/1m.bin ] || head -c 1048576 /dev/urandom > backend/bodies/1m.bin
    [ "$SCENARIO" = large ] && URLPATH=/bodies/100k.bin || URLPATH=/bodies/1m.bin
    [ "$CONFIG" = tuned ] && CONFIGS=$TUNED
    ;;
  routes)
    CONFIGS=./configs/routes
    python3 -I gen-routes.py configs/routes 1000
    EXTRA=(-e HOSTS=1000)
    ;;
  *) echo "SCENARIO is single, lb, tls, tls-ramped, tls-new, h2, slow, routes, large or huge" >&2; exit 2 ;;
esac
case $CONFIG in
  default) ;;
  tuned)
    if [ "${CONFIGS#"$TUNED"}" = "$CONFIGS" ]; then
      echo "no tuned configuration for SCENARIO=$SCENARIO (single, tls, tls-ramped, tls-new, h2, slow, large, huge)" >&2
      exit 2
    fi
    TRAEFIK_STATIC=$TUNED/traefik.yml
    [ "$SCENARIO" = single ] && OUT="results/$VERSION/single-tuned" || OUT="$OUT-tuned"
    ;;
  *) echo "CONFIG is default or tuned" >&2; exit 2 ;;
esac
# A throwaway certificate, the same file for every proxy; compose mounts the folder for every
# scenario. ECDSA P-256 (README "TLS parity").
if [ ! -f configs/tls/certs/combined.pem ]; then
  mkdir -p configs/tls/certs
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj /CN=bench \
    -addext "subjectAltName=DNS:rdock,DNS:nginx,DNS:haproxy,DNS:caddy,DNS:traefik" \
    -keyout configs/tls/certs/key.pem -out configs/tls/certs/cert.pem 2>/dev/null
  cat configs/tls/certs/cert.pem configs/tls/certs/key.pem > configs/tls/certs/combined.pem
  chmod 644 configs/tls/certs/*
fi
WARMUP=${WARMUP:-10s}
mkdir -p "$OUT"
# k6 runs as an unprivileged user in its container; on Linux it must be able to write here.
chmod a+w "$OUT"
# What ran: the machine, the pinning and the image digests Docker resolved.
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "scenario: $SCENARIO, config: $CONFIG, pinned: $PIN (proxy ${PROXY_CPUSET:-0,1}, backend and k6 ${LOAD_CPUSET:-2,3})"
  echo "kernel: $(uname -r), CPUs: $(nproc)"
  lscpu 2>/dev/null | grep -E '^(Model name|Thread\(s\) per core|Core\(s\) per socket|Socket\(s\)|Hypervisor vendor):' || true
  docker version --format 'docker: {{.Server.Version}}' 2>/dev/null || true
} > "$OUT/machine.txt"
# shellcheck disable=SC2086  # BACKENDS is a list of service names
"${COMPOSE[@]}" --profile lb --profile slow up -d $BACKENDS
for proxy in $PROXIES; do
  if [ "$proxy" = direct ]; then
    if [ "$SCHEME" != http ] || [ "$SCENARIO" = lb ]; then
      echo "== direct: skipped (plain HTTP scenarios with one backend only)"
      continue
    fi
    target="http://backend:80$URLPATH"
  else
    "${COMPOSE[@]}" --profile "$proxy" up -d --no-deps "$proxy"
    sleep 3
    target="$SCHEME://$proxy:8080$URLPATH"
  fi
  "${COMPOSE[@]}" --profile load run --rm "${EXTRA[@]}" -e OUT="/$OUT" -e PROXY="warmup" -e TARGET="$target" -e RATE=2000 -e DURATION="$WARMUP" k6 run --quiet /scripts/load.js >/dev/null
  for rate in $RATES; do
    echo "== $proxy at $rate req/s for $DURATION"
    before=""
    [ "$CPU_STAT" = 1 ] && [ "$proxy" != direct ] && before=$(./cpu-stat.sh "rdock-bench-$proxy-1" || true)
    "${COMPOSE[@]}" --profile load run --rm "${EXTRA[@]}" "${EXPECT[@]}" -e OUT="/$OUT" -e PROXY="$proxy" -e TARGET="$target" -e RATE="$rate" -e DURATION="$DURATION" k6 run --quiet /scripts/load.js >/dev/null
    if [ -n "$before" ] && after=$(./cpu-stat.sh "rdock-bench-$proxy-1"); then
      # The proxy's CPU over the rate's run: usage_usec nr_periods nr_throttled throttled_usec.
      read -r u0 p0 t0 w0 <<<"$before"
      read -r u1 p1 t1 w1 <<<"$after"
      printf '{"usage_usec": %d, "nr_periods": %d, "nr_throttled": %d, "throttled_usec": %d}\n' \
        $((u1 - u0)) $((p1 - p0)) $((t1 - t0)) $((w1 - w0)) >"$OUT/$proxy-$rate.cpu"
    fi
  done
  if [ "$proxy" != direct ]; then
    "${COMPOSE[@]}" --profile "$proxy" stop "$proxy"
    "${COMPOSE[@]}" --profile "$proxy" rm -f "$proxy" >/dev/null
  fi
done
# The digests every image resolved to (backends, k6 and each proxy that ran).
{
  for image in $("${COMPOSE[@]}" --profile '*' config --images | sort -u); do
    digest=$(docker image inspect --format '{{join .RepoDigests " "}}' "$image" 2>/dev/null || true)
    echo "$image ${digest:-(not pulled in this run)}"
  done
} > "$OUT/images.txt"
rm -f "$OUT"/warmup-*.json
"${COMPOSE[@]}" --profile '*' down >/dev/null
python3 -I report.py "$OUT" > "$OUT/report.md"
cat "$OUT/report.md"
if grep -q 'parity mismatch' "$OUT/report.md"; then
  echo "TLS or protocol parity mismatch: see the Negotiated column in $OUT/report.md" >&2
  exit 3
fi
