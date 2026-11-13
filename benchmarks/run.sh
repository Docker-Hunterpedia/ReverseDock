#!/usr/bin/env bash
# Runs every proxy at every rate and writes results/<version>/<proxy>-<rate>.json and
# results/<version>/report.md.
#   ./run.sh                        # all proxies, default rates, one backend
#   PROXIES="rdock nginx" RATES="5000 20000" DURATION=60s ./run.sh
#   SCENARIO=lb ./run.sh            # results/<version>/<scenario>/
# Scenarios: single (default) one backend; lb round-robin over three backends; tls HTTPS with
# kept-alive connections; tls-ramped the same with the rate reached over RAMP (2 s) instead of at
# once; tls-new a TLS handshake for every request; slow a backend that takes 100 ms; routes 1,000
# hosts, each with its own route.
# CPU_STAT=1 also records the proxy's cgroup CPU time over each rate (cpu-stat.sh) in
# <proxy>-<rate>.cpu next to the k6 result; compare.py and cpu-ladder.sh read it.
set -euo pipefail
cd "$(dirname "$0")"
PROXIES=${PROXIES:-"rdock nginx haproxy caddy traefik"}
RATES=${RATES:-"5000 10000 20000 40000"}
DURATION=${DURATION:-30s}
VERSION=${VERSION:-dev}
SCENARIO=${SCENARIO:-single}
CPU_STAT=${CPU_STAT:-0}
SCHEME=http; URLPATH=/; BACKENDS="backend"; OUT="results/$VERSION/$SCENARIO"; EXTRA=()
export CONFIGS=./configs BACKEND_CPUS=4
case $SCENARIO in
  single) OUT="results/$VERSION" ;;
  lb) BACKENDS="backend backend-2 backend-3"; CONFIGS=./configs/lb; BACKEND_CPUS=1.33 ;;
  tls | tls-new | tls-ramped)
    SCHEME=https; CONFIGS=./configs/tls
    # HTTP/1.1 for everyone: not every proxy here offers HTTP/2 by default.
    EXTRA=(-e GODEBUG=http2client=0)
    [ "$SCENARIO" = tls-new ] && EXTRA+=(-e NEW_CONNECTIONS=1)
    # k6 opens a connection per virtual user on its first request; reaching the rate over
    # RAMP spreads those handshakes instead of opening them all in the first 50 ms (issue 181).
    [ "$SCENARIO" = tls-ramped ] && EXTRA+=(-e "RAMP=${RAMP:-2s}")
    ;;
  slow) BACKENDS="backend-slow"; URLPATH="/?wait=100ms" ;;
  large | huge)
    # Response bodies of 100 KiB and 1 MiB instead of 1 KiB; lower rates, see README.
    mkdir -p backend/bodies
    [ -f backend/bodies/100k.bin ] || head -c 102400 /dev/urandom > backend/bodies/100k.bin
    [ -f backend/bodies/1m.bin ] || head -c 1048576 /dev/urandom > backend/bodies/1m.bin
    [ "$SCENARIO" = large ] && URLPATH=/bodies/100k.bin || URLPATH=/bodies/1m.bin
    ;;
  routes)
    CONFIGS=./configs/routes
    python3 -I gen-routes.py configs/routes 1000
    EXTRA=(-e HOSTS=1000)
    ;;
  *) echo "SCENARIO is single, lb, tls, tls-ramped, tls-new, slow, routes, large or huge" >&2; exit 2 ;;
esac
# A throwaway certificate; compose mounts the folder for every scenario.
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
# shellcheck disable=SC2086  # BACKENDS is a list of service names
docker compose --profile lb --profile slow up -d $BACKENDS
for proxy in $PROXIES; do
  docker compose --profile "$proxy" up -d --no-deps "$proxy"
  sleep 3
  target="$SCHEME://$proxy:8080$URLPATH"
  docker compose --profile load run --rm "${EXTRA[@]}" -e OUT="/$OUT" -e PROXY="warmup" -e TARGET="$target" -e RATE=2000 -e DURATION="$WARMUP" k6 run --quiet /scripts/load.js >/dev/null
  for rate in $RATES; do
    echo "== $proxy at $rate req/s for $DURATION"
    before=""
    [ "$CPU_STAT" = 1 ] && before=$(./cpu-stat.sh "rdock-bench-$proxy-1" || true)
    docker compose --profile load run --rm "${EXTRA[@]}" -e OUT="/$OUT" -e PROXY="$proxy" -e TARGET="$target" -e RATE="$rate" -e DURATION="$DURATION" k6 run --quiet /scripts/load.js >/dev/null
    if [ -n "$before" ] && after=$(./cpu-stat.sh "rdock-bench-$proxy-1"); then
      # The proxy's CPU over the rate's run: usage_usec nr_periods nr_throttled throttled_usec.
      read -r u0 p0 t0 w0 <<<"$before"
      read -r u1 p1 t1 w1 <<<"$after"
      printf '{"usage_usec": %d, "nr_periods": %d, "nr_throttled": %d, "throttled_usec": %d}\n' \
        $((u1 - u0)) $((p1 - p0)) $((t1 - t0)) $((w1 - w0)) >"$OUT/$proxy-$rate.cpu"
    fi
  done
  docker compose --profile "$proxy" stop "$proxy"
  docker compose --profile "$proxy" rm -f "$proxy" >/dev/null
done
rm -f "$OUT"/warmup-*.json
docker compose --profile '*' down >/dev/null
python3 report.py "$OUT" > "$OUT/report.md"
cat "$OUT/report.md"
