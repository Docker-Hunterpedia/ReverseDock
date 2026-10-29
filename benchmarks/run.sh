#!/usr/bin/env bash
# Runs every proxy at every rate and writes results/<version>/<proxy>-<rate>.json and
# results/<version>/report.md.
#   ./run.sh                        # all proxies, default rates
#   PROXIES="rdock nginx" RATES="5000 20000" DURATION=60s ./run.sh
set -euo pipefail
cd "$(dirname "$0")"
PROXIES=${PROXIES:-"rdock nginx haproxy caddy traefik"}
RATES=${RATES:-"5000 10000 20000 40000"}
DURATION=${DURATION:-30s}
VERSION=${VERSION:-dev}
OUT="results/$VERSION"
WARMUP=${WARMUP:-10s}
mkdir -p "$OUT"
docker compose up -d backend
for proxy in $PROXIES; do
  docker compose --profile "$proxy" up -d "$proxy"
  sleep 3
  target="http://$proxy:8080/"
  docker compose --profile load run --rm -e OUT="/results/$VERSION" -e PROXY="warmup" -e TARGET="$target" -e RATE=2000 -e DURATION="$WARMUP" k6 run --quiet /scripts/load.js >/dev/null
  for rate in $RATES; do
    echo "== $proxy at $rate req/s for $DURATION"
    docker compose --profile load run --rm -e OUT="/results/$VERSION" -e PROXY="$proxy" -e TARGET="$target" -e RATE="$rate" -e DURATION="$DURATION" k6 run --quiet /scripts/load.js >/dev/null
  done
  docker compose --profile "$proxy" stop "$proxy"
  docker compose --profile "$proxy" rm -f "$proxy" >/dev/null
done
rm -f "$OUT"/warmup-*.json
docker compose --profile '*' down >/dev/null
python3 report.py "$OUT" > "$OUT/report.md"
cat "$OUT/report.md"
