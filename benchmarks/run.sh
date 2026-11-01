#!/usr/bin/env bash
# Runs every proxy at every rate and writes results/<version>/<proxy>-<rate>.json and
# results/<version>/report.md.
#   ./run.sh                        # all proxies, default rates, one backend
#   PROXIES="rdock nginx" RATES="5000 20000" DURATION=60s ./run.sh
#   SCENARIO=lb ./run.sh            # round-robin over three backends (results/<version>/lb/)
set -euo pipefail
cd "$(dirname "$0")"
PROXIES=${PROXIES:-"rdock nginx haproxy caddy traefik"}
RATES=${RATES:-"5000 10000 20000 40000"}
DURATION=${DURATION:-30s}
VERSION=${VERSION:-dev}
SCENARIO=${SCENARIO:-single}
case $SCENARIO in
  single) OUT="results/$VERSION"; BACKENDS="backend"; export CONFIGS=./configs BACKEND_CPUS=4 ;;
  lb) OUT="results/$VERSION/lb"; BACKENDS="backend backend-2 backend-3"; export CONFIGS=./configs/lb BACKEND_CPUS=1.33 ;;
  *) echo "SCENARIO is single or lb" >&2; exit 2 ;;
esac
WARMUP=${WARMUP:-10s}
mkdir -p "$OUT"
# k6 runs as an unprivileged user in its container; on Linux it must be able to write here.
chmod a+w "$OUT"
# shellcheck disable=SC2086  # BACKENDS is a list of service names
docker compose --profile lb up -d $BACKENDS
for proxy in $PROXIES; do
  docker compose --profile "$proxy" up -d "$proxy"
  sleep 3
  target="http://$proxy:8080/"
  docker compose --profile load run --rm -e OUT="/$OUT" -e PROXY="warmup" -e TARGET="$target" -e RATE=2000 -e DURATION="$WARMUP" k6 run --quiet /scripts/load.js >/dev/null
  for rate in $RATES; do
    echo "== $proxy at $rate req/s for $DURATION"
    docker compose --profile load run --rm -e OUT="/$OUT" -e PROXY="$proxy" -e TARGET="$target" -e RATE="$rate" -e DURATION="$DURATION" k6 run --quiet /scripts/load.js >/dev/null
  done
  docker compose --profile "$proxy" stop "$proxy"
  docker compose --profile "$proxy" rm -f "$proxy" >/dev/null
done
rm -f "$OUT"/warmup-*.json
docker compose --profile '*' down >/dev/null
python3 report.py "$OUT" > "$OUT/report.md"
cat "$OUT/report.md"
