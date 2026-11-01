#!/usr/bin/env bash
# Isolation test (H-ENG-04): the proxy's latency and errors under fixed-rate load must not move
# while the admin API is flooded, written to, stalled or aborted.
#   docker build -t rdock:fault --build-arg CARGO_FEATURES=fault-injection ../..
#   ./run.sh                          # every phase, 60 s each at 4,000 req/s
#   RATE=8000 DURATION=120 ./run.sh
set -euo pipefail
cd "$(dirname "$0")"
RATE=${RATE:-4000}
DURATION=${DURATION:-60}
FAULT_AT=${FAULT_AT:-15}
PHASES=${PHASES:-"baseline login sse apply write-lock stall abort"}

load() {  # load NAME: fixed-rate load on the proxy for DURATION seconds
  docker compose --profile load run --rm --no-deps -e OUT=/results -e PROXY="$1" -e TARGET=http://rdock:8080/ \
    -e RATE="$RATE" -e DURATION="${DURATION}s" k6 run --quiet /scripts/load.js >/dev/null
}

start() {  # start [FAULT]: a fresh rdock with an admin user and an operator token
  docker compose down -v >/dev/null 2>&1 || true
  # Exported for the whole phase: compose compares every later `run` with this value and
  # would recreate rdock without the fault.
  export RDOCK_FAULT="${1:-}"
  docker compose up -d backend rdock >/dev/null
  until docker compose exec -T rdock rdock status >/dev/null 2>&1; do sleep 1; done
  openssl rand -hex 16 | docker compose exec -T rdock rdock users add admin --role admin >/dev/null
  docker compose exec -T rdock rdock tokens create attack --role operator --days 1 | head -n 1 > work/token
  docker compose --profile load run --rm --no-deps -e OUT=/results -e PROXY=warmup -e TARGET=http://rdock:8080/ \
    -e RATE="$RATE" -e DURATION=10s k6 run --quiet /scripts/load.js >/dev/null
}

attack() {  # attack MODE: attack.py next to the load, its counts kept in work/
  docker compose --profile attack run --rm --no-deps attack "$1" "$DURATION" > "work/attack-$1.json" 2>&1 &
}

admin_alive() {
  docker compose --profile attack run --rm --no-deps --entrypoint python3 attack -c \
    'import socket; socket.create_connection(("127.0.0.1", 2080), 2)' >/dev/null 2>&1
}

rm -rf work && mkdir -p work/results && chmod a+w work/results
trap 'docker compose --profile "*" down -v >/dev/null 2>&1 || true' EXIT
for phase in $PHASES; do
  echo "== $phase"
  case $phase in
    baseline) start; load baseline ;;
    login | sse | apply) start; attack "$phase"; load "$phase"; wait ;;
    write-lock) start "write-lock@$((FAULT_AT + 10))+$((DURATION - FAULT_AT))"; attack apply; load "$phase"; wait ;;
    stall) start "stall@$((FAULT_AT + 10))+$((DURATION - FAULT_AT))"; load "$phase" ;;
    abort)
      start "abort@$((FAULT_AT + 10))"; load "$phase"
      if admin_alive; then echo "admin still answers" > work/abort-admin; else echo "admin gone" > work/abort-admin; fi ;;
  esac
  docker compose logs --no-color rdock > "work/rdock-$phase.log" 2>&1
done
rm -f work/results/warmup-*.json
python3 -I analyze.py work | tee work/report.md
