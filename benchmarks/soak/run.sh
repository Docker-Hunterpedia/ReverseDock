#!/usr/bin/env bash
# Soak test (H-ENG-02, H-ENG-03): steady load on rdock for a long time while its configuration
# reloads, a backend goes down and comes back, and its certificate is replaced. A probe samples
# rdock's memory, threads, file descriptors and connections; analyze.py then looks for growth.
#   ./run.sh                                                    # 24 h at 1,000 req/s
#   DURATION=20m RELOAD_EVERY=60 FLAP_EVERY=180 CERT_EVERY=240 WINDOW=120 ./run.sh   # a quick check
set -euo pipefail
cd "$(dirname "$0")"
DURATION=${DURATION:-24h}
RATE=${RATE:-1000}
WINDOW=${WINDOW:-600}              # seconds per k6 window, one point of the latency series
RELOAD_EVERY=${RELOAD_EVERY:-300}  # seconds; multiples of 10, FLAP_EVERY above 60
FLAP_EVERY=${FLAP_EVERY:-900}
CERT_EVERY=${CERT_EVERY:-1800}

seconds() {
  case $1 in
    *h) echo $((${1%h} * 3600)) ;;
    *m) echo $((${1%m} * 60)) ;;
    *s) echo "${1%s}" ;;
    *) echo "$1" ;;
  esac
}

event() { echo "$(date +%s),$1" >> work/events.csv; }

write_config() {
  sed "s/GENERATION/$1/" rdock.yaml > work/config/.rdock.yaml.new
  mv -f work/config/.rdock.yaml.new work/config/rdock.yaml
}

# A throwaway self-signed certificate, written next to the old one and renamed into place.
new_cert() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3 \
    -subj /CN=rdock -addext "subjectAltName=DNS:rdock" \
    -keyout work/config/certs/.soak.key -out work/config/certs/.soak.pem 2>/dev/null
  chmod 644 work/config/certs/.soak.key work/config/certs/.soak.pem
  mv -f work/config/certs/.soak.key work/config/certs/soak.key
  mv -f work/config/certs/.soak.pem work/config/certs/soak.pem
}

# Reloads, backend outages and certificate changes on a 10-second clock.
chaos() {
  local t=0 generation=0
  while true; do
    sleep 10
    t=$((t + 10))
    if ((t % RELOAD_EVERY == 0)); then
      generation=$((generation + 1))
      write_config "$generation"
      event reload
    fi
    if ((t % FLAP_EVERY == 0)); then
      docker compose stop b3 >/dev/null 2>&1
      event backend_down
    elif ((t > FLAP_EVERY && t % FLAP_EVERY == 60)); then
      docker compose start b3 >/dev/null 2>&1
      event backend_up
    fi
    if ((t % CERT_EVERY == 0)); then
      new_cert
      event certificate
    fi
  done
}

finish() {
  [ -n "${CHAOS:-}" ] && kill "$CHAOS" 2>/dev/null || true
  docker compose logs --no-color rdock > work/rdock.log 2>&1 || true
  docker compose --profile load down >/dev/null 2>&1 || true
}

rm -rf work
mkdir -p work/config/certs work/windows
# The probe and k6 write here as unprivileged users in their containers.
chmod a+w work work/windows
echo "time,event" > work/events.csv
new_cert
write_config 0
trap finish EXIT
docker compose up -d b1 b2 b3 rdock probe
sleep 5
event start
chaos &
CHAOS=$!

total=$(seconds "$DURATION")
end=$((SECONDS + total))
n=0
while ((SECONDS < end)); do
  left=$((end - SECONDS))
  window=$((left < WINDOW ? left : WINDOW))
  docker compose --profile load run --rm -e RATE="$RATE" -e DURATION="${window}s" -e WINDOW_N="$n" \
    k6 run --quiet /scripts/soak.js >/dev/null
  n=$((n + 1))
done
event end
finish
trap - EXIT
python3 -I analyze.py work | tee work/report.md
