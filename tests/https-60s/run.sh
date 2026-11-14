#!/usr/bin/env bash
# The 60-second HTTPS proof against Pebble (ADR-0033, "60-second HTTPS"; docs/01-vision.md §7).
#
#   RDOCK_IMAGE=rdock:release-ci tests/https-60s/run.sh
#
# The documented example deploy/docker/examples/https/ (one rdock container and one application
# container whose labels are `rdock.enable=true` and `rdock.host=app.example.com`), with only the
# ACME directory changed from Let's Encrypt staging to Pebble (compose.ci.yaml). Pebble and its
# DNS server are started first and are not timed: they stand for the internet and a DNS record
# that already points at the machine. Then the clock starts and `docker compose up -d` brings up
# the example; the clock stops at the first HTTPS answer from the application (200, its body)
# whose certificate chain verifies against the root Pebble issues from, for app.example.com,
# through port 443 of this machine. Images are pulled before the clock starts and that time is
# printed separately.
#
# Prints the measured time and the phases; exits 1 above LIMIT seconds (60) or when no verified
# answer came within WAIT seconds (120), and 0 otherwise. Needs Docker with Compose, curl and
# openssl, and ports 80 and 443 free.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PROOF_DIR="$ROOT/tests/https-60s"
EXAMPLE="$ROOT/deploy/docker/examples/https"
: "${RDOCK_IMAGE:?set RDOCK_IMAGE to the image under test}"
LIMIT=${LIMIT:-60}
WAIT=${WAIT:-120}
HOST=app.example.com
WORK=$(mktemp -d)
export RDOCK_IMAGE PROOF_DIR PROOF_CONFIG="$WORK/config"
DOCKER_GID=$(stat -c %g /var/run/docker.sock)
export DOCKER_GID
COMPOSE=(docker compose -f "$EXAMPLE/compose.yaml" -f "$PROOF_DIR/compose.ci.yaml")
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", b - a }'; }
# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
  status=$?
  if [ "$status" != 0 ]; then
    echo "--- rdock log"
    "${COMPOSE[@]}" logs --no-log-prefix rdock 2>/dev/null | tail -100 || true
    echo "--- pebble log"
    "${COMPOSE[@]}" logs --no-log-prefix pebble 2>/dev/null | tail -40 || true
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT

if "${COMPOSE[@]}" ps -q 2>/dev/null | grep -q .; then
  echo "the rdock-https project is already running; stop it first" >&2
  exit 2
fi

echo "== image under test: $RDOCK_IMAGE ($(docker image inspect --format '{{.Id}}' "$RDOCK_IMAGE"))"
pull_start=$(now)
"${COMPOSE[@]}" pull --quiet app pebble challtestsrv
pull_end=$(now)
echo "== pulled the other images in $(since "$pull_start" "$pull_end") s (not timed)"

# The CA and DNS, before the clock: Pebble's directory must answer.
"${COMPOSE[@]}" up -d --quiet-pull pebble challtestsrv
for _ in $(seq 1 60); do
  curl -sfk --noproxy '*' --max-time 2 https://127.0.0.1:15000/roots/0 -o "$WORK/root.pem" && break
  sleep 0.5
done
test -s "$WORK/root.pem" || { echo "Pebble did not start" >&2; exit 1; }

# The example's configuration with one change: Pebble instead of Let's Encrypt staging.
mkdir -p "$PROOF_CONFIG"
"${COMPOSE[@]}" cp pebble:/test/certs/pebble.minica.pem "$PROOF_CONFIG/pebble.minica.pem" >/dev/null
grep -q '^  staging: true$' "$EXAMPLE/config/rdock.yaml" || { echo "the example no longer sets acme.staging" >&2; exit 1; }
sed -e 's#^  staging: true$#  ca: https://pebble:14000/dir\n  ca_root: /etc/rdock/pebble.minica.pem#' \
  "$EXAMPLE/config/rdock.yaml" > "$PROOF_CONFIG/rdock.yaml"
chmod 755 "$PROOF_CONFIG"; chmod 644 "$PROOF_CONFIG"/*
echo "== configuration (the example's, ACME directory changed)"
grep -v '^#' "$PROOF_CONFIG/rdock.yaml" | sed '/^$/d'

# The clock.
t0=$(now)
"${COMPOSE[@]}" up -d --quiet-pull
t_up=$(now)
first_tls=""
t1=""
while :; do
  t=$(now)
  if [ "$(since "$t0" "$t" | cut -d. -f1)" -ge "$WAIT" ]; then break; fi
  if [ -z "$first_tls" ] && curl -sk --noproxy '*' --max-time 2 --resolve "$HOST:443:127.0.0.1" \
    "https://$HOST/" -o /dev/null 2>/dev/null; then
    first_tls=$(now)
  fi
  code=$(curl -s --noproxy '*' --max-time 2 --resolve "$HOST:443:127.0.0.1" --cacert "$WORK/root.pem" \
    -o "$WORK/body" -w '%{http_code}' "https://$HOST/" 2>/dev/null || true)
  if [ "$code" = 200 ] && grep -q '^Hostname:' "$WORK/body"; then
    t1=$(now)
    break
  fi
  sleep 0.25
done

echo "== timeline (seconds after docker compose up -d was invoked)"
echo "docker compose up -d returned   $(since "$t0" "$t_up")"
[ -n "$first_tls" ] && echo "first TLS answer on :443        $(since "$t0" "$first_tls") (any certificate)"
"${COMPOSE[@]}" logs --no-log-prefix --timestamps rdock 2>/dev/null \
  | grep -i -E 'acme|certificate|order|challenge|docker' | head -30 || true
if [ -z "$t1" ]; then
  echo "RESULT: no verified HTTPS answer within $WAIT s" >&2
  exit 1
fi
elapsed=$(since "$t0" "$t1")
echo "first verified HTTPS 200       $elapsed"
echo | openssl s_client -connect 127.0.0.1:443 -servername "$HOST" 2>/dev/null \
  | openssl x509 -noout -issuer -subject -serial -startdate 2>/dev/null || true
if awk -v e="$elapsed" -v l="$LIMIT" 'BEGIN { exit !(e < l) }'; then
  echo "RESULT: valid HTTPS in $elapsed s (limit $LIMIT s)"
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "Valid HTTPS **$elapsed s** after \`docker compose up -d\` (limit $LIMIT s; Pebble, image pulls excluded: $(since "$pull_start" "$pull_end") s)" >> "$GITHUB_STEP_SUMMARY"
  exit 0
fi
echo "RESULT: valid HTTPS took $elapsed s, above the $LIMIT s limit" >&2
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "Valid HTTPS took **$elapsed s**, above the $LIMIT s limit" >> "$GITHUB_STEP_SUMMARY"
exit 1
