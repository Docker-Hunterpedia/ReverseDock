#!/usr/bin/env bash
# The 60-second HTTPS proof on a real server against Let's Encrypt (ADR-0033, "60-second HTTPS";
# docs/01-vision.md §7: "Fresh VPS, DNS pointed, docker compose up -> valid HTTPS in under 60
# seconds with one label"). Run by hand by a maintainer; CI runs the same example against Pebble
# (tests/https-60s/run.sh, .github/workflows/https-60s.yml).
#
#   scripts/https-60s-vps.sh run   --domain NAME [--image IMAGE] [--email ADDRESS] [--production] [--fresh] [--expect-ip IP]
#   scripts/https-60s-vps.sh probe --domain NAME [--production]
#
# `run`, on the fresh server, from a checkout of this repository:
#   1. checks the prerequisites: Docker with Compose, curl and openssl, ports 80 and 443 free, no
#      earlier run's data volume (a stored certificate would make the run meaningless; --fresh
#      removes it), and that NAME resolves (and to --expect-ip, when given);
#   2. copies deploy/docker/examples/https/ to a new work folder, with NAME in the `rdock.host`
#      label, IMAGE as rdock's image when given, ADDRESS as `acme.email` when given, and
#      `acme.staging: true` kept unless --production;
#   3. downloads the staging roots from letsencrypt.org (staging certificates are not trusted by
#      any client) and pulls the images; both are timed separately and are outside the clock;
#   4. starts the clock, runs `docker compose up -d`, and polls https://NAME/ every 250 ms through
#      this machine's port 443 (curl --resolve NAME:443:127.0.0.1) until the application answers
#      200 with a certificate that verifies (against the staging roots, or the system's trust
#      store with --production) for NAME;
#   5. prints the time, the phases, the certificate's issuer, serial and start date, and writes them
#      to result.txt in the work folder. Exit 0 below 60 s, 1 otherwise. The project keeps running;
#      the last line says how to remove it.
# `probe`, on a second machine, started before `run`: polls https://NAME/ through public DNS and
# prints the UTC time of the first verified answer, to compare with the `t0` that `run` prints
# (keep both clocks synchronised with NTP). It shows the result as an outside client sees it.
#
# Inputs are arguments or environment variables (RDOCK_PROOF_DOMAIN, RDOCK_IMAGE,
# RDOCK_PROOF_EMAIL); nothing about a real deployment is stored in this file. Names you prove with
# end up in Certificate Transparency logs: use a throw-away name that reveals nothing, a new one per
# run. Let's Encrypt's limits (https://letsencrypt.org/docs/rate-limits/ and
# https://letsencrypt.org/docs/staging-environment/, read 2026-11-14): staging allows 50 new
# accounts per IP address per 3 hours; production allows 5 certificates per exact set of names per
# 7 days (no override) and 50 per registered domain per 7 days, so run --production once per
# release with a new name.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
EXAMPLE="$ROOT/deploy/docker/examples/https"
PROJECT=rdock-https
WAIT=${WAIT:-180}
LIMIT=${LIMIT:-60}
STAGING_ROOTS=(
  https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem
  https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem
  https://letsencrypt.org/certs/staging/gen-y/root-ye.pem
  https://letsencrypt.org/certs/staging/gen-y/root-yr.pem
)

usage() { sed -n '7,8p' "$0" | sed 's/^# *//' >&2; exit 2; }
[ $# -ge 1 ] || usage
MODE=$1; shift
DOMAIN=${RDOCK_PROOF_DOMAIN:-}
IMAGE=${RDOCK_IMAGE:-}
EMAIL=${RDOCK_PROOF_EMAIL:-}
PRODUCTION=0; FRESH=0; EXPECT_IP=""
while [ $# -gt 0 ]; do
  case $1 in
    --domain) DOMAIN=$2; shift 2 ;;
    --image) IMAGE=$2; shift 2 ;;
    --email) EMAIL=$2; shift 2 ;;
    --expect-ip) EXPECT_IP=$2; shift 2 ;;
    --production) PRODUCTION=1; shift ;;
    --fresh) FRESH=1; shift ;;
    *) usage ;;
  esac
done
[ -n "$DOMAIN" ] || { echo "--domain (or RDOCK_PROOF_DOMAIN) is required" >&2; exit 2; }
case $DOMAIN in *[!a-zA-Z0-9.-]* | .* | *.) echo "not a host name: $DOMAIN" >&2; exit 2 ;; esac

now() { date +%s.%N; }
utc() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
since() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", b - a }'; }
need() { command -v "$1" >/dev/null || { echo "missing: $1" >&2; exit 2; }; }

roots() { # $1: output bundle
  : > "$1"
  for url in "${STAGING_ROOTS[@]}"; do curl -fsS --max-time 20 "$url" >> "$1"; done
}

verified_get() { # $1: extra curl args (string), $2: body file; prints the status code
  # shellcheck disable=SC2086  # $1 is a list of curl options
  curl -s --max-time 2 $1 -o "$2" -w '%{http_code}' "https://$DOMAIN/" 2>/dev/null || true
}

if [ "$MODE" = probe ]; then
  need curl
  WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
  trust=""
  if [ "$PRODUCTION" = 0 ]; then roots "$WORK/roots.pem"; trust="--cacert $WORK/roots.pem"; fi
  echo "probing https://$DOMAIN/ every 250 ms from $(hostname); start \`run\` now"
  first_tcp=""
  while :; do
    if [ -z "$first_tcp" ] && curl -sk --max-time 2 -o /dev/null "https://$DOMAIN/" 2>/dev/null; then
      first_tcp=$(utc); echo "first TLS answer (any certificate): $first_tcp"
    fi
    if [ "$(verified_get "$trust" "$WORK/body")" = 200 ]; then
      echo "first verified 200:                 $(utc)"
      exit 0
    fi
    sleep 0.25
  done
fi
[ "$MODE" = run ] || usage

# 1. Prerequisites.
need docker; need curl; need openssl; need awk; need sed
docker compose version >/dev/null 2>&1 || { echo "missing: the Docker Compose plugin" >&2; exit 2; }
[ -f "$EXAMPLE/compose.yaml" ] || { echo "run this from a checkout of the repository ($EXAMPLE missing)" >&2; exit 2; }
if command -v ss >/dev/null && ss -Hltn '( sport = :80 or sport = :443 )' | grep -q .; then
  echo "ports 80 or 443 are in use:" >&2; ss -ltnp '( sport = :80 or sport = :443 )' >&2; exit 2
fi
if docker volume inspect "${PROJECT}_rdock-data" >/dev/null 2>&1; then
  if [ "$FRESH" = 1 ]; then
    docker compose -p "$PROJECT" down -v >/dev/null 2>&1 || true
    docker volume rm "${PROJECT}_rdock-data" >/dev/null
  else
    echo "an earlier run's data volume ${PROJECT}_rdock-data exists (it may hold a certificate); pass --fresh to remove it" >&2
    exit 2
  fi
fi
addresses=$(getent ahosts "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
[ -n "$addresses" ] || { echo "$DOMAIN does not resolve yet; point its A/AAAA record at this server first" >&2; exit 2; }
echo "== $DOMAIN resolves to: $addresses"
if command -v dig >/dev/null; then
  for resolver in 1.1.1.1 8.8.8.8; do echo "   via $resolver: $(dig +short "$DOMAIN" A @"$resolver" | tr '\n' ' ')"; done
fi
if [ -n "$EXPECT_IP" ] && ! grep -qw -- "$EXPECT_IP" <<<"$addresses"; then
  echo "$DOMAIN does not resolve to $EXPECT_IP" >&2; exit 2
fi

# 2. The example, with this run's name.
WORK="$PWD/https-60s-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$WORK"
cp -r "$EXAMPLE/compose.yaml" "$EXAMPLE/config" "$WORK/"
sed -i "s#rdock.host: app.example.com#rdock.host: $DOMAIN#" "$WORK/compose.yaml"
grep -q "rdock.host: $DOMAIN" "$WORK/compose.yaml" || { echo "the example's rdock.host label changed; update this script" >&2; exit 1; }
if [ -n "$IMAGE" ]; then
  sed -i "s#image: ghcr.io/docker-hunterpedia/rdock:.*#image: $IMAGE#" "$WORK/compose.yaml"
fi
if [ "$PRODUCTION" = 1 ]; then
  sed -i '/^  staging: true$/d' "$WORK/config/rdock.yaml"
fi
if [ -n "$EMAIL" ]; then
  sed -i "s#^acme:\$#acme:\n  email: \"$EMAIL\"#" "$WORK/config/rdock.yaml"
fi
cd "$WORK"
DOCKER_GID=$(stat -c %g /var/run/docker.sock)
export DOCKER_GID
echo "== work folder: $WORK"
echo "== image: $(grep -m1 'image: ' compose.yaml | awk '{print $2}'), CA: $([ "$PRODUCTION" = 1 ] && echo 'Let'"'"'s Encrypt production' || echo 'Let'"'"'s Encrypt staging')"

# 3. Outside the clock: trust anchors and images.
trust=""
if [ "$PRODUCTION" = 0 ]; then roots "$WORK/staging-roots.pem"; trust="--resolve $DOMAIN:443:127.0.0.1 --cacert $WORK/staging-roots.pem"
else trust="--resolve $DOMAIN:443:127.0.0.1"; fi
pull_start=$(now)
docker compose pull --quiet
pull_end=$(now)
echo "== images pulled in $(since "$pull_start" "$pull_end") s (not timed)"

# 4. The clock.
echo "== t0 $(utc): docker compose up -d"
t0=$(now)
docker compose up -d --quiet-pull
t_up=$(now)
first_tls=""; t1=""
while [ "$(since "$t0" "$(now)" | cut -d. -f1)" -lt "$WAIT" ]; do
  if [ -z "$first_tls" ] && curl -sk --max-time 2 --resolve "$DOMAIN:443:127.0.0.1" -o /dev/null "https://$DOMAIN/" 2>/dev/null; then
    first_tls=$(now)
  fi
  if [ "$(verified_get "$trust" "$WORK/body")" = 200 ]; then t1=$(now); break; fi
  sleep 0.25
done

# 5. The result.
{
  echo "domain: $DOMAIN"
  echo "ca: $([ "$PRODUCTION" = 1 ] && echo production || echo staging)"
  echo "server: $(uname -srm), $(nproc) CPUs, docker $(docker version --format '{{.Server.Version}}')"
  echo "images pulled (not timed): $(since "$pull_start" "$pull_end") s"
  echo "docker compose up -d returned: $(since "$t0" "$t_up") s"
  [ -n "$first_tls" ] && echo "first TLS answer (any certificate): $(since "$t0" "$first_tls") s"
  if [ -n "$t1" ]; then echo "first verified HTTPS 200: $(since "$t0" "$t1") s"; else echo "first verified HTTPS 200: none within $WAIT s"; fi
  echo | openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" 2>/dev/null \
    | openssl x509 -noout -issuer -serial -startdate 2>/dev/null || true
} | tee result.txt
docker compose logs --no-log-prefix --timestamps rdock > rdock.log 2>&1 || true
grep -i -E 'acme|certificate|order|challenge' rdock.log | head -20 || true
echo "== logs and result in $WORK; remove the project with: (cd $WORK && docker compose down -v)"
[ -n "$t1" ] || exit 1
awk -v e="$(since "$t0" "$t1")" -v l="$LIMIT" 'BEGIN { exit !(e < l) }' || { echo "RESULT: above $LIMIT s" >&2; exit 1; }
echo "RESULT: valid HTTPS in $(since "$t0" "$t1") s (limit $LIMIT s)"
