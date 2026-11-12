#!/usr/bin/env bash
# Smoke test of the WAF example (compose.yaml): a clean request reaches the application, attack
# patterns are refused by the CRS WAF with 403, and a stopped WAF makes rdock fail closed.
#
#   RDOCK_IMAGE=rdock:ci ./examples/waf/smoke.sh
#
# Needs Docker with Compose and curl. Exits non-zero on the first failed check and prints the
# containers' logs.
set -euo pipefail

cd "$(dirname "$0")"
port="${PORT:-8088}"
base="http://127.0.0.1:${port}"
export PORT="${port}"

compose() {
  docker compose -f compose.yaml "$@"
}

ok=0
cleanup() {
  if [ "${ok}" -ne 1 ]; then
    compose logs --no-color --tail 100 >&2 || true
  fi
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# status <curl arguments...>: prints the HTTP status, keeps the body in $body_file.
body_file="$(mktemp)"
status() {
  curl --silent --show-error --max-time 10 --output "${body_file}" --write-out '%{http_code}' "$@" || true
}

compose up --detach --quiet-pull

echo "waiting for rdock and the WAF..."
ready=0
for _ in $(seq 1 90); do
  if [ "$(status "${base}/ready" 2>/dev/null)" = "200" ]; then
    ready=1
    break
  fi
  sleep 1
done
[ "${ready}" -eq 1 ] || fail "no 200 from ${base}/ready within 90 s"

code="$(status "${base}/hello?name=world")"
[ "${code}" = "200" ] || fail "a clean request returned ${code}, not 200"
grep -q "Name: demo-backend" "${body_file}" || fail "the clean request was not answered by the application"
echo "ok: a clean request reaches the application (200)"

code="$(status "${base}/download?file=../../../../etc/passwd")"
[ "${code}" = "403" ] || fail "a path traversal returned ${code}, not 403"
grep -qi "forbidden" "${body_file}" || fail "the 403 is not the WAF's refusal page"
echo "ok: a path traversal in the query is refused (403)"

code="$(status --get --data-urlencode "id=1' OR '1'='1" "${base}/items")"
[ "${code}" = "403" ] || fail "an SQL injection returned ${code}, not 403"
echo "ok: an SQL injection in the query is refused (403)"

code="$(status --data-urlencode "comment=<script>alert(document.cookie)</script>" "${base}/comments")"
[ "${code}" = "403" ] || fail "a cross-site scripting body returned ${code}, not 403"
echo "ok: a cross-site scripting payload in the body is refused (403)"

code="$(status --data "name=alice&comment=hello" "${base}/comments")"
[ "${code}" = "200" ] || fail "a clean form post returned ${code}, not 200"
echo "ok: a clean form post reaches the application (200)"

compose stop waf >/dev/null
code="$(status "${base}/hello")"
case "${code}" in
  502 | 503 | 504) echo "ok: with the WAF stopped, requests are refused (${code})" ;;
  *) fail "with the WAF stopped, a request returned ${code}, not 502, 503 or 504" ;;
esac

ok=1
rm -f "${body_file}"
echo "WAF example: all checks passed"
