#!/usr/bin/env bash
# Regenerates caddy.json in every case directory from its Caddyfile with the pinned Caddy image
# (`caddy adapt`), so the hand-written JSON can be checked against Caddy's own adapter. Needs
# Docker; run by a maintainer or CI (`just caddy-corpus`), then review the diff and run
# `just migrate-golden`.
#
# caddy:2.11.9, pinned by its index digest (Docker Hub's tag API, read 2026-11-14).
set -euo pipefail
IMAGE="caddy:2.11.9@sha256:4e2425f6009577e7c651010f16679c28f7d12df3e7b1914f941a7a3370746b3c"
here="$(cd "$(dirname "$0")" && pwd)"
for dir in "$here"/*/; do
  [ -f "$dir/Caddyfile" ] || continue
  if docker run --rm --network none -v "$dir:/case:ro" "$IMAGE" \
    caddy adapt --config /case/Caddyfile --adapter caddyfile --pretty > "$dir/caddy.json.new"; then
    mv "$dir/caddy.json.new" "$dir/caddy.json"
    echo "adapted $(basename "$dir")"
  else
    # Cases that use plugins (layer4, rate_limit) do not adapt with the standard image.
    rm -f "$dir/caddy.json.new"
    echo "kept the hand-written caddy.json of $(basename "$dir") (caddy adapt failed)" >&2
  fi
done
