#!/usr/bin/env bash
# Renders docs/assets/banner.html → banner.png (2560×1280, 2x) and logo.svg → logo.png (512×512) with headless Chrome.
set -euo pipefail
cd "$(dirname "$0")/.."
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
PROFILE="${TMPDIR:-/tmp}/rdock-chrome-profile"
common=(--headless=new --disable-gpu --hide-scrollbars --no-first-run --no-default-browser-check --user-data-dir="$PROFILE" --virtual-time-budget=8000)
"$CHROME" "${common[@]}" --window-size=1280,640 --force-device-scale-factor=2 --screenshot="$PWD/docs/assets/banner.png" "file://$PWD/docs/assets/banner.html"
"$CHROME" "${common[@]}" --window-size=512,512 --screenshot="$PWD/docs/assets/logo.png" "file://$PWD/docs/assets/logo.svg"
echo "rendered docs/assets/banner.png and docs/assets/logo.png"
