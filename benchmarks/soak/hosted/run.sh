#!/usr/bin/env bash
# The hosted soak: rdock under steady load, reloads and binary upgrades, then the analysis.
# Needs Linux, Python 3 and openssl; no Docker, no other tool. See benchmarks/README.md.
#
#   cargo build --locked --release -p rdock
#   benchmarks/soak/hosted/run.sh                       # 5 h 20 min, what the weekly workflow runs
#   DURATION=10m UPGRADE_EVERY=150 UPGRADE_UNTIL=0.7 RELOAD_EVERY=90 \
#     ANALYZE_ARGS="--warmup 60 --min-tail 90 --allow-inconclusive" benchmarks/soak/hosted/run.sh   # a smoke run
#
# Settings (environment): RDOCK (binary, default target/release/rdock), OUT (default
# benchmarks/soak/hosted/work), DURATION, RATE (req/s), SAMPLE_EVERY, RELOAD_EVERY, UPGRADE_EVERY,
# UPGRADE_UNTIL (fraction of the run), DRAIN (upgrade.drain, seconds), LABEL (allocator name for
# the report), MIN_UPGRADES, MIN_RELOADS, ANALYZE_ARGS (more arguments for analyze.py).
# Exit code: the analysis's (0 pass, 1 a check failed, 3 too little data), or 2 when rdock died.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
RDOCK=${RDOCK:-$root/target/release/rdock}
OUT=${OUT:-$here/work}
DURATION=${DURATION:-5h20m}
RATE=${RATE:-400}
SAMPLE_EVERY=${SAMPLE_EVERY:-30}
RELOAD_EVERY=${RELOAD_EVERY:-300}
UPGRADE_EVERY=${UPGRADE_EVERY:-1800}
UPGRADE_UNTIL=${UPGRADE_UNTIL:-0.5}
DRAIN=${DRAIN:-30}
LABEL=${LABEL:-mimalloc}
MIN_UPGRADES=${MIN_UPGRADES:-0}
MIN_RELOADS=${MIN_RELOADS:-0}
ANALYZE_ARGS=${ANALYZE_ARGS:-}

[[ -x "$RDOCK" ]] || { echo "no rdock binary at $RDOCK (cargo build --locked --release -p rdock)" >&2; exit 64; }

# The rules the analysis applies, tested against synthetic runs first.
python3 -I "$here/test_analyze.py"

# The soak ends the run itself; the analysis reads whatever it wrote, even after a failure.
driver=0
python3 -I "$here/soak.py" --rdock "$RDOCK" --out "$OUT" --duration "$DURATION" --rate "$RATE" \
  --sample-every "$SAMPLE_EVERY" --reload-every "$RELOAD_EVERY" --upgrade-every "$UPGRADE_EVERY" \
  --upgrade-until "$UPGRADE_UNTIL" --drain "$DRAIN" --label "$LABEL" || driver=$?

analysis=0
# ANALYZE_ARGS is split on purpose: it holds extra command-line arguments.
# shellcheck disable=SC2086
python3 -I "$here/analyze.py" "$OUT" --min-upgrades "$MIN_UPGRADES" --min-reloads "$MIN_RELOADS" $ANALYZE_ARGS || analysis=$?

if ((driver != 0)); then exit "$driver"; fi
exit "$analysis"
