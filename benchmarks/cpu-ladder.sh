#!/usr/bin/env bash
# The CPU ladder: each proxy at rising fixed rates, with the CPU time of its cgroup over each
# rate (cpu.stat), as the lab recorded it by hand for v0.5 and v0.6 (results/*/cpu.txt).
#   ./cpu-ladder.sh                                   # rdock, nginx and haproxy, 2,500 to 12,500 req/s
#   PROXIES="rdock nginx" RATES="5000 10000" VERSION=dev ./cpu-ladder.sh
# Writes results/<version>/<scenario>/cpu.txt (proxy rate usage_usec nr_periods nr_throttled
# throttled_usec, the same columns as before) and cpu.md, a table of µs per request:
# usage_usec divided by the requests k6 completed (README.md's formula, usage_usec ÷ (rate × 30),
# used the target rate instead).
#
# Untested: written on 2026-11-13 in a sandbox without Docker to match run.sh and the lab layout
# (compose.yaml: each proxy limited to 2 CPUs). Needs Docker on cgroup v2 (cpu-stat.sh).
set -euo pipefail
cd "$(dirname "$0")"
export PROXIES=${PROXIES:-"rdock nginx haproxy"}
export RATES=${RATES:-"2500 5000 7500 10000 12500"}
export DURATION=${DURATION:-30s}
export VERSION=${VERSION:-dev}
export SCENARIO=${SCENARIO:-single}
export CPU_STAT=1
./run.sh
OUT="results/$VERSION/$SCENARIO"
[ "$SCENARIO" = single ] && OUT="results/$VERSION"
python3 -I - "$OUT" <<'PY'
import json, pathlib, sys

out = pathlib.Path(sys.argv[1])
rows = []
for cpu in sorted(out.glob("*.cpu")):
    run = json.loads(cpu.with_suffix(".json").read_text())
    stat = json.loads(cpu.read_text())
    rows.append((run["proxy"], run["rate"], stat, run["requests"]))
rows.sort(key=lambda r: (r[0], r[1]))
with open(out / "cpu.txt", "w") as f:
    f.write("proxy rate usage_usec nr_periods nr_throttled throttled_usec\n")
    for proxy, rate, s, _ in rows:
        f.write(f"{proxy} {rate} {s['usage_usec']} {s['nr_periods']} {s['nr_throttled']} {s['throttled_usec']}\n")
with open(out / "cpu.md", "w") as f:
    f.write("| Proxy | Target req/s | Requests | CPU µs per request | Throttled periods |\n|---|---:|---:|---:|---:|\n")
    for proxy, rate, s, requests in rows:
        per = s["usage_usec"] / requests if requests else float("nan")
        f.write(f"| {proxy} | {rate} | {requests} | {per:.1f} | {s['nr_throttled']} |\n")
print((out / "cpu.md").read_text())
PY
