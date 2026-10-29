"""Turns results/<proxy>-<rate>.json into a Markdown table per rate."""
import json
import pathlib
import sys

results = [json.loads(p.read_text()) for p in sorted(pathlib.Path(sys.argv[1]).glob("*.json"))]
rates = sorted({r["rate"] for r in results})
print("| Proxy | Target req/s | Achieved req/s | p50 ms | p90 ms | p99 ms | p99.9 ms | max ms | Failed | Dropped |")
print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
for rate in rates:
    for r in sorted((r for r in results if r["rate"] == rate), key=lambda r: r["ms"]["p99"]):
        ms = r["ms"]
        print(
            f"| {r['proxy']} | {rate} | {r['achieved_rps']:.0f} | {ms['p50']:.2f} | {ms['p90']:.2f} | "
            f"{ms['p99']:.2f} | {ms['p999']:.2f} | {ms['max']:.1f} | {r['failed'] * 100:.2f} % | {r['dropped']} |"
        )
