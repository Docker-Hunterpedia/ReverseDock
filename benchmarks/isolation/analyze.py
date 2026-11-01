"""Compares each phase of an isolation run (work/) with the baseline and fails when the admin
side moved the proxy's latency or errors (H-ENG-04).

    python3 analyze.py work

A phase passes when its p99 is at most 25 % plus 2 ms above the baseline's, when at most
0.05 points more requests failed, and when k6 dropped at most 0.1 % of them. After `abort`,
the admin listener must be gone while the proxy keeps answering.
"""
import json
import pathlib
import sys

P99_FACTOR, P99_SLACK_MS = 1.25, 2.0
MAX_EXTRA_FAILED = 0.0005
MAX_DROPPED_SHARE = 0.001


def main(work):
    results = {json.loads(p.read_text())["proxy"]: json.loads(p.read_text()) for p in (work / "results").glob("*.json")}
    base = results.get("baseline")
    if base is None:
        sys.exit("no baseline result")
    limit = base["ms"]["p99"] * P99_FACTOR + P99_SLACK_MS
    lines = [
        "# Admin isolation (H-ENG-04)",
        "",
        f"{base['rate']} req/s for {base['duration']} per phase. A phase passes when p99 ≤ {limit:.2f} ms "
        f"(baseline × {P99_FACTOR} + {P99_SLACK_MS:g} ms), failures ≤ baseline + {MAX_EXTRA_FAILED:.2%} "
        f"and dropped ≤ {MAX_DROPPED_SHARE:.1%}.",
        "",
        "| Phase | Achieved req/s | p50 ms | p99 ms | p99.9 ms | max ms | Failed | Dropped | Result |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    failures = []
    for name in ["baseline", "login", "sse", "apply", "write-lock", "stall", "abort"]:
        r = results.get(name)
        if r is None:
            continue
        problems = []
        if r["ms"]["p99"] > limit:
            problems.append(f"p99 {r['ms']['p99']:.2f} ms")
        if r["failed"] > base["failed"] + MAX_EXTRA_FAILED:
            problems.append(f"failed {r['failed']:.3%}")
        if r["dropped"] > r["requests"] * MAX_DROPPED_SHARE:
            problems.append(f"dropped {r['dropped']}")
        if name == "abort" and (work / "abort-admin").read_text().strip() != "admin gone":
            problems.append("the admin listener still answers after the abort")
        failures += [f"{name}: {p}" for p in problems]
        ms = r["ms"]
        lines.append(
            f"| {name} | {r['achieved_rps']:.0f} | {ms['p50']:.2f} | {ms['p99']:.2f} | {ms['p999']:.2f} | {ms['max']:.1f} "
            f"| {r['failed']:.3%} | {r['dropped']} | {'fail: ' + ', '.join(problems) if problems else 'pass'} |"
        )
    lines += ["", "Admin side during each phase (attack.py counts by answer):", ""]
    for p in sorted(work.glob("attack-*.json")):
        lines.append(f"- {p.stem.removeprefix('attack-')}: `{p.read_text().strip().splitlines()[-1]}`")
    print("\n".join(lines))
    if failures:
        print("\nFAILED:\n" + "\n".join(failures))
        sys.exit(1)


main(pathlib.Path(sys.argv[1]))
