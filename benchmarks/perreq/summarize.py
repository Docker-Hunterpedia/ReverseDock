"""Turns the JSON lines of perreq/run.sh into Markdown tables.

    python3 -I perreq/summarize.py counts <out-dir> [<out-dir-after>]
    python3 -I perreq/summarize.py cpu <out-dir>
    python3 -I perreq/summarize.py tail <out-dir> [<out-dir> ...]

`cpu`: per variant, the median of the A runs and of the B runs, the A/A spread ((max - min) / median
of the A runs, the noise floor) and the B/A change. A change is called a difference only when it
is larger than twice the A/A spread; otherwise it is reported as "within noise".
"""
import json
import pathlib
import statistics
import sys


def lines(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def counts(dirs):
    runs = [({r["label"]: r for r in lines(d / "allocs.jsonl")}, {r["label"]: r for r in lines(d / "syscalls.jsonl")}) for d in dirs]
    labels = list(runs[0][0])
    if len(runs) == 1:
        print("| Variant | Allocations | Bytes allocated | System calls | Of which |")
        print("|---|---:|---:|---:|---|")
        for label in labels:
            a, s = runs[0][0][label], runs[0][1].get(label, {})
            top = ", ".join(f"{k} {v:g}" for k, v in sorted(s.get("by_name", {}).items(), key=lambda kv: -kv[1]) if v >= 0.05)
            print(f"| {label} | {a['allocations']:.1f} | {a['bytes_allocated']:.0f} | {s.get('syscalls', float('nan')):.2f} | {top} |")
        return
    print("| Variant | Allocations before → after | Bytes before → after | System calls before → after |")
    print("|---|---:|---:|---:|")
    for label in labels:
        (a0, s0), (a1, s1) = (runs[0][0][label], runs[0][1].get(label, {})), (runs[1][0].get(label, {}), runs[1][1].get(label, {}))
        print(
            f"| {label} | {a0['allocations']:.1f} → {a1.get('allocations', float('nan')):.1f} "
            f"| {a0['bytes_allocated']:.0f} → {a1.get('bytes_allocated', float('nan')):.0f} "
            f"| {s0.get('syscalls', float('nan')):.2f} → {s1.get('syscalls', float('nan')):.2f} |"
        )


def cpu(d):
    by = {}
    for r in lines(d / "cpu.jsonl"):
        variant, which = r["label"].rsplit("/", 1)
        by.setdefault(variant, {}).setdefault(which, []).append(r["cpu_us_2n_only"])
    print("| Variant | A median µs | B median µs | A/A spread | B/A | Verdict | Runs (A, B) |")
    print("|---|---:|---:|---:|---:|---|---|")
    for variant, runs in by.items():
        a, b = runs.get("A", []), runs.get("B", [])
        if not a or not b:
            continue
        ma, mb = statistics.median(a), statistics.median(b)
        spread = (max(a) - min(a)) / ma
        change = mb / ma - 1
        verdict = f"{'lower' if change < 0 else 'higher'} by {abs(change):.0%}" if abs(change) > 2 * spread else "within noise"
        print(f"| {variant} | {ma:.1f} | {mb:.1f} | {spread:.1%} | {mb / ma:.3f} | {verdict} | {len(a)}, {len(b)} |")


def tail(dirs):
    print("| Variant | Burst | Ramp | During burst p99 / p99.9 / max ms | Outside p99 / max ms | Handshakes p50 / max ms | Failures |")
    print("|---|---:|---:|---|---|---|---:|")
    for d in dirs:
        for r in lines(d / "tail.jsonl"):
            db, ob, hs = r["during_burst_ms"], r["outside_burst_ms"], r["handshake_ms"]
            print(
                f"| {r['label']} | {r['burst']} | {r['ramp_ms']} ms "
                f"| {db.get('p99', '-')} / {db.get('p999', '-')} / {db.get('max', '-')} "
                f"| {ob.get('p99', '-')} / {ob.get('max', '-')} "
                f"| {hs.get('p50', '-')} / {hs.get('max', '-')} | {r['burst_failures']} |"
            )


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    kind, dirs = sys.argv[1], [pathlib.Path(p) for p in sys.argv[2:]]
    if kind == "counts":
        counts(dirs)
    elif kind == "cpu":
        cpu(dirs[0])
    elif kind == "tail":
        tail(dirs)
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
