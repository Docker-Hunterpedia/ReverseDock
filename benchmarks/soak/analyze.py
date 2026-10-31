"""Reads a soak run (work/) and fails when rdock leaked or degraded.

    python3 analyze.py work

The first tenth of the run is warm-up: pools and caches fill there. Over the rest, a straight
line is fitted to memory and file descriptors; its rise over that time is the growth. A leak
shows as steady growth however noisy the samples are.
"""
import csv
import json
import pathlib
import sys

WARMUP_SHARE = 0.1
# Memory may rise by at most this much after warm-up: 16 MiB, or 10 % of the warm size.
MAX_RSS_GROWTH_KIB = 16 * 1024
MAX_RSS_GROWTH_SHARE = 0.10
MAX_FD_GROWTH = 64
# Requests: at most 0.1 % failed or dropped over the whole run, outages and reloads included.
MAX_FAILED = 0.001
MAX_DROPPED = 0.001


def growth(times, values):
    """Rise of the least-squares line through (times, values) between the first and last time."""
    n = len(times)
    mean_t, mean_v = sum(times) / n, sum(values) / n
    spread = sum((t - mean_t) ** 2 for t in times)
    if spread == 0:
        return 0.0
    slope = sum((t - mean_t) * (v - mean_v) for t, v in zip(times, values)) / spread
    return slope * (times[-1] - times[0])


def read_probe(work):
    with open(work / "probe.csv") as f:
        rows = [{k: int(v) for k, v in row.items()} for row in csv.DictReader(f)]
    return rows[int(len(rows) * WARMUP_SHARE):], rows


def read_windows(work):
    return [json.loads(p.read_text()) for p in sorted((work / "windows").glob("*.json"))]


def count_events(work, name):
    with open(work / "events.csv") as f:
        return sum(1 for row in csv.DictReader(f) if row["event"] == name)


def samples_table(rows, start):
    step = max(1, len(rows) // 12)
    lines = ["| Hours | RSS MiB | Threads | File descriptors | TCP connections |", "|---:|---:|---:|---:|---:|"]
    for row in rows[::step] + ([rows[-1]] if (len(rows) - 1) % step else []):
        lines.append(
            f"| {(row['time'] - start) / 3600:.1f} | {row['rss_kib'] / 1024:.1f} | {row['threads']} "
            f"| {row['fds']} | {row['tcp']} |"
        )
    return lines


def main(work):
    work = pathlib.Path(work)
    measured, rows = read_probe(work)
    windows = read_windows(work)
    log = (work / "rdock.log").read_text()
    times = [r["time"] for r in measured]
    rss_growth = growth(times, [r["rss_kib"] for r in measured])
    fd_growth = growth(times, [r["fds"] for r in measured])
    rss_limit = max(MAX_RSS_GROWTH_KIB, MAX_RSS_GROWTH_SHARE * measured[0]["rss_kib"])
    requests = sum(w["requests"] for w in windows)
    failed = sum(w["failed"] * w["requests"] for w in windows) / requests
    dropped = sum(w["dropped"] for w in windows) / requests
    reloads = count_events(work, "reload")
    applied = sum(
        1 for line in log.splitlines() if "configuration applied" in line and '"trigger":"start"' not in line
    )
    rejected, panics = log.count("configuration rejected"), log.count("panicked")

    checks = [
        ("Memory growth after warm-up", f"{rss_growth / 1024:+.1f} MiB", f"≤ {rss_limit / 1024:.1f} MiB", rss_growth <= rss_limit),
        ("File descriptor growth after warm-up", f"{fd_growth:+.0f}", f"≤ {MAX_FD_GROWTH}", fd_growth <= MAX_FD_GROWTH),
        ("Failed requests", f"{failed * 100:.3f} %", f"≤ {MAX_FAILED * 100:.1f} %", failed <= MAX_FAILED),
        ("Dropped requests", f"{dropped * 100:.3f} %", f"≤ {MAX_DROPPED * 100:.1f} %", dropped <= MAX_DROPPED),
        ("Reloads applied", f"{applied} for {reloads} changes", "every change applied", applied >= reloads),
        ("Reloads rejected", str(rejected), "0", rejected == 0),
        ("Panics in the log", str(panics), "0", panics == 0),
    ]
    start = rows[0]["time"]
    hours = (rows[-1]["time"] - start) / 3600
    print(f"Soak: {hours:.1f} h, {requests:,} requests, {count_events(work, 'backend_down')} backend outages, "
          f"{count_events(work, 'certificate')} certificate changes, {reloads} configuration reloads.\n")
    print("| Check | Measured | Limit | Result |\n|---|---:|---:|---|")
    for name, measured_value, limit, ok in checks:
        print(f"| {name} | {measured_value} | {limit} | {'pass' if ok else '**fail**'} |")
    print("\n## rdock over time\n")
    print("\n".join(samples_table(rows, start)))
    p99 = sorted(w["ms"]["p99"] for w in windows)
    print(f"\nLatency per {len(windows)} windows: median p99 {p99[len(p99) // 2]:.2f} ms, worst p99 {p99[-1]:.2f} ms, "
          f"first {windows[0]['ms']['p99']:.2f} ms, last {windows[-1]['ms']['p99']:.2f} ms.")
    return 0 if all(ok for *_, ok in checks) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
