#!/usr/bin/env python3
"""Reads a hosted soak run (soak.py's output directory) and fails when rdock leaked or misbehaved.

    python3 -I analyze.py DIR [--min-upgrades N] [--min-reloads N] [--allow-inconclusive]

Standard library only. Writes DIR/report.md and DIR/analysis.json and prints the report.
Exit code: 0 all checks pass; 1 a check failed; 3 nothing failed but a trend check had too little
data to judge (a run too short for the rules below; `--allow-inconclusive` turns it into 0).

The rules, and why (benchmarks/README.md has the long version):

Requests. A request fails when the client got no answer, a status other than 200, a wrong body
or no answer within 10 s. A stale kept-alive connection (closed by the server before it sent
anything) is retried once on a new connection, as HTTP clients do for GET, and only counted.
At most 0.001 % of the requests may fail (floor of 1e-5 x requests), computed separately for
the requests inside an upgrade or reload window (about 3 % of a full run's 7.7 million: about 2)
and for all the others (about 75).

Trends (memory by PSS, open file descriptors, threads). An upgrade starts a new process, which
starts with nothing, so a trend is judged per process, never across the run. The first 600 s
of every process are discarded (caches, pools and the allocator settle). A process takes part
when at least 900 s and 20 samples remain; the others are listed and not judged. For each:

  slope   the Theil-Sen estimate, the median of the slopes between all pairs of points: unlike
          a least-squares line, spikes move it little (29 % of the points can be outliers),
          and so does a step early or late in the window. A step half way through moves half
          of the data: no slope estimate tells that from growth, and it is flagged;
  level   the median of the first quarter of the remaining samples;
  delta   the median of the last quarter minus the median of the second.

Memory is flagged when BOTH the slope's projection over 24 h exceeds 10 % of the level AND
delta exceeds max(1 MiB, 1 % of the level). The projection alone would turn a few hundred KiB of
noise over a 15-minute window into a "leak" of tens of MiB a day; delta alone would flag a
step that has already settled. Together: growth that continues, and by an amount that is not
noise. File descriptors and threads are flagged when the rise over the window (slope x window)
and delta both exceed max(16, 5 % of the level) descriptors, or max(4, 10 % of the level)
threads. rdock holds a number of these that depends on the load, never on the age of the
process, so any sustained rise is a leak.

A trend check fails when the longest judged process is flagged (the run puts one long process at
the end, `--upgrade-until`, for this), or when at least three processes were judged and more
than half are flagged. With no process judged it is inconclusive.
"""
import argparse
import csv
import json
import math
import pathlib
import statistics
import sys

WARMUP = 600.0
MIN_TAIL = 900.0
MIN_SAMPLES = 20
DAY = 86400.0
MEM_PROJECTED_SHARE = 0.10
MEM_DELTA_KIB = 1024.0
MEM_DELTA_SHARE = 0.01
FD_FLOOR, FD_SHARE = 16.0, 0.05
THREAD_FLOOR, THREAD_SHARE = 4.0, 0.10
FAIL_RATIO = 1e-5
UPGRADE_WINDOW = (2.0, 10.0)  # seconds before the start and after the end of an upgrade
RELOAD_WINDOW = (2.0, 5.0)
LATENCY_FACTOR, LATENCY_SLACK_MS = 3.0, 5.0
MAX_POINTS = 240  # Theil-Sen is quadratic: at most this many points per fit


def theil_sen(times, values):
    """The median of the slopes between all pairs of points (units per second)."""
    step = max(1, len(times) // MAX_POINTS)
    t, v = times[::step], values[::step]
    slopes = [
        (v[j] - v[i]) / (t[j] - t[i])
        for i in range(len(t))
        for j in range(i + 1, len(t))
        if t[j] > t[i]
    ]
    return statistics.median(slopes) if slopes else 0.0


def judge(times, values, kind):
    """The trend of one process after warm-up. kind: 'mem', 'fds' or 'threads'. Returns a dict."""
    n = len(values)
    quarter = n // 4
    level = statistics.median(values[:quarter])
    slope = theil_sen(times, values)
    delta = statistics.median(values[3 * quarter:]) - statistics.median(values[quarter:2 * quarter])
    window = times[-1] - times[0]
    out = {"level": level, "slope_per_s": slope, "delta": delta, "window_s": window,
           "projected_24h": slope * DAY, "rise_in_window": slope * window}
    if kind == "mem":
        out["flagged"] = (
            slope * DAY > MEM_PROJECTED_SHARE * level and delta > max(MEM_DELTA_KIB, MEM_DELTA_SHARE * level)
        )
    else:
        floor, share = (FD_FLOOR, FD_SHARE) if kind == "fds" else (THREAD_FLOOR, THREAD_SHARE)
        limit = max(floor, share * level)
        out["flagged"] = slope * window > limit and delta > limit
    return out


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def number(text):
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def segments(rows):
    """Samples grouped by process, in order of appearance: [(pid, [row, ...]), ...]."""
    out = {}
    for row in rows:
        out.setdefault(row["pid"], []).append(row)
    return list(out.items())


def trend_check(segs, field, kind, warmup, min_tail):
    """Judges every process; returns (status, judged, all) for the check."""
    results = []
    for pid, rows in segs:
        points = []
        for row in rows:
            value = number(row.get(field))
            if value is None and field == "pss_kib":
                value = number(row.get("rss_kib"))
            if value is not None:
                points.append((number(row["time"]), value))
        if not points:
            continue
        start = points[0][0]
        tail = [(t, v) for t, v in points if t - start >= warmup]
        info = {"pid": pid, "span_s": points[-1][0] - start, "samples": len(tail), "judged": False}
        if len(tail) >= MIN_SAMPLES and tail[-1][0] - tail[0][0] >= min_tail:
            info.update(judge([t for t, _ in tail], [v for _, v in tail], kind))
            info["judged"] = True
        results.append(info)
    judged = [r for r in results if r["judged"]]
    if not judged:
        return "inconclusive", judged, results
    longest = max(judged, key=lambda r: r["window_s"])
    flagged = sum(1 for r in judged if r["flagged"])
    fail = longest["flagged"] or (len(judged) >= 3 and flagged * 2 > len(judged))
    return ("fail" if fail else "pass"), judged, results


def in_windows(t, windows):
    return any(a <= t <= b for a, b in windows)


def analyse(work, min_upgrades=0, min_reloads=0, warmup=WARMUP, min_tail=MIN_TAIL):
    work = pathlib.Path(work)
    meta = json.loads((work / "meta.json").read_text())
    samples = read_csv(work / "samples.csv")
    events = read_csv(work / "events.csv")
    load = read_csv(work / "load.csv")
    failures = read_csv(work / "failures.csv")
    log = (work / "rdock.log").read_text(errors="replace") if (work / "rdock.log").exists() else ""
    checks = []

    def add(name, measured, limit, status, note=""):
        checks.append({"name": name, "measured": measured, "limit": limit, "status": status, "note": note})

    # The run itself.
    elapsed = meta["finished"] - meta["started"]
    expected = elapsed / meta["sample_every"]
    ended = [e for e in events if e["kind"] == "end"]
    down = [e for e in events if e["kind"] == "rdock_down"]
    add("The run completed", f"{elapsed / 60:.1f} of {meta['duration'] / 60:.1f} min, rdock down {len(down)}x",
        "≥ 98 % of the time, rdock never down",
        "pass" if elapsed >= 0.98 * meta["duration"] and ended and ended[-1]["ok"] == "1" and not down else "fail")
    add("Samples taken", f"{len(samples)} of {expected:.0f}", "≥ 85 %", "pass" if len(samples) >= 0.85 * expected - 4 else "fail")

    # Requests.
    upgrades = [e for e in events if e["kind"] == "upgrade"]
    reloads = [e for e in events if e["kind"] == "reload"]
    windows = [(float(e["start"]) - UPGRADE_WINDOW[0], float(e["end"]) + UPGRADE_WINDOW[1]) for e in upgrades]
    windows += [(float(e["start"]) - RELOAD_WINDOW[0], float(e["end"]) + RELOAD_WINDOW[1]) for e in reloads]
    times = [number(r["time"]) for r in load]
    step = statistics.median([b - a for a, b in zip(times, times[1:])]) if len(times) > 1 else 10.0
    sent_in = sent_out = 0
    for row in load:
        middle = number(row["time"]) - step / 2
        if in_windows(middle, windows):
            sent_in += int(row["sent"])
        else:
            sent_out += int(row["sent"])
    failed_in = sum(1 for f in failures if in_windows(number(f["time"]), windows))
    failed_out = len(failures) - failed_in
    allowed_in, allowed_out = math.floor(FAIL_RATIO * sent_in), math.floor(FAIL_RATIO * sent_out)
    sent = sent_in + sent_out
    kinds = {}
    for f in failures:
        kinds[f["error"]] = kinds.get(f["error"], 0) + 1
    note = "; ".join(f"{n} x {k}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])[:4])
    add("Failed requests outside upgrade and reload windows", f"{failed_out} of {sent_out:,}", f"≤ {allowed_out} (0.001 %)",
        "pass" if failed_out <= allowed_out else "fail", note)
    add("Failed requests inside upgrade and reload windows", f"{failed_in} of {sent_in:,}", f"≤ {allowed_in} (0.001 %)",
        "pass" if failed_in <= allowed_in else "fail")
    stale = sum(int(r["stale"]) for r in load)
    add("Stale kept-alive connections retried (information)", f"{stale}", "not limited", "pass",
        "an idle connection the server closed before the client's next request; retried once, as a client does")

    # Upgrades, reloads, the held connections.
    bad_up = [e for e in upgrades if e["ok"] != "1"]
    add("Binary upgrades", f"{len(upgrades) - len(bad_up)} ok of {len(upgrades)}", f"all ok, at least {min_upgrades}",
        "pass" if not bad_up and len(upgrades) >= min_upgrades else "fail", "; ".join(e["detail"] for e in bad_up[:2]))
    held = [e for e in events if e["kind"] in ("held_check", "handover_check")]
    bad_held = [e for e in held if e["ok"] != "1"]
    add("Held WebSocket and event stream across upgrades", f"{len(held) - len(bad_held)} ok of {len(held)} checks",
        "all ok: kept while the old process drains, closed when its drain ends, old process gone",
        "pass" if not bad_held else "fail", "; ".join(e["detail"] for e in bad_held[:2]))
    bad_rl = [e for e in reloads if e["ok"] != "1"]
    add("Configuration reloads", f"{len(reloads) - len(bad_rl)} ok of {len(reloads)}", f"all ok, at least {min_reloads}",
        "pass" if not bad_rl and len(reloads) >= min_reloads else "fail", "; ".join(e["detail"] for e in bad_rl[:2]))
    add("Panics in the log", str(log.count("panicked")), "0", "pass" if log.count("panicked") == 0 else "fail")
    add("Rejected configurations in the log", str(log.count("configuration rejected")), "0",
        "pass" if log.count("configuration rejected") == 0 else "fail")

    # Trends.
    segs = segments(samples)
    trend_rows = {}
    for label, field, kind in (("Memory (PSS)", "pss_kib", "mem"), ("Open file descriptors", "fds", "fds"), ("Threads", "threads", "threads")):
        status, judged, every = trend_check(segs, field, kind, warmup, min_tail)
        trend_rows[kind] = every
        if judged:
            longest = max(judged, key=lambda r: r["window_s"])
            unit = 1024.0 if kind == "mem" else 1.0
            suffix = " MiB" if kind == "mem" else ""
            measured = (f"longest process: {longest['rise_in_window'] / unit:+.1f}{suffix} over {longest['window_s'] / 60:.1f} min, "
                        f"{longest['projected_24h'] / unit:+.1f}{suffix} projected in 24 h; "
                        f"{sum(1 for r in judged if r['flagged'])} of {len(judged)} processes flagged")
        else:
            measured = f"no process has {min_tail / 60:.1f} min after its {warmup / 60:.1f} min warm-up"
        rule = ("projection over 24 h ≤ 10 % of the level, or last-quartile median within max(1 MiB, 1 %) of the second" if kind == "mem"
                else "no sustained rise")
        add(f"{label} does not grow", measured, rule, status)

    # Latency drift (the p99 of the windows).
    p99 = [number(r["p99_ms"]) for r in load if number(r["p99_ms"]) is not None]
    if len(p99) >= 8:
        q = len(p99) // 4
        first, last = statistics.median(p99[:q]), statistics.median(p99[-q:])
        add("Latency does not drift", f"median p99 {first:.1f} ms in the first quarter, {last:.1f} ms in the last",
            f"last ≤ {LATENCY_FACTOR:.0f} x first + {LATENCY_SLACK_MS:.0f} ms", "pass" if last <= LATENCY_FACTOR * first + LATENCY_SLACK_MS else "fail")

    result = {
        "meta": meta, "checks": checks, "requests": sent, "failures": len(failures), "upgrades": len(upgrades),
        "reloads": len(reloads), "processes": [p for p, _ in segs], "trends": trend_rows,
        "windows": {"p99_ms": p99}, "samples": samples, "load": load, "warmup": warmup, "min_tail": min_tail,
    }
    statuses = {c["status"] for c in checks}
    result["exit"] = 1 if "fail" in statuses else (3 if "inconclusive" in statuses else 0)
    return result


def hourly_table(samples, start, per_hour=2):
    lines = ["| Minutes | pid | PSS MiB | RSS MiB | FDs | Threads | Cache objects | Data KiB |", "|---:|---:|---:|---:|---:|---:|---:|---:|"]
    stride = max(1, len(samples) // 16)
    shown = samples[::stride]
    if samples and shown[-1] is not samples[-1]:
        shown.append(samples[-1])
    for r in shown:
        pss = number(r["pss_kib"]) or 0
        lines.append(f"| {(number(r['time']) - start) / 60:.1f} | {r['pid']} | {pss / 1024:.1f} | {number(r['rss_kib']) / 1024:.1f} "
                     f"| {r['fds']} | {r['threads']} | {r['cache_objects']} | {r['data_kib']} |")
    return lines


def render(result, allow_inconclusive=False):
    meta = result["meta"]
    machine = meta["machine"]
    lines = [
        f"# Hosted soak: {'FAILED' if result['exit'] == 1 else 'inconclusive' if result['exit'] == 3 else 'passed'}",
        "",
        f"{(meta['finished'] - meta['started']) / 3600:.2f} h at {meta['rate']:.0f} req/s ({result['requests']:,} requests, "
        f"{result['failures']} failed), {result['upgrades']} binary upgrades, {result['reloads']} reloads, "
        f"{len(result['processes'])} processes. `{meta['rdock_version'].splitlines()[0] if meta['rdock_version'] else 'rdock'}`, "
        f"allocator label `{meta['label']}`, binary sha256 `{meta['binary_sha256'][:12]}`; "
        f"{machine['cpus']} CPUs, {machine['mem_mib']} MiB, kernel {machine['kernel']}, Python {machine['python']}.",
        "",
        "| Check | Measured | Limit | Result |", "|---|---|---|---|",
    ]
    for c in result["checks"]:
        status = {"pass": "pass", "fail": "**FAIL**", "inconclusive": "**inconclusive**"}[c["status"]]
        extra = f" ({c['note']})" if c["note"] else ""
        lines.append(f"| {c['name']} | {c['measured']}{extra} | {c['limit']} | {status} |")
    lines += ["", "## Processes", "",
              f"One row per rdock process (an upgrade starts a new one). Judged: at least {result['min_tail'] / 60:.1f} min and {MIN_SAMPLES} samples after a {result['warmup'] / 60:.1f} min warm-up.", "",
              "| pid | Minutes sampled | Judged | PSS level MiB | Slope MiB/h | Projected 24 h MiB | Last-quarter minus second MiB | Flagged |",
              "|---:|---:|---|---:|---:|---:|---:|---|"]
    for r in result["trends"].get("mem", []):
        if r["judged"]:
            lines.append(f"| {r['pid']} | {r['span_s'] / 60:.1f} | yes | {r['level'] / 1024:.1f} | {r['slope_per_s'] * 3600 / 1024:+.2f} "
                         f"| {r['projected_24h'] / 1024:+.1f} | {r['delta'] / 1024:+.2f} | {'**yes**' if r['flagged'] else 'no'} |")
        else:
            lines.append(f"| {r['pid']} | {r['span_s'] / 60:.1f} | no (too short) | | | | | |")
    if result["samples"]:
        lines += ["", "## Over time", ""] + hourly_table(result["samples"], number(result["samples"][0]["time"]))
    lines += ["", "Hosted runners are shared virtual machines: see benchmarks/README.md for what this run does and does not show."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("work")
    p.add_argument("--min-upgrades", type=int, default=0, help="fail with fewer successful upgrades")
    p.add_argument("--min-reloads", type=int, default=0, help="fail with fewer successful reloads")
    p.add_argument("--warmup", type=float, default=WARMUP, help="seconds discarded per process (default 600)")
    p.add_argument("--min-tail", type=float, default=MIN_TAIL, help="seconds a process needs after warm-up to be judged (default 900)")
    p.add_argument("--allow-inconclusive", action="store_true", help="exit 0 when a trend had too little data (short runs)")
    args = p.parse_args(argv)
    try:
        result = analyse(args.work, args.min_upgrades, args.min_reloads, args.warmup, args.min_tail)
    except FileNotFoundError as err:
        print(f"FAILED: the run did not write {err.filename}: rdock or the driver did not start (see its output and rdock.log)")
        return 1
    report = render(result, args.allow_inconclusive)
    work = pathlib.Path(args.work)
    (work / "report.md").write_text(report)
    summary = {k: v for k, v in result.items() if k not in ("samples", "load", "windows")}
    (work / "analysis.json").write_text(json.dumps(summary, indent=2, default=str))
    print(report)
    return 0 if result["exit"] == 0 or (result["exit"] == 3 and args.allow_inconclusive) else result["exit"]


if __name__ == "__main__":
    sys.exit(main())
