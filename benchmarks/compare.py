"""Compares rdock with NGINX measured in the same run and fails on a clear regression.

    python3 compare.py results/ci

Shared CI runners are too noisy for absolute numbers, but both proxies see the same noise in
one job, so their ratio is stable enough to catch a slowdown. The limits are loose on purpose:
they flag a regression, not a few percent. Tighten them as ReverseDock gets faster.
"""
import json
import pathlib
import sys

# rdock must complete at least this share of what NGINX completes at the same target rate.
MIN_THROUGHPUT_RATIO = 0.95
# rdock p99 may be at most this multiple of NGINX p99 plus a fixed allowance. The allowance is
# today's gap, not a goal: on a 4-CPU runner on 2026-10-30, rdock's p99 at 5k was 19.9 ms against
# NGINX's 1.7 ms (#91). Lower it as that gap closes.
MAX_P99_RATIO = 4.0
P99_SLACK_MS = 25.0
# Failed requests: at most 1 %, or twice what NGINX failed if the machine itself was overloaded.
MAX_FAILED = 0.01


def load(directory):
    runs = {}
    for path in pathlib.Path(directory).glob("*.json"):
        run = json.loads(path.read_text())
        runs[(run["proxy"], run["rate"])] = run
    return runs


def problems(rdock, nginx):
    found = []
    ratio = rdock["achieved_rps"] / nginx["achieved_rps"]
    if ratio < MIN_THROUGHPUT_RATIO:
        found.append(f"throughput {ratio:.2f}× NGINX (minimum {MIN_THROUGHPUT_RATIO})")
    p99_limit = MAX_P99_RATIO * nginx["ms"]["p99"] + P99_SLACK_MS
    if rdock["ms"]["p99"] > p99_limit:
        found.append(f"p99 {rdock['ms']['p99']:.2f} ms (limit {p99_limit:.2f} ms)")
    failed_limit = max(MAX_FAILED, 2 * nginx["failed"])
    if rdock["failed"] > failed_limit:
        found.append(f"{rdock['failed'] * 100:.2f} % failed (limit {failed_limit * 100:.2f} %)")
    return found


def main(directory):
    runs = load(directory)
    rates = sorted(rate for proxy, rate in runs if proxy == "rdock")
    if not rates:
        print(f"no rdock results in {directory}")
        return 1
    print("| Target req/s | Throughput vs NGINX | p99 rdock / NGINX ms | Failed rdock / NGINX | Result |")
    print("|---:|---:|---:|---:|---|")
    failures = 0
    for rate in rates:
        rdock, nginx = runs[("rdock", rate)], runs.get(("nginx", rate))
        if nginx is None:
            print(f"| {rate} | no NGINX run | | | fail |")
            failures += 1
            continue
        found = problems(rdock, nginx)
        failures += bool(found)
        print(
            f"| {rate} | {rdock['achieved_rps'] / nginx['achieved_rps']:.2f}× "
            f"| {rdock['ms']['p99']:.2f} / {nginx['ms']['p99']:.2f} "
            f"| {rdock['failed'] * 100:.2f} % / {nginx['failed'] * 100:.2f} % "
            f"| {'; '.join(found) or 'ok'} |"
        )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
