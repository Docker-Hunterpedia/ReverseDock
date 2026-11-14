"""Compares rdock with NGINX measured in the same run and fails on a clear regression.

    python3 compare.py results/ci

Shared CI runners are too noisy for absolute numbers, but both proxies see the same noise in
one job, so their ratio is stable enough to catch a slowdown. The limits are loose on purpose:
they flag a regression, not a few percent. Tighten them as ReverseDock gets faster.
"""
import json
import pathlib
import sys

# rdock must complete at least this share of what NGINX completes at the same target rate. Not
# 1.0: k6 on the runner achieves slightly under the target rate, by a different amount for each
# proxy. Of six green nights from 2026-11-07 to 11-12, two had rdock at 9,997 and 9,982 req/s
# against NGINX's 10,000 and 9,999 (ratios 0.9997 and 0.998): rounding, not a gap, and 1.0 would
# have failed them (docs/research/v0.9-scale.md, issue 181).
MIN_THROUGHPUT_RATIO = 0.98
# rdock p99 may be at most this multiple of NGINX p99 plus a fixed allowance. On 2 CPUs on
# 2026-11-02, rdock's p99 was 1.0–1.4× NGINX's up to 10k req/s (results/2026-11-02-small-cpu);
# the allowance absorbs the shared runner's jitter, not a gap (#93).
MAX_P99_RATIO = 2.0
P99_SLACK_MS = 5.0
# Failed requests: at most 1 %, or twice what NGINX failed if the machine itself was overloaded.
MAX_FAILED = 0.01
# CPU time per request, from the proxy's cgroup (run.sh with CPU_STAT=1): rdock may use at most
# this multiple of NGINX's. On the retired lab's dedicated 2 CPUs rdock used 76 µs per request at
# 10,000 req/s against NGINX's 56 µs (1.36×, v0.5, results/2026-11-02-small-cpu) and about 80 µs
# in v0.6 (1.43×, results/2026-11-07-v06). CPU time does not wait in queues, so it moves far less
# on a shared runner than latency does, but the two proxies run minutes apart on a machine whose
# neighbours change. The limit was first 1.6 (12 % above the worst lab ratio). Three runs of the
# same code on hosted runners on 2026-11-13 read 1.32 and 1.37, 1.40 and 1.46, and 2.18 and
# 1.79: in the third, on a faster machine, NGINX's cost fell from about 100 µs to 37 µs per
# request and rdock's from about 130 µs to 81 µs, so the ratio depends on the runner's CPU and 1.6
# fails by the machine drawn, not by the code. 2.4 leaves 10 % above the highest reading and
# still catches a regression of about three quarters against the usual 1.4; a smaller one shows
# in the printed table and in the dedicated-hardware results. Tighten it once a few weeks of
# nightly readings show the spread, or compare against the previous night on the same CPU model.
MAX_CPU_RATIO = 2.4


def load(directory):
    runs = {}
    for path in pathlib.Path(directory).glob("*.json"):
        run = json.loads(path.read_text())
        cpu = path.with_suffix(".cpu")
        if cpu.exists() and run.get("requests"):
            stat = json.loads(cpu.read_text())
            run["cpu_us_per_request"] = stat["usage_usec"] / run["requests"]
            run["nr_throttled"] = stat["nr_throttled"]
        runs[(run["proxy"], run["rate"])] = run
    return runs


def problems(rdock, nginx):
    found = []
    ratio = rdock["achieved_rps"] / nginx["achieved_rps"]
    if ratio < MIN_THROUGHPUT_RATIO:
        found.append(f"throughput {ratio:.3f}× NGINX (minimum {MIN_THROUGHPUT_RATIO})")
    p99_limit = MAX_P99_RATIO * nginx["ms"]["p99"] + P99_SLACK_MS
    if rdock["ms"]["p99"] > p99_limit:
        found.append(f"p99 {rdock['ms']['p99']:.2f} ms (limit {p99_limit:.2f} ms)")
    failed_limit = max(MAX_FAILED, 2 * nginx["failed"])
    if rdock["failed"] > failed_limit:
        found.append(f"{rdock['failed'] * 100:.2f} % failed (limit {failed_limit * 100:.2f} %)")
    cpu = cpu_ratio(rdock, nginx)
    if cpu is not None and cpu > MAX_CPU_RATIO:
        found.append(f"CPU per request {cpu:.2f}× NGINX (limit {MAX_CPU_RATIO})")
    return found


def cpu_ratio(rdock, nginx):
    """rdock's CPU per request over NGINX's; None when either was not recorded."""
    a, b = rdock.get("cpu_us_per_request"), nginx.get("cpu_us_per_request")
    if a is None or not b:
        return None
    return a / b


def cpu_cell(rdock, nginx):
    ratio = cpu_ratio(rdock, nginx)
    if ratio is None:
        return "not recorded"
    return f"{rdock['cpu_us_per_request']:.1f} / {nginx['cpu_us_per_request']:.1f} ({ratio:.2f}×)"


def main(directory):
    runs = load(directory)
    rates = sorted(rate for proxy, rate in runs if proxy == "rdock")
    if not rates:
        print(f"no rdock results in {directory}")
        return 1
    print("| Target req/s | Throughput vs NGINX | p99 rdock / NGINX ms | CPU µs per request rdock / NGINX | Failed rdock / NGINX | Result |")
    print("|---:|---:|---:|---:|---:|---|")
    failures = 0
    for rate in rates:
        rdock, nginx = runs[("rdock", rate)], runs.get(("nginx", rate))
        if nginx is None:
            print(f"| {rate} | no NGINX run | | | | fail |")
            failures += 1
            continue
        found = problems(rdock, nginx)
        failures += bool(found)
        print(
            f"| {rate} | {rdock['achieved_rps'] / nginx['achieved_rps']:.3f}× "
            f"| {rdock['ms']['p99']:.2f} / {nginx['ms']['p99']:.2f} "
            f"| {cpu_cell(rdock, nginx)} "
            f"| {rdock['failed'] * 100:.2f} % / {nginx['failed'] * 100:.2f} % "
            f"| {'; '.join(found) or 'ok'} |"
        )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
