#!/usr/bin/env python3
"""Tests of analyze.py against synthetic soak runs.

    python3 -I benchmarks/soak/hosted/test_analyze.py

Standard library only. Each test writes a run directory (samples.csv, events.csv, load.csv,
failures.csv, meta.json, rdock.log) of the kind soak.py writes, with a memory, descriptor or
thread series of a known shape, and checks the verdict. The shapes the rules must tell apart:
flat, noisy flat, a step then flat (a cache filling), a slow leak, and a sawtooth (an
allocator returning memory in cycles).
"""
import contextlib
import csv
import io
import json
import math
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze  # noqa: E402

T0 = 1_000_000
SAMPLE = 30
HEADER = ["time", "pid", "generation", "rss_kib", "pss_kib", "fds", "threads", "data_kib", "requests",
          "errors_5xx", "upstream_errors", "connections_total", "connections_open", "cache_objects", "cache_bytes"]
MIB = 1024.0


def settle(t, level, ramp=300.0, start=0.6):
    """A process starting at `start` x level and reaching `level` within `ramp` seconds."""
    return level * (start + (1 - start) * min(1.0, t / ramp))


def flat(level=100 * MIB):
    return lambda t: settle(t, level)


def noisy(level=100 * MIB, sigma=0.5 * MIB, seed=1):
    rng = random.Random(seed)
    return lambda t: settle(t, level) + rng.gauss(0, sigma) + (3 * MIB if rng.random() < 0.01 else 0)


def step(at, size=20 * MIB, level=100 * MIB):
    return lambda t: settle(t, level) + (size if t >= at else 0)


def leak(per_hour, level=100 * MIB):
    return lambda t: settle(t, level) + per_hour * max(0.0, t - 600) / 3600


def sawtooth(period=1200.0, amplitude=8 * MIB, level=100 * MIB):
    return lambda t: settle(t, level) + amplitude * ((t % period) / period)


def make_run(directory, processes, failures=(), load_rows=None, events=(), log="", duration=None):
    """processes: [(pid, seconds, pss(t), fds(t), threads(t))] one after the other."""
    rows, t = [], 0.0
    for pid, seconds, pss, fds, threads in processes:
        local = 0.0
        while local < seconds:
            rows.append([T0 + t, pid, 0, pss(local) + 2 * MIB, pss(local), round(fds(local)), round(threads(local)),
                         10, 0, 0, 0, 0, 0, 0, 0])
            local += SAMPLE
            t += SAMPLE
    total = t
    with open(os.path.join(directory, "samples.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(rows)
    with open(os.path.join(directory, "events.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["kind", "start", "end", "ok", "detail"])
        w.writerow(["start", T0, T0, 1, ""])
        for e in events:
            w.writerow(e)
        w.writerow(["end", T0 + total, T0 + total, 1, ""])
    with open(os.path.join(directory, "load.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "sent", "ok", "failed", "stale", "p50_ms", "p99_ms", "p999_ms", "max_ms", "lag_ms", "inflight"])
        for i in range(int(total // 10)):
            w.writerow([T0 + 10 * (i + 1), 4000, 4000, 0, 0, 1.0, 3.0, 5.0, 9.0, 3.0, 0] if load_rows is None else load_rows(i))
    with open(os.path.join(directory, "failures.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "target", "error"])
        w.writerows(failures)
    with open(os.path.join(directory, "meta.json"), "w") as f:
        json.dump({"started": T0, "finished": T0 + total, "duration": duration or total, "rate": 400, "sample_every": SAMPLE,
                   "reload_every": 300, "upgrade_every": 1800, "upgrade_until": 0.5, "drain": 30, "label": "test",
                   "rdock_version": "rdock test", "binary_sha256": "0" * 64,
                   "machine": {"cpus": 4, "mem_mib": 16000, "kernel": "test", "python": "3"}}, f)
    with open(os.path.join(directory, "rdock.log"), "w") as f:
        f.write(log)
    return total


def const(n):
    return lambda t: n


HOURS = 3600.0


class Verdicts(unittest.TestCase):
    def run_analysis(self, processes, **kwargs):
        with tempfile.TemporaryDirectory() as d:
            make_run(d, processes, **{k: v for k, v in kwargs.items() if k in ("failures", "load_rows", "events", "log", "duration")})
            return analyze.analyse(d, **{k: v for k, v in kwargs.items() if k in ("min_upgrades", "min_reloads")})

    def status(self, result, name):
        return next(c["status"] for c in result["checks"] if c["name"].startswith(name))

    def one(self, pss, fds=const(42), threads=const(16), hours=5.0, **kw):
        return self.run_analysis([(100, hours * HOURS, pss, fds, threads)], **kw)

    # -- memory shapes -----------------------------------------------------------------------

    def test_flat_passes(self):
        r = self.one(flat())
        self.assertEqual(r["exit"], 0, r["checks"])

    def test_noisy_flat_passes(self):
        for seed in range(5):
            r = self.one(noisy(seed=seed))
            self.assertEqual(self.status(r, "Memory"), "pass", seed)

    def test_step_early_then_flat_passes(self):
        # A cache filling in the first minutes: inside the warm-up.
        r = self.one(step(at=240))
        self.assertEqual(self.status(r, "Memory"), "pass")

    def test_step_after_warmup_off_centre_is_not_growth(self):
        # A step 40 minutes in (or in the last tenth) is not a trend: the slope stays near zero.
        for at in (40 * 60.0, 4.6 * HOURS):
            r = self.one(step(at=at))
            self.assertEqual(self.status(r, "Memory"), "pass", at)

    def test_step_in_the_middle_of_the_run_is_flagged(self):
        # Documented limit: a step half way through moves half the data, which no slope
        # estimate can tell from growth. A one-off step of 20 % at that point is reported.
        r = self.one(step(at=2.5 * HOURS))
        self.assertEqual(self.status(r, "Memory"), "fail")

    def test_slow_leak_fails(self):
        # 2 MiB an hour on 100 MiB: 48 MiB (48 %) in 24 h, which a 5-hour run can see.
        r = self.one(leak(2 * MIB))
        self.assertEqual(self.status(r, "Memory"), "fail")
        self.assertEqual(r["exit"], 1)

    def test_leak_under_the_floor_passes(self):
        # 0.1 MiB an hour: 2.4 % a day. Below what the rule is meant to see; documented.
        r = self.one(leak(0.1 * MIB))
        self.assertEqual(self.status(r, "Memory"), "pass")

    def test_detection_floor_of_the_default_run(self):
        # The shape of the weekly run: five 30-minute processes, then one of 2 h 40 min. A leak
        # of 0.5 MiB an hour (12 % a day on 100 MiB) is under what the rule can tell from noise
        # in 150 minutes; 1 MiB an hour (24 % a day, under one byte per request at 400 req/s) is
        # not. benchmarks/README.md quotes these two numbers.
        for per_hour, verdict in ((0.5, "pass"), (1.0, "fail")):
            r = self.run_analysis(self.upgraded(flat(), leak(per_hour * MIB)))
            self.assertEqual(self.status(r, "Memory"), verdict, per_hour)

    def test_sawtooth_passes(self):
        r = self.one(sawtooth())
        self.assertEqual(self.status(r, "Memory"), "pass")

    def test_noisy_leak_still_fails(self):
        base = leak(3 * MIB)
        rng = random.Random(7)
        r = self.one(lambda t: base(t) + rng.gauss(0, 1.0 * MIB))
        self.assertEqual(self.status(r, "Memory"), "fail")

    # -- several processes (upgrades) --------------------------------------------------------

    def upgraded(self, short, long_, count=5):
        procs = [(100 + i, 0.5 * HOURS, short, const(42), const(16)) for i in range(count)]
        procs.append((200, 160 * 60.0, long_, const(42), const(16)))
        return procs

    def test_restarts_with_warmup_each_pass(self):
        r = self.run_analysis(self.upgraded(noisy(seed=3), noisy(seed=4)))
        self.assertEqual(r["exit"], 0, r["checks"])
        self.assertEqual(len(r["processes"]), 6)

    def test_a_leak_in_every_short_process_fails_even_when_the_long_one_is_flat(self):
        r = self.run_analysis(self.upgraded(leak(40 * MIB), flat()))
        self.assertEqual(self.status(r, "Memory"), "fail")

    def test_a_leak_only_in_the_long_process_fails(self):
        r = self.run_analysis(self.upgraded(flat(), leak(4 * MIB)))
        self.assertEqual(self.status(r, "Memory"), "fail")

    def test_one_noisy_short_process_does_not_fail_the_run(self):
        procs = self.upgraded(flat(), flat())
        procs[1] = (101, 0.5 * HOURS, leak(40 * MIB), const(42), const(16))
        r = self.run_analysis(procs)
        self.assertEqual(self.status(r, "Memory"), "pass")

    # -- descriptors and threads -------------------------------------------------------------

    def test_fd_noise_passes_and_a_fd_leak_fails(self):
        rng = random.Random(2)
        r = self.one(flat(), fds=lambda t: 42 + rng.randint(-5, 5))
        self.assertEqual(self.status(r, "Open file descriptors"), "pass")
        r = self.one(flat(), fds=lambda t: 42 + 12 * t / HOURS)
        self.assertEqual(self.status(r, "Open file descriptors"), "fail")

    def test_thread_growth_fails(self):
        r = self.one(flat(), threads=lambda t: 16 + 3 * t / HOURS)
        self.assertEqual(self.status(r, "Threads"), "fail")
        r = self.one(flat(), threads=lambda t: 16 + (2 if (t // 600) % 2 else 0))
        self.assertEqual(self.status(r, "Threads"), "pass")

    # -- too little data ---------------------------------------------------------------------

    def test_a_short_run_is_inconclusive_not_a_pass(self):
        r = self.one(flat(), hours=0.3)
        self.assertEqual(r["exit"], 3)
        self.assertEqual(self.status(r, "Memory"), "inconclusive")
        with tempfile.TemporaryDirectory() as d:
            make_run(d, [(1, 0.3 * HOURS, flat(), const(42), const(16))])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(analyze.main([d]), 3)
                self.assertEqual(analyze.main([d, "--allow-inconclusive"]), 0)
                self.assertEqual(analyze.main([d, "--warmup", "60", "--min-tail", "300"]), 0)

    # -- requests and events -----------------------------------------------------------------

    def test_failure_budget(self):
        # 5 h at 400 req/s: 7.2 million requests, 72 failures allowed outside windows.
        ok = [(T0 + 100 + i, "http", "reset") for i in range(72)]
        r = self.one(flat(), failures=ok)
        self.assertEqual(self.status(r, "Failed requests outside"), "pass")
        r = self.one(flat(), failures=ok + [(T0 + 200, "http", "reset")])
        self.assertEqual(self.status(r, "Failed requests outside"), "fail")

    def test_one_failure_in_an_upgrade_window_fails(self):
        events = [["upgrade", T0 + 1000, T0 + 1004, 1, "ok"]]
        r = self.one(flat(), events=events, failures=[(T0 + 1005, "https", "reset")])
        self.assertEqual(self.status(r, "Failed requests inside"), "fail")
        r = self.one(flat(), events=events, failures=[(T0 + 1500, "https", "reset")])
        self.assertEqual(self.status(r, "Failed requests inside"), "pass")

    def test_a_failed_upgrade_or_held_check_fails(self):
        r = self.one(flat(), events=[["upgrade", T0 + 1000, T0 + 1004, 0, "HTTP 500"]])
        self.assertEqual(self.status(r, "Binary upgrades"), "fail")
        r = self.one(flat(), events=[["upgrade", T0 + 1000, T0 + 1004, 1, "ok"], ["held_check", T0 + 1004, T0 + 1050, 0, "ws closed early"]])
        self.assertEqual(self.status(r, "Held"), "fail")
        r = self.one(flat(), min_upgrades=3)
        self.assertEqual(self.status(r, "Binary upgrades"), "fail")

    def test_a_panic_or_a_rejected_configuration_fails(self):
        self.assertEqual(self.status(self.one(flat(), log="thread 'x' panicked at"), "Panics"), "fail")
        self.assertEqual(self.status(self.one(flat(), log='"configuration rejected"'), "Rejected"), "fail")

    def test_an_early_end_fails(self):
        r = self.one(flat(), duration=7 * HOURS)
        self.assertEqual(self.status(r, "The run completed"), "fail")

    def test_latency_drift_fails(self):
        def rows(i):
            return [T0 + 10 * (i + 1), 4000, 4000, 0, 0, 1.0, 3.0 if i < 1000 else 40.0, 5.0, 9.0, 3.0, 0]
        r = self.one(flat(), load_rows=rows)
        self.assertEqual(self.status(r, "Latency"), "fail")

    def test_theil_sen(self):
        times = list(range(0, 1000, 10))
        self.assertTrue(math.isclose(analyze.theil_sen(times, [3 * t + 5 for t in times]), 3.0))
        spiky = [3 * t + 5 + (1e6 if i % 25 == 0 else 0) for i, t in enumerate(times)]
        self.assertTrue(math.isclose(analyze.theil_sen(times, spiky), 3.0, rel_tol=0.05))


if __name__ == "__main__":
    unittest.main(verbosity=1)
