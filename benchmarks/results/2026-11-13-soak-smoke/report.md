# Hosted soak, smoke run, 2026-11-13

**This is a smoke run on a shared 4-vCPU development sandbox, not a result.** It proves that the driver (`benchmarks/soak/hosted`), the following of the process across binary upgrades and the analysis work end to end. It says nothing about rdock's long-run memory: the run is 10 minutes, and the trend rules need far more (see `benchmarks/README.md`, "Hosted soak").

Commit `a1d7b82` plus the uncommitted step-9 files; release build, mimalloc. Command (10 minutes, a reload every 90 s, an upgrade every 150 s until 70 % of the run, `upgrade.drain` 30 s):

```sh
DURATION=10m RATE=400 SAMPLE_EVERY=10 RELOAD_EVERY=90 UPGRADE_EVERY=150 UPGRADE_UNTIL=0.7 DRAIN=30 MIN_UPGRADES=2 MIN_RELOADS=2 \
  ANALYZE_ARGS="--warmup 60 --min-tail 120 --allow-inconclusive" benchmarks/soak/hosted/run.sh
```

Smoke parameters: the warm-up is 60 s instead of 600 s and a process is judged after 120 s instead of 900 s, so **the memory, descriptor and thread rows below judged one process of 4.7 minutes, whose first minute after warm-up was still settling** (its projected "+395 MiB in 24 h" is that settling extrapolated 300-fold; it was not flagged only because the last-quartile median was within 0.21 MiB of the second). With the real parameters this process would not have been judged at all. What the run does show: 0 failed requests of 239,978, 2 upgrades and 6 reloads that all worked, the held WebSocket and event stream kept for the 30 s drain and closed when it ended (30.0 s after the swap), the old processes gone, no panic. The 4 stale-connection retries are counted, not hidden.

The files: `samples.csv`, `load.csv`, `failures.csv`, `events.csv`, `meta.json`, `analysis.json`, the configuration as written (`rdock.yaml`) and `rdock.log`. The report below is `analyze.py`'s output, unchanged.

---

# Hosted soak: passed

0.17 h at 400 req/s (239,978 requests, 0 failed), 2 binary upgrades, 6 reloads, 3 processes. `rdock 0.8.0-alpha.1`, allocator label `mimalloc`, binary sha256 `490abfea394a`; 4 CPUs, 16086 MiB, kernel 6.18.44-fc-v445, Python 3.13.18.

| Check | Measured | Limit | Result |
|---|---|---|---|
| The run completed | 10.0 of 10.0 min, rdock down 0x | ≥ 98 % of the time, rdock never down | pass |
| Samples taken | 60 of 60 | ≥ 85 % | pass |
| Failed requests outside upgrade and reload windows | 0 of 207,978 | ≤ 2 (0.001 %) | pass |
| Failed requests inside upgrade and reload windows | 0 of 32,000 | ≤ 0 (0.001 %) | pass |
| Stale kept-alive connections retried (information) | 4 (an idle connection the server closed before the client's next request; retried once, as a client does) | not limited | pass |
| Binary upgrades | 2 ok of 2 | all ok, at least 2 | pass |
| Held WebSocket and event stream across upgrades | 6 ok of 6 checks | all ok: kept while the old process drains, closed when its drain ends, old process gone | pass |
| Configuration reloads | 6 ok of 6 | all ok, at least 2 | pass |
| Panics in the log | 0 | 0 | pass |
| Rejected configurations in the log | 0 | 0 | pass |
| Memory (PSS) does not grow | longest process: +1.0 MiB over 3.7 min, +395.1 MiB projected in 24 h; 0 of 1 processes flagged | projection over 24 h ≤ 10 % of the level, or last-quartile median within max(1 MiB, 1 %) of the second | pass |
| Open file descriptors does not grow | longest process: +2.8 over 3.7 min, +1080.0 projected in 24 h; 0 of 1 processes flagged | no sustained rise | pass |
| Threads does not grow | longest process: +0.0 over 3.7 min, +0.0 projected in 24 h; 0 of 1 processes flagged | no sustained rise | pass |
| Latency does not drift | median p99 2.6 ms in the first quarter, 2.7 ms in the last | last ≤ 3 x first + 5 ms | pass |

## Processes

One row per rdock process (an upgrade starts a new one). Judged: at least 2.0 min and 20 samples after a 1.0 min warm-up.

| pid | Minutes sampled | Judged | PSS level MiB | Slope MiB/h | Projected 24 h MiB | Last-quarter minus second MiB | Flagged |
|---:|---:|---|---:|---:|---:|---:|---|
| 6889 | 2.5 | no (too short) | | | | | |
| 7083 | 2.3 | no (too short) | | | | | |
| 7308 | 4.7 | yes | 88.8 | +16.46 | +395.1 | +0.21 | no |

## Over time

| Minutes | pid | PSS MiB | RSS MiB | FDs | Threads | Cache objects | Data KiB |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.0 | 6889 | 66.4 | 68.5 | 31 | 16 | 0 | 5 |
| 0.5 | 6889 | 86.2 | 88.2 | 44 | 16 | 400 | 5 |
| 1.0 | 6889 | 85.3 | 87.4 | 44 | 16 | 400 | 5 |
| 1.5 | 6889 | 87.1 | 89.1 | 44 | 16 | 400 | 8 |
| 2.0 | 6889 | 86.9 | 88.9 | 44 | 16 | 400 | 8 |
| 2.5 | 6889 | 89.0 | 91.0 | 54 | 16 | 400 | 8 |
| 3.0 | 7083 | 69.9 | 86.7 | 38 | 17 | 400 | 12 |
| 3.5 | 7083 | 87.8 | 90.0 | 52 | 16 | 400 | 15 |
| 4.0 | 7083 | 87.8 | 90.0 | 52 | 16 | 400 | 15 |
| 4.5 | 7083 | 90.1 | 92.2 | 45 | 16 | 400 | 15 |
| 5.0 | 7083 | 88.8 | 91.0 | 43 | 16 | 400 | 18 |
| 5.5 | 7308 | 69.6 | 87.1 | 38 | 17 | 400 | 21 |
| 6.0 | 7308 | 87.2 | 89.3 | 43 | 16 | 400 | 21 |
| 6.5 | 7308 | 88.9 | 91.0 | 41 | 16 | 400 | 24 |
| 7.0 | 7308 | 88.8 | 90.9 | 42 | 16 | 400 | 24 |
| 7.5 | 7308 | 89.5 | 91.6 | 42 | 16 | 400 | 24 |
| 8.0 | 7308 | 90.2 | 92.3 | 44 | 16 | 400 | 28 |
| 8.5 | 7308 | 90.3 | 92.4 | 46 | 16 | 400 | 28 |
| 9.0 | 7308 | 89.8 | 91.9 | 46 | 16 | 400 | 28 |
| 9.5 | 7308 | 89.6 | 91.7 | 43 | 16 | 400 | 31 |
| 9.8 | 7308 | 89.6 | 91.8 | 43 | 16 | 400 | 31 |

Hosted runners are shared virtual machines: see benchmarks/README.md for what this run does and does not show.
