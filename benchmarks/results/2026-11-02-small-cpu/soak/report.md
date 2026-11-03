# 24-hour soak of the v0.5 release candidate

Run from 2026-11-02 22:18 UTC to 2026-11-03 22:18 UTC on the same server as the [benchmarks](../report.md) (Hetzner, 8 vCPUs, 32 GiB, Ubuntu 26.04, Docker 29.1.3), with [`benchmarks/soak/`](../../../soak/) at its defaults: `main` at `36f64a9` built as `rdock:final`, limited to 2 CPUs and 1 GiB, three backends, 1,000 req/s alternating plain HTTP and HTTPS, a reload every 5 minutes, one backend stopped every 15 minutes for a minute, the certificate replaced every 30 minutes. The admin side stayed on (the default loopback listener, 2 admin threads), so the probe measured the whole process. Nothing else ran on the machine.

The run **passed** every check of [`analyze.py`](../../../soak/analyze.py). Its output follows unchanged.

Two things to know when reading the windows:

- Four windows show a maximum of about 5 s (`windows/0016.json`, `0017.json`, `0019.json`, `0029.json`). Each one coincides with a backend being stopped: one request waited the full 5 s default connect timeout on the stopped backend before its retry succeeded on another. No request failed. The default connect timeout is reviewed separately.
- Window 70 (`windows/0070.json`) has a p99 of 0.89 ms, the only one above 0.4 ms, with a maximum of 49 ms. Nothing in the events or the log explains it; a short stall of the host is the likely cause.

Files: `probe.csv` (every 30 s: RSS, threads, file descriptors, TCP connections), `events.csv` (reloads, backend stops and starts, certificate changes), `windows/` (one k6 summary per 10-minute window).

---

Soak: 24.0 h, 86,306,108 requests, 95 backend outages, 47 certificate changes, 287 configuration reloads.

| Check | Measured | Limit | Result |
|---|---:|---:|---|
| Memory growth after warm-up | +0.3 MiB | ≤ 16.0 MiB | pass |
| File descriptor growth after warm-up | -2 | ≤ 64 | pass |
| Failed requests | 0.000 % | ≤ 0.1 % | pass |
| Dropped requests | 0.000 % | ≤ 0.1 % | pass |
| Reloads applied | 287 for 287 changes | every change applied | pass |
| Reloads rejected | 0 | 0 | pass |
| Panics in the log | 0 | 0 | pass |

## rdock over time

| Hours | RSS MiB | Threads | File descriptors | TCP connections |
|---:|---:|---:|---:|---:|
| 0.0 | 43.7 | 11 | 23 | 3 |
| 2.0 | 60.9 | 11 | 151 | 131 |
| 4.0 | 61.8 | 11 | 135 | 115 |
| 6.0 | 60.9 | 11 | 137 | 117 |
| 8.0 | 61.6 | 11 | 137 | 117 |
| 10.0 | 62.1 | 11 | 177 | 157 |
| 12.0 | 61.7 | 11 | 141 | 121 |
| 14.0 | 61.7 | 11 | 135 | 115 |
| 16.0 | 61.2 | 11 | 162 | 142 |
| 18.0 | 61.7 | 11 | 135 | 115 |
| 20.0 | 61.8 | 11 | 157 | 137 |
| 22.0 | 62.2 | 11 | 136 | 116 |
| 24.0 | 62.3 | 11 | 137 | 117 |

Latency per 144 windows: median p99 0.33 ms, worst p99 0.89 ms, first 0.32 ms, last 0.34 ms.
