Soak: 2.0 h, 7,193,012 requests, 7 backend outages, 3 certificate changes, 23 configuration reloads.

| Check | Measured | Limit | Result |
|---|---:|---:|---|
| Memory growth after warm-up | +4.0 MiB | ≤ 16.0 MiB | pass |
| File descriptor growth after warm-up | +2 | ≤ 64 | pass |
| Failed requests | 0.000 % | ≤ 0.1 % | pass |
| Dropped requests | 0.000 % | ≤ 0.1 % | pass |
| Reloads applied | 23 for 23 changes | every change applied | pass |
| Reloads rejected | 0 | 0 | pass |
| Panics in the log | 0 | 0 | pass |

## rdock over time

| Hours | RSS MiB | Threads | File descriptors | TCP connections |
|---:|---:|---:|---:|---:|
| 0.0 | 44.0 | 11 | 23 | 3 |
| 0.2 | 58.8 | 11 | 138 | 118 |
| 0.3 | 60.0 | 11 | 138 | 118 |
| 0.5 | 62.3 | 11 | 138 | 118 |
| 0.7 | 62.2 | 11 | 136 | 116 |
| 0.8 | 61.8 | 11 | 136 | 116 |
| 1.0 | 61.1 | 11 | 133 | 113 |
| 1.2 | 64.2 | 11 | 135 | 115 |
| 1.3 | 64.2 | 11 | 135 | 115 |
| 1.5 | 64.2 | 11 | 135 | 115 |
| 1.7 | 64.2 | 11 | 141 | 121 |
| 1.8 | 65.0 | 11 | 140 | 120 |
| 2.0 | 63.7 | 11 | 139 | 119 |

Latency per 12 windows: median p99 0.33 ms, worst p99 0.37 ms, first 0.37 ms, last 0.34 ms.
