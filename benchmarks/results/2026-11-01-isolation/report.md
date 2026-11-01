# Admin isolation (H-ENG-04)

Machine: Hetzner Cloud, 8 vCPU, 32 GB, Ubuntu 26.04, Docker 29.1. rdock limited to 2 CPUs and 1 GiB, k6 2 CPUs, backend 2 CPUs. Date: 2026-11-01.

4000 req/s for 60s per phase. A phase passes when p99 ≤ 2.80 ms (baseline × 1.25 + 2 ms), failures ≤ baseline + 0.05% and dropped ≤ 0.1%.

| Phase | Achieved req/s | p50 ms | p99 ms | p99.9 ms | max ms | Failed | Dropped | Result |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| baseline | 4000 | 0.28 | 0.64 | 2.60 | 4.9 | 0.000% | 0 | pass |
| login | 4000 | 0.28 | 0.90 | 4.01 | 19.8 | 0.000% | 0 | pass |
| sse | 4000 | 0.26 | 0.63 | 3.59 | 15.0 | 0.000% | 0 | pass |
| apply | 4000 | 0.27 | 0.78 | 3.25 | 6.6 | 0.000% | 0 | pass |
| write-lock | 4000 | 0.27 | 0.66 | 3.13 | 7.2 | 0.000% | 0 | pass |
| stall | 4000 | 0.28 | 0.64 | 3.13 | 5.4 | 0.000% | 0 | pass |
| abort | 4000 | 0.27 | 0.66 | 3.09 | 5.4 | 0.000% | 0 | pass |

Admin side during each phase (attack.py counts by answer):

- apply: `{"mode": "apply", "counts": {"KeyError": 3408, "TimeoutError": 4, "apply 200": 6, "apply 412": 84, "apply 429": 13741, "rollback 200": 1, "rollback 412": 3, "rollback 429": 46}}`
- login: `{"mode": "login", "counts": {"401": 5, "429": 141743}}`
- sse: `{"mode": "sse", "counts": {"opened": 10000}}`
