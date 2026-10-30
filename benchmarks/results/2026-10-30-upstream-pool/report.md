# Benchmark: upstream keep-alive pool (#86)

Run on 2026-10-30 on the same machine and setup as [0.4.0-alpha.1](../0.4.0-alpha.1/report.md), with ReverseDock built from `main` plus [ADR-0023](../../../docs/decisions/0023-upstream-connection-pool.md) (`upstream_idle_connections: 4096`), and NGINX in the same session for comparison: `PROXIES="rdock nginx" RATES="10000 40000" ./run.sh`.

At a 40,000 req/s target ReverseDock now sustains about 14,900 req/s with 0.37 % failures, instead of collapsing to 1,925 req/s with 52 % failures. NGINX reaches about 17,100 req/s with 1.29 % failures. At 10,000 req/s both keep up; p99 is 3.2 ms for ReverseDock and 2.0 ms for NGINX.

| Proxy | Target req/s | Achieved req/s | p50 ms | p90 ms | p99 ms | p99.9 ms | max ms | Failed | Dropped |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| nginx | 10000 | 9999 | 0.18 | 0.23 | 2.03 | 6.49 | 21.0 | 0.00 % | 0 |
| rdock | 10000 | 10000 | 0.22 | 0.34 | 3.23 | 26.34 | 59.2 | 0.00 % | 0 |
| rdock | 40000 | 14931 | 136.04 | 422.13 | 1003.59 | 8800.16 | 10001.1 | 0.37 % | 749502 |
| nginx | 40000 | 17137 | 37.05 | 58.10 | 10000.02 | 10027.82 | 10035.9 | 1.29 % | 633477 |
