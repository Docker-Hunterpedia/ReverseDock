# Benchmark report: ReverseDock 0.4.0-alpha.1

Run on 2026-10-29 with [`run.sh`](../../run.sh): Apple M5 Pro (15 cores), 24 GiB, Docker Desktop (Engine 29.9.2). Every proxy limited to 2 CPUs and 1 GiB; backend and k6 4 CPUs each; 30 s per rate after a 10 s warm-up. Versions: ReverseDock built from this tree, NGINX 1.29.3, HAProxy 3.2.8, Caddy 2.10.2, Traefik 3.5.4, k6 1.3.0. Raw numbers: the JSON files next to this report.

## Findings

- **Up to 10,000 req/s** every proxy keeps up. Medians are 0.17–0.21 ms, and p99 is 0.62–0.66 ms at 5,000 req/s and 1.40–2.21 ms at 10,000 req/s. ReverseDock is in the middle of the group, close to NGINX and Caddy.
- **At 20,000 req/s the lab saturates.** NGINX and HAProxy, the fastest here, reach about 17,000–18,000 req/s, so that is roughly the capacity of this VM with these limits; load generator, proxy and backend share it. ReverseDock sustains 13,700 req/s; Caddy and Traefik fall below 2,000.
- **Overload: ReverseDock degrades worse than NGINX and HAProxy.** At a 40,000 req/s target it completes fewer than 2,000 req/s and 52 % of requests fail, while NGINX and HAProxy keep 16,500–18,800 req/s with about 1 % failures. Under overload it accepts more work than it can finish instead of refusing the excess. `security.limits.max_in_flight` sheds load with `503` today; making overload behaviour good by default is tracked in [#86](https://github.com/Docker-Hunterpedia/ReverseDock/issues/86). **Update 2026-10-30:** the cause was a 128-connection upstream pool; with [ADR-0023](../../../docs/decisions/0023-upstream-connection-pool.md) ReverseDock holds about 14,900 req/s with 0.37 % failures at this load ([results](../2026-10-30-upstream-pool/report.md)).
- These are proxying micro-benchmarks on a laptop VM: small responses, one route, no TLS. Read the ranking, not the absolute numbers, and see [the README](../../README.md#reading-the-results).

## Results

| Proxy | Target req/s | Achieved req/s | p50 ms | p90 ms | p99 ms | p99.9 ms | max ms | Failed | Dropped |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| nginx | 5000 | 5000 | 0.17 | 0.42 | 0.62 | 2.05 | 4.6 | 0.00 % | 0 |
| haproxy | 5000 | 5000 | 0.20 | 0.44 | 0.63 | 2.25 | 5.6 | 0.00 % | 0 |
| traefik | 5000 | 5000 | 0.18 | 0.20 | 0.65 | 2.42 | 8.7 | 0.00 % | 0 |
| caddy | 5000 | 4999 | 0.18 | 0.23 | 0.65 | 2.12 | 7.5 | 0.00 % | 0 |
| rdock | 5000 | 5000 | 0.18 | 0.20 | 0.66 | 2.40 | 9.0 | 0.00 % | 0 |
| haproxy | 10000 | 10000 | 0.17 | 0.22 | 1.40 | 4.59 | 11.2 | 0.00 % | 0 |
| nginx | 10000 | 10000 | 0.18 | 0.23 | 1.62 | 4.39 | 11.0 | 0.00 % | 0 |
| caddy | 10000 | 9999 | 0.20 | 0.27 | 1.84 | 4.72 | 16.4 | 0.00 % | 0 |
| rdock | 10000 | 10000 | 0.21 | 0.30 | 1.92 | 6.83 | 15.7 | 0.00 % | 0 |
| traefik | 10000 | 10000 | 0.21 | 0.29 | 2.21 | 7.34 | 34.5 | 0.00 % | 0 |
| nginx | 20000 | 17884 | 78.12 | 100.26 | 129.63 | 9999.95 | 10010.4 | 0.11 % | 9178 |
| rdock | 20000 | 13702 | 63.51 | 629.21 | 3379.58 | 10000.13 | 10001.2 | 0.87 % | 173820 |
| haproxy | 20000 | 17156 | 27.67 | 85.05 | 5027.89 | 10000.27 | 10009.3 | 0.55 % | 29096 |
| caddy | 20000 | 1883 | 1161.48 | 4444.37 | 5056.29 | 5740.49 | 6986.8 | 0.55 % | 537664 |
| traefik | 20000 | 1927 | 460.73 | 6603.31 | 10005.01 | 10013.63 | 10020.6 | 3.83 % | 525789 |
| rdock | 40000 | 1925 | 205.83 | 933.09 | 7914.03 | 8992.96 | 10004.2 | 52.51 % | 1132652 |
| haproxy | 40000 | 16534 | 27.80 | 30.55 | 9379.98 | 10000.96 | 10065.7 | 0.98 % | 650616 |
| nginx | 40000 | 18795 | 46.05 | 58.87 | 9999.81 | 10000.63 | 10007.3 | 1.14 % | 610805 |
| caddy | 40000 | 1003 | 3491.97 | 8194.90 | 10000.56 | 10001.55 | 10003.0 | 65.97 % | 1168727 |
| traefik | 40000 | 1001 | 1205.27 | 9990.37 | 10001.04 | 10007.80 | 10014.8 | 23.81 % | 1166399 |
