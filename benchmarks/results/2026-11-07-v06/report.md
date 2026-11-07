# v0.6 on the small-CPU lab, a 2-hour soak, and a 3-node Swarm

Run on 2026-11-07 on the same server and lab as [the v0.5 results](../2026-11-02-small-cpu/report.md) (Hetzner, 8 vCPUs, 32 GiB, Ubuntu 26.04, Docker 29.1.3): every proxy limited to **2 CPUs and 1 GiB**, backend and k6 with 4 CPUs each, k6's open model, 10 s warm-up and 30 s per target rate. ReverseDock is `main` at `c71a538`, with every v0.6 feature merged (TCP routes, PROXY protocol, Swarm, static files, DNS adapters, the per-attempt connect budget). NGINX 1.29.3 and HAProxy 3.2.8 ran in the same session; Caddy and Traefik were left out because v0.5 already showed where they stand on 2 CPUs.

## Summary

- **No regression beyond the lab's noise.** ReverseDock's peaks are 3–6 % lower than on 2026-11-02, but its ratio to NGINX and HAProxy run in the same session is unchanged in every scenario (NGINX's own p99 was about 25 % higher this session, so the machine was slower overall). ReverseDock still failed no request at the 40,000 req/s target, where NGINX failed 1.2–3.5 %.
- **CPU per request** is about 80 µs at 10,000 req/s against 76 µs for v0.5: within noise, and the number to watch in the profiling work of [#181](https://github.com/Docker-Hunterpedia/ReverseDock/issues/181).
- **The connect budget works** ([#185](https://github.com/Docker-Hunterpedia/ReverseDock/issues/185)): in the 2-hour soak, the longest request across 7 backend stops was 1.04 s, against 5.0 s per stop in v0.5.
- **The 3-node Swarm lab found a gap and confirmed the fix:** rolling updates lost 0.08–0.23 % of requests with the default settings because a service without `retries` did not retry a failed connection; with one connection retry, no request failed in any phase. [#206](https://github.com/Docker-Hunterpedia/ReverseDock/pull/206) makes that retry the default.

## Peak throughput

Highest completed req/s at any target rate with under 5 % failed. Ratios compare with NGINX and HAProxy in the same session.

| Scenario | v0.5 | v0.6 | Change | ÷ NGINX v0.5 → v0.6 | ÷ HAProxy v0.5 → v0.6 |
|---|---:|---:|---:|---:|---:|
| Single backend | 24,619 | 23,303 | −5.3 % | 1.00 → 0.96 | 0.77 → 0.76 |
| Load balancing | 24,094 | 23,163 | −3.9 % | 0.98 → 1.00 | 0.75 → 0.76 |
| TLS, reused connections | 22,326 | 21,098 | −5.5 % | 1.05 → 1.04 | 0.74 → 0.75 |
| TLS, new connections | 5,821 | 5,544 | −4.8 % | 1.58 → 1.56 | 1.80 → 1.79 |
| Slow backend (100 ms) | 17,755 | 17,161 | −3.3 % | 1.92 → 1.96 | 0.93 → 0.93 |
| Many routes | 23,075 | 21,997 | −4.7 % | 0.97 → 1.05 | 0.82 → 0.82 |

## Latency

p99 in ms; NGINX in the same session in brackets.

| Scenario | 5,000 req/s, v0.5 → v0.6 | 10,000 req/s, v0.5 → v0.6 |
|---|---:|---:|
| Single backend | 0.46 → 0.56 (0.35 → 0.46) | 1.17 → 1.43 (1.13 → 1.38) |
| Load balancing | 0.53 → 0.63 (0.40 → 0.49) | 1.41 → 1.67 (1.11 → 1.24) |
| TLS, reused connections | 0.49 → 0.71 (0.45 → 0.55) | 2.10 → 2.50 (1.76 → 2.02) |
| Many routes | 0.53 → 0.65 (0.42 → 0.52) | 1.70 → 1.91 (1.21 → 1.26) |

ReverseDock's p99 rose by about as much as NGINX's in the same session. Failed requests at the 40,000 req/s target: ReverseDock 0 % in all six scenarios; NGINX 1.23 % (single), 1.41 % (lb), 1.54 % (tls), 3.45 % (tls-new), 3.18 % (slow), 1.72 % (routes).

## CPU per request

`cpu.stat` of the proxy's cgroup over 30 s at each rate, single backend: µs per request = `usage_usec` ÷ (rate × 30).

| Rate | v0.5 | v0.6 |
|---:|---:|---:|
| 2,500 | 81 | 85 |
| 5,000 | 76 | 79 |
| 7,500 | 77 | 81 |
| 10,000 | 76 | 80 |
| 12,500 | 76 | 79 |

## 2-hour soak

[`benchmarks/soak/`](../../soak/) at its defaults for 2 hours (1,000 req/s, reload every 5 minutes, one backend stopped every 15 minutes, certificate change every 30 minutes, admin side on): 7,193,012 requests, none failed or dropped, memory +4.0 MiB after warm-up (63.7 MiB at the end), file descriptors +2, 23 of 23 reloads applied, no panic, p99 per 10-minute window 0.32–0.37 ms. The longest request in each window: 8, 19, 26, 6, 19, 17, 6, 25, 25, 7, **1,039** and 7 ms. The 1,039 ms is one request whose first connection attempt went to the stopped backend and gave up after `timeouts.connect_attempt` (1 s) before the retry succeeded; in v0.5 four windows of the 24-hour soak had a 5,000 ms maximum for the same reason. [Report](soak/report.md).

## 3-node Swarm

Three LXD system containers on the server (Ubuntu 24.04, Docker 29.1.3, 2 CPUs and 4 GiB each), joined as three managers with an attachable overlay network. ReverseDock runs as a **global** service with port 80 published in host mode on every node and the Swarm provider in its default task mode; `traefik/whoami` runs with 6 replicas and `update_config: { order: start-first, parallelism: 1, delay: 3s }`. k6 sends 300 req/s across the three nodes' addresses and counts every answer that is not 200. Each node has its own Docker daemon and network stack, so the overlay (VXLAN) runs between nodes; they share one kernel, which three separate hosts would not. Stack, configuration and script: [`swarm/lab/`](swarm/lab/).

| Phase | Default settings | One connection retry |
|---|---:|---:|
| Baseline, 60 s | 0 of 18,001 | 0 of 18,001 |
| Rolling update, `start-first`, 120 s | **85 of 36,001** (0.23 %) | 0 of 36,000 |
| Scale 6 → 2 → 6, 90 s | 0 of 27,001 | 0 of 27,001 |
| Drain one node (traffic to the other two), 90 s | 0 of 27,001 | 0 of 27,001 |
| Rolling update, `stop-first`, 120 s | **31 of 36,001** (0.08 %) | 0 of 36,001 |

With default settings ReverseDock logged 81 failed answers in these phases, every one for a task Swarm had just stopped: 80 × 504 after the 5 s connect timeout and 1 × 502 for a refused connection ([`swarm/before/failures.csv`](swarm/before/failures.csv)); k6's own 5 s request timeout ends some of the same requests first, so its count is higher. The cause: ReverseDock learns of it at its next task poll (every 5 s, because Swarm sends no task events), and a service without `retries` did not try another task, so each such request waited the full 5 s connect timeout. With one connection retry (Traefik's `retry` middleware on the router, which ReverseDock maps to `retries: { attempts: 1 }`), nothing failed; the slowest request took 1.04 s in the `start-first` update and 1.04 s in the `stop-first` one (the connect budget), and p95 stayed under 0.7 ms in every phase ([`swarm/with-retry/`](swarm/with-retry/)). [#206](https://github.com/Docker-Hunterpedia/ReverseDock/pull/206) makes a connection retry the default for every service.

## Read with care

- One machine, 2 CPUs per proxy, 1 KiB responses; run-to-run noise on this lab is about 10 % (see the v0.5 report). Compare proxies within one session.
- The Swarm nodes are containers on one host: they test the provider, overlay networking between daemons, rolling updates, drain and global mode, but not separate NICs, MTU differences or a node that loses power.
- The 4- and 8-CPU rungs are not here: the test server has 8 vCPUs, and an 8-CPU proxy needs about 12 more for k6.

## Files

- [`single/`](single/), [`lb/`](lb/), [`tls/`](tls/), [`tls-new/`](tls-new/), [`slow/`](slow/), [`routes/`](routes/): one JSON per proxy and rate, and the generated `report.md`.
- [`cpu.txt`](cpu.txt): the CPU ladder.
- [`soak/`](soak/): the soak report, `probe.csv`, `events.csv` and one k6 summary per window.
- [`swarm/`](swarm/): the lab files, and for each run the k6 output per phase, the task lists and the non-200 answers taken from ReverseDock's access logs.
