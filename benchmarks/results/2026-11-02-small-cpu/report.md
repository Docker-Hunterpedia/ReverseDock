# Benchmark: performance on small machines (#93)

Run on 2026-11-02 on a dedicated Linux server (Hetzner, 8 vCPUs, 32 GiB, Ubuntu 26.04, Docker 29.1.3), with the [usual lab](../../README.md): every proxy in its own container limited to **2 CPUs and 1 GiB**, the backend and k6 with 4 CPUs each, k6's open model, 10 s warm-up and 30 s at each target rate. Nothing else ran on the machine. All six scenarios ran with all five proxies in one session (`for s in single lb tls tls-new slow routes; do SCENARIO=$s VERSION=2026-11-02-small-cpu ./run.sh; done`).

- **ReverseDock now:** `main` at `36f64a9`, the four fixes for [#93](https://github.com/Docker-Hunterpedia/ReverseDock/issues/93) merged: [#170](https://github.com/Docker-Hunterpedia/ReverseDock/pull/170) (open-file limit), [#172](https://github.com/Docker-Hunterpedia/ReverseDock/pull/172) (mimalloc), [#173](https://github.com/Docker-Hunterpedia/ReverseDock/pull/173) (no `getrandom` per request, no unread access-log record), [#174](https://github.com/Docker-Hunterpedia/ReverseDock/pull/174) (buffered writes to the client). Results in this folder.
- **ReverseDock before:** `main` at `c3e2f1a`, the same morning, before those fixes. Results in [`before/`](before/).
- **The others:** NGINX 1.29.3, HAProxy 3.2.8, Caddy 2.10.2, Traefik 3.5.4, the versions pinned in [`compose.yaml`](../../compose.yaml), with the [configurations](../../configs/) of each scenario.

## Summary

On 2 CPUs, ReverseDock completes about twice as many requests per second as before in most scenarios, and as many as NGINX. It failed no request in any scenario at any rate, including the 40,000 req/s target where NGINX fails 1–4 %. HAProxy stays ahead on plain throughput (ReverseDock is at 0.75–0.82× of it, except with new TLS connections, where ReverseDock is 1.8× faster); [#176](https://github.com/Docker-Hunterpedia/ReverseDock/issues/176) follows that up. NGINX still uses less CPU per request (about 50 µs against 76) and has a lower p99 at moderate rates, by 0.1–0.5 ms.

The two targets of #93 are met: peak throughput at least 0.9× NGINX's (lowest: 0.95×, `routes`), and a p99 at 5,000 req/s at most 3× NGINX's (highest: 1.3×). Of [#91](https://github.com/Docker-Hunterpedia/ReverseDock/issues/91), the peak is within 5 % of NGINX and the p99 at 10,000 req/s within 1.5× (highest: 1.4×, `routes`); the p99.9 at 10,000 is within 2× for plain HTTP but not for `tls`, where ReverseDock's tail is 30.7 ms against NGINX's 4.8 ms.

## What changed, and what each change did

`perf`, `strace -c` and the container's `cpu.stat` on the `before` build showed four costs, each fixed in its own pull request and measured alone on the same lab before being combined. CPU time per request, from `cpu.stat` over 30 s at each rate with a single backend (the [ladders](fixes/)):

| Rate | before | + open-file limit | + mimalloc | + write buffer | combined branch | `main` now | NGINX |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2,500 | 174 | 185 | 95 | 162 | 81 | **81** | 42 |
| 5,000 | 139 | 151 | 90 | 128 | 75 | **76** | 47 |
| 7,500 | 157 | 187 | 90 | 142 | 76 | **77** | 56 |
| 10,000 | 164 | 172 | 90 | 154 | 76 | **76** | 56 |
| 12,500 | 147 | 152 | 88 | 143 | 75 | **76** | 53 |

1. **Open-file limit** (#170): the container's soft limit of 1,024 file descriptors capped ReverseDock near 500 requests in flight, so every stall became errors. Raising it to the hard limit at start does not save CPU (the column above is noise) but removes the cap: the `before` build failed 1–3 % of requests at the 40,000 target, the fixed one none.
2. **mimalloc** (#172): musl's allocator mapped and unmapped memory for every 64 KiB buffer and took a global lock; `perf` put about 27 % of CPU in it. mimalloc as the global allocator takes CPU per request from 139 to 90 µs.
3. **Hot-path syscalls** (#173): a `getrandom` call per request for the request id, and an access-log record built for every request even when the log is off. UUIDv7 ids from a thread-local generator and skipping the record when nobody reads it; this one was measured only in the combined branch.
4. **Write buffer** (#174): Pingora's stream wrote the response head and the body in two `sendto` calls, so every response left as two TCP segments and the client ACKed twice. An 8 KiB write buffer flushed at the end of the response sends one segment: 3 → 2 segments per request each way, and about 8 % less CPU.

Together they take CPU per request from 139 to 76 µs and the peak with a single backend from 11,839 to 24,619 req/s.

## Peak throughput

The highest completed req/s at any target rate, counting only runs with under 5 % failed requests. Caddy and Traefik collapse above 10,000 req/s in this lab; see below.

| Scenario | ReverseDock before | ReverseDock now | NGINX | HAProxy | Caddy | Traefik |
|---|---:|---:|---:|---:|---:|---:|
| Single backend | 11,839 (2.7% failed) | **24,619** | 24,889 (1.2% failed) | 31,895 | 10,000 | 10,000 |
| Load balancing | 10,000 | **24,094** | 24,986 (1.1% failed) | 31,960 | 10,000 | 10,000 |
| TLS, reused connections | 10,091 (3.0% failed) | **22,326** | 21,600 (1.4% failed) | 29,991 | 9,971 | 9,976 |
| TLS, new connections | 4,999 | **5,821** | 3,815 (3.5% failed) | 3,227 | 1,062 (1.9% failed) | 2,009 |
| Slow backend (100 ms) | 3,698 (1.0% failed) | **17,755** | 9,556 (3.1% failed) | 19,091 | 4,952 | 9,823 |
| Many routes | 10,673 (3.1% failed) | **23,075** | 24,221 (1.3% failed) | 28,106 | 3,761 (0.3% failed) | 10,000 |

## Latency

p99 in ms (for `tls-new`, k6's `iteration_duration`, which includes the handshake; for `slow`, the backend's 100 ms is included). "Behind" marks a run that did not keep up with the target rate, so its latency is queueing, not proxying.

At 5,000 req/s:

| Scenario | ReverseDock before | ReverseDock now | NGINX | HAProxy | Caddy | Traefik |
|---|---:|---:|---:|---:|---:|---:|
| Single backend | 1.35 | **0.46** | 0.35 | 0.37 | 0.70 | 0.52 |
| Load balancing | 1.37 | **0.53** | 0.40 | 0.34 | 0.68 | 0.57 |
| TLS, reused connections | 1.43 | **0.49** | 0.45 | 0.65 | 0.77 | 0.55 |
| TLS, new connections | 31.07 | **6.23** | 10000.25 (2.6% failed) | 1331.29 (behind) | 10000.15 (1.9% failed) | 5525.84 (behind) |
| Slow backend (100 ms) | 104.60 (1.0% failed) | **102.14** | 102.29 | 102.26 | 105.40 | 102.80 |
| Many routes | 1.51 | **0.53** | 0.42 | 0.60 | 46.48 (0.3% failed) | 0.66 |

At 10,000 req/s:

| Scenario | ReverseDock before | ReverseDock now | NGINX | HAProxy | Caddy | Traefik |
|---|---:|---:|---:|---:|---:|---:|
| Single backend | 6.98 | **1.17** | 1.13 | 0.94 | 6.44 | 1.29 |
| Load balancing | 8.97 | **1.41** | 1.11 | 0.92 | 3.82 | 1.45 |
| TLS, reused connections | 12.04 | **2.10** | 1.76 | 1.79 | 24.69 | 11.87 |
| TLS, new connections | 7336.98 (0.5% failed) | **2729.23 (behind)** | 10000.25 (3.3% failed) | 1327.57 (behind) | 10003.44 (36.3% failed) | 10003.03 (17.6% failed) |
| Slow backend (100 ms) | 6916.08 (6.8% failed) | **110.39** | 106.60 (0.5% failed) | 109.46 | 5552.60 (behind) | 118.94 |
| Many routes | 7.93 | **1.70** | 1.21 | 2.09 | 10000.60 (17.6% failed) | 2.44 |

## Failed requests at the 40,000 req/s target

| Scenario | ReverseDock | NGINX | HAProxy |
|---|---:|---:|---:|
| Single backend | 0.00% | 1.22% | 0.00% |
| Load balancing | 0.00% | 1.10% | 0.00% |
| TLS, reused connections | 0.00% | 1.36% | 0.00% |
| TLS, new connections | 0.00% | 3.76% | 0.00% |
| Slow backend (100 ms) | 0.00% | 3.11% | 0.00% |
| Many routes | 0.00% | 1.35% | 0.00% |

Caddy and Traefik are left out: both failed most requests at this rate.

## Large responses

Two more scenarios, added for this report: the backend answers with 100 KiB (`large`, at 1,000 to 10,000 req/s) and with 1 MiB (`huge`, at 100 to 1,000 req/s). Each cell is the p99 in ms when the proxy kept up with the rate, otherwise what it completed.

100 KiB responses:

| Target req/s | ReverseDock | NGINX | HAProxy | Caddy | Traefik |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 0.38 | 0.57 | 0.43 | 0.46 | 0.43 |
| 2,500 | 0.49 | 0.80 | 0.57 | 0.69 | 0.60 |
| 5,000 | 0.80 | 1.66 | 1.15 | 1.30 | 0.92 |
| 10,000 | 6.17 | 7,470 done, 1.0% failed | 7,460 done | 1,728 done | 2,374 done, 15.5% failed |

1 MiB responses:

| Target req/s | ReverseDock | NGINX | HAProxy | Caddy | Traefik |
|---:|---:|---:|---:|---:|---:|
| 100 | 1.06 | 2.43 | 1.82 | 1.49 | 1.21 |
| 250 | 0.90 | 2.25 | 1.52 | 1.15 | 1.03 |
| 500 | 0.84 | 30.43 | 1.58 | 1.13 | 1.02 |
| 1,000 | 1.27 | 18.82 | 1.74 | 1.49 | 1.46 |

At 10,000 req/s of 100 KiB, 1 GB/s, ReverseDock is the only one of the five that keeps up on 2 CPUs; NGINX and HAProxy complete about 7,500. With 1 MiB responses every proxy keeps up to 1,000 req/s (also 1 GB/s) and ReverseDock has the lowest p99 at every rate; NGINX's tail at 500 and 1,000 req/s is in the tens of milliseconds. Results in [`large/`](large/) and [`huge/`](huge/).

## Caddy and Traefik above 10,000 req/s

Both keep up with 10,000 req/s but complete under 5,000 at the 20,000 target and almost nothing at 40,000. The server's kernel log shows the memory limit killing Traefik three times and Caddy once during the run; both also spent most of each 100 ms period throttled by the 2-CPU quota. To check that the lab, not the proxies, was the cause, the `single` scenario ran again for both with `GOMAXPROCS=2` (Traefik is built with Go 1.24, which does not read the container's CPU quota by itself), and then with 8 GiB of memory on top:

| Setup (`single`, 2 CPUs) | Traefik at 20,000 | Traefik at 40,000 | Caddy at 20,000 | Caddy at 40,000 |
|---|---:|---:|---:|---:|
| As published, 1 GiB | 2,525 (11.7 % failed) | killed by the memory limit | 1,358 (2.9 % failed) | 837 (23.5 % failed) |
| `GOMAXPROCS=2`, 1 GiB | 1,678 (22.8 % failed) | killed by the memory limit | 1,453 | 800 (31.7 % failed) |
| `GOMAXPROCS=2`, 8 GiB | 2,595 | 1,063 (23.6 % failed) | 1,524 | 712 (35.3 % failed) |

Neither change helps: with the memory limit lifted, Traefik is no longer killed but still completes about 2,600 req/s at the 20,000 target, and Caddy about 1,500. Both containers were throttled by the CPU quota in most 100 ms periods. With two CPUs, once requests arrive faster than they are answered, the open model piles up connections (k6 holds up to 4,000) and the two Go proxies spend their CPU on the backlog instead of on answers. ReverseDock, NGINX and HAProxy answer what they can and keep the rest short.

The numbers for Caddy and Traefik in this report are what a 2-CPU, 1 GiB container gives; they are not a measure of either proxy on a bigger machine.

## Read with care

- One machine, one lab, 2 CPUs, 1 KiB responses. Other hardware gives other numbers; compare proxies within one run only.
- Run-to-run noise is about 10 %: NGINX's single-backend peak was 22,638 in one session and 24,889 in the next. Differences of a few percent between proxies mean "about the same".
- HAProxy is faster on plain proxying: 0.75–0.82× is the honest ratio, and the remaining cost is in cross-thread wake-ups in the runtime, not in ReverseDock's request path ([#176](https://github.com/Docker-Hunterpedia/ReverseDock/issues/176)).
- Bigger machines (4 and 8 CPUs) are not measured here; the lab's load generator needs more CPUs than this server has.

## Files

- [`single/`](single/), [`lb/`](lb/), [`tls/`](tls/), [`tls-new/`](tls-new/), [`slow/`](slow/), [`routes/`](routes/), [`large/`](large/), [`huge/`](huge/): one JSON per proxy and rate, and the generated `report.md`, for `main` at `36f64a9`.
- [`before/`](before/): the same for `main` at `c3e2f1a`.
- [`cpu.txt`](cpu.txt), [`before/cpu.txt`](before/cpu.txt), [`fixes/`](fixes/): the CPU ladders (`cpu.stat` of the proxy's cgroup after 30 s at each rate; µs per request = `usage_usec` ÷ (rate × 30)).
