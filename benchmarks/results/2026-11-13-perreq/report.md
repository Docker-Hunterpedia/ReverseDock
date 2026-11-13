# Per-request cost, before and after the v0.9 request-path changes (2026-11-13)

Measured with [`perreq`](../../README.md#per-request-cost-without-docker) on 2026-11-13, without Docker and without k6.

**Machine:** a development sandbox, not a lab: 4 shared vCPUs (Intel Xeon @ 2.10 GHz), 15 GiB, Linux 6.18, other tenants' load average around 1–3 during the runs. rdock ran on CPUs 0–1 (`taskset`), the tool (client and backend) on CPUs 2–3. **Only the counts are exact. CPU time is relative**: it compares two builds on the same machine within one session, and no absolute figure here stands for the lab or for production.

**Builds.** Baseline (A): `main` at `5c7d7f8` (0.8.0-alpha.1) plus the bench-only `alloc-count` feature, which does not touch the request path. After (B): the same tree with the per-request changes of issue 181 and the socket and runtime options of H-PERF-01 (ADR-0031). Counts come from debug builds with `--features alloc-count` (the system allocator, counted); CPU time from release builds with `--no-default-features --features mimalloc` and `CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16` for build time, the same for A and B.

**Workload.** One route per host to one service, a backend answering 1 KiB, four kept-alive client connections, access log off, admin API off (the benchmark configuration). Counts: N = 2,000 then 2N = 4,000 requests after a warm-up that reaches every route; CPU: N = 20,000 then 40,000, reported over the 40,000.

## Counts per request

Raw: [`baseline/`](baseline/) and [`after/`](after/) (`allocs.jsonl`, `syscalls.jsonl`).

| Variant | Allocations before → after | Bytes allocated before → after | System calls before → after |
|---|---:|---:|---:|
| 1 route | 137.5 → 125.5 | 121,195 → 120,943 | 6.34 → 6.75 |
| 1,000 routes | 137.5 → 125.6 | 121,200 → 120,938 | 6.42 → 6.38 |
| 10,000 routes | 137.7 → 125.5 | 121,177 → 120,934 | 6.34 → 6.46 |
| 1 route, 20 browser-like headers | 169.6 → 140.5 | 134,965 → 133,827 | 6.79 → 6.55 |
| HTTPS, reused connection | 139.6 → 127.5 | 122,523 → 122,244 | 6.32 → 6.66 |

- Allocations are repeatable to about ±0.3 per request between runs of one binary.
- **System calls did not change.** The calls a request makes are the same before and after: 2 `recvfrom`, 2 `sendto` and 1 `getpeername` (HTTPS: 1 `sendto` and 1 `writev`), 5.00 per request in every run. The rest are `futex` and `epoll_wait` wake-ups, which depend on timing: three alternating runs of each build with one route gave 6.28–6.48 (before) and 6.28–6.36 (after) ([`syscalls-aa/`](syscalls-aa/)). The differences in the table are that noise.
- About 120 KB of the bytes allocated per request are Pingora's 64 KiB upstream body buffer and similar per-request buffers, untouched here.

### Where the allocations went

Measured by putting one change back in the "after" tree (allocations per request, one route):

| Change | 3 headers | 20 headers |
|---|---:|---:|
| `remove_managed` compares header names in place instead of a `String` per header (`forwarded.rs`) | −3.0 | −19.9 |
| No copy of every client read; only the header phase is scanned (`conn.rs`) | −1.1 | −1.0 |
| The rest together: request ID encoded once, no empty `Arc<str>` per request, the authority moved instead of copied, a shortcut for paths that are already normal, backend selection without the source list and with one list of eligible backends | about −8 | about −8 |
| Host index for routing, moving the spool handle into the hold, borrowing the route, lazy rings | 0 (no allocations; CPU and memory, below) | 0 |

## CPU time per request (relative)

Raw: [`cpu/cpu.jsonl`](cpu/cpu.jsonl). Six rounds; each round ran A, B, A for every variant, so each variant has 12 A runs and 6 B runs. The **A/A spread** is (max − min) ÷ median of the A runs; a change counts only when it is larger than **twice** that spread.

| Variant | A median µs | B median µs | A/A spread | B/A | Verdict |
|---|---:|---:|---:|---:|---|
| 1 route | 75.4 | 75.8 | 8.8 % | 1.006 | within noise |
| 1,000 routes | 84.1 | 74.6 | 16.1 % | 0.886 | within noise (every B run, 73.9–76.2, was below every A run, 77.3–90.8, but the rule does not count it) |
| **10,000 routes** | **180.4** | **78.0** | 19.3 % | **0.433** | **lower by 57 %** |
| 1 route, 20 headers | 87.2 | 83.7 | 9.9 % | 0.961 | within noise |
| HTTPS, reused connection | 80.6 | 76.9 | 12.2 % | 0.954 | within noise |

- **Routing:** before, CPU per request at 10,000 routes was 2.4× that of one route (the linear scan); after, 1.03×, inside the noise. That is the host index (candidate 1 of issue 181).
- Everything else is within this machine's noise, as the research expected (about 1 % each). The gate "no regression beyond twice the A/A spread" holds for every variant.
- The absolute values happen to be close to the lab's 76 µs; that is a coincidence of this machine, not a comparison.

## TLS tail during a burst of handshakes (issue 181 step 4)

Raw: [`tail/tail.jsonl`](tail/tail.jsonl). rdock on 2 CPUs; eight established TLS connections send 2,000 requests a second on a fixed schedule for 8 s; at 3 s a second process on its own CPU opens 500 new TLS connections (P-256 certificate), all at once or spread over 2 s. Latency of the established connections' requests in the burst window (from its start to 1 s after its last connection) and outside it; three runs each, separated by ·.

| `tls.max_handshakes` | Burst | Established, in the burst: p99 / p99.9 / max ms | Outside the burst: p99 / max ms | New connections' handshake p50 / max ms |
|---|---|---|---|---|
| unset | all at once | 75.8 / 81.0 / 84.2 · 83.5 / 91.0 / 92.5 · 39.6 / 44.0 / 45.0 | 2.2–2.8 / 4.7–14.1 | 50–63 / 108–128 |
| unset | over 2 s | 6.5 / 20.4 / 23.5 · 15.3 / 32.1 / 35.0 · 5.7 / 16.2 / 19.3 | 2.5 / 5.2–6.5 | 0.53–0.56 / 23–43 |
| 32 | all at once | 10.7 / 12.8 / 13.2 · 26.3 / 30.0 / 32.9 · 25.7 / 28.6 / 29.9 | 2.5–2.6 / 6.6–9.7 | 91–103 / 117–134 |
| 32 | over 2 s | 11.3 / 22.4 / 25.1 · 3.2 / 14.5 / 17.5 · 7.8 / 17.9 / 20.7 | 2.4 / 6.8–9.3 | 0.53–0.54 / 21–32 |
| 8 | all at once | 14.8 / 19.7 / 20.5 · 5.7 / 8.4 / 9.6 · 3.7 / 5.2 / 6.2 | 2.3–2.8 / 5.1–9.8 | 116–136 / 148–178 |
| 8 | over 2 s | 2.7 / 10.6 / 13.7 · 3.0 / 11.6 / 13.1 · 3.4 / 19.7 / 22.4 | 2.6–2.8 / 5.9–7.6 | 0.52–0.58 / 21–24 |

What this sandbox measurement shows, with the caveat that the machine is shared:

- **The shape of the published tail reproduces.** With all 500 connections at once and no bound, requests on established connections stall for 45–93 ms during the burst (p99.9 44–91 ms), while outside it their p99 stays at 2–3 ms: one stall per burst, not a steady delay, as the research read from the lab's files (p99.9 30.7 ms, max 73.7 ms at 10,000 req/s).
- **Opening the same connections over 2 s removes most of it** (p99.9 16–32 ms, max 19–35 ms; the handshakes themselves take 0.5 ms at the median instead of 50–63 ms). The benchmark's `tls` scenario therefore measures its own connection storm; the new `tls-ramped` scenario is the comparison to run in the lab.
- **`tls.max_handshakes` protects established connections during a storm**: with a bound of 8 their worst request in the burst took 6–20 ms instead of 45–93 ms, with 32 it took 13–33 ms. The price is paid by the new connections, which wait in the backlog: their median handshake time rises from 50–63 ms to 91–103 ms (32) and 116–136 ms (8). No connection failed in any run.
- The effect is several times larger than the run-to-run spread, so the direction is clear; the exact numbers are not lab numbers and do not decide a default. The default stays unset (ADR-0031) until the experiment is repeated on lab hardware with k6.

## Reproduce

    cargo build --locked -p rdock --features alloc-count     # counts (debug), before and after
    cargo build --locked -p rdock-perreq
    PERREQ=target/debug/rdock-perreq benchmarks/perreq/run.sh counts <alloc-count rdock> <dir>
    # release builds of rdock (A and B) and rdock-perreq, then:
    benchmarks/perreq/run.sh cpu <rdock A> <rdock B> <dir> 3      # twice, for six rounds
    benchmarks/perreq/run.sh tail <rdock B> <dir> [max_handshakes]
    python3 -I benchmarks/perreq/summarize.py counts <before> <after>
    python3 -I benchmarks/perreq/summarize.py cpu <dir>
    python3 -I benchmarks/perreq/summarize.py tail <dir>
