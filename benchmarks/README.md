# Benchmarks

Reproducible comparisons of ReverseDock with NGINX, HAProxy, Caddy and Traefik (H-ENG-01). Every proxy runs the same job with the same limits, and anyone with Docker can run it again.

## What is measured

One route forwards every request to one backend, an NGINX serving a fixed 1 KiB page. Each proxy:

- listens on plain HTTP on `:8080` and keeps connections to the backend alive;
- has access logging off, and no other feature turned on;
- runs in its own container limited to **2 CPUs and 1 GiB**; the backend gets 4 CPUs, k6 4 CPUs.

Configurations: [`configs/`](configs/). Versions are pinned in [`compose.yaml`](compose.yaml).

### Scenarios

`SCENARIO=<name> ./run.sh` measures something other than the bare proxy. Results go to `results/<version>/<name>/`.

| Scenario | What changes | What it shows |
|---|---|---|
| `single` (default) | One route, one backend, plain HTTP | The cost of the proxy itself |
| `lb` | Three backends, round-robin; they share the same 4 CPUs (1.33 each) | The load balancer |
| `tls` | HTTPS with kept-alive connections, HTTP/1.1, a P-256 certificate | Encryption per request |
| `tls-ramped` | Like `tls`, with the rate reached over 2 s (`RAMP`) instead of at once, so k6 opens its connections gradually | Whether the `tls` tail is the burst of handshakes at the start of a run (issue 181) |
| `tls-new` | Like `tls`, with a new connection and TLS handshake for every request | Handshakes, the most expensive thing a proxy does. Latency here is k6's `iteration_duration`, because `http_req_duration` leaves out connecting and the handshake |
| `slow` | The backend answers after 100 ms ([traefik/whoami](https://github.com/traefik/whoami) `?wait=100ms`) | Holding many requests open at once. Subtract the 100 ms when reading latency |
| `routes` | 1,000 hosts, each with its own route, one chosen per request; [`gen-routes.py`](gen-routes.py) writes the configurations | Routing as a configuration grows. HAProxy uses plain ACLs in order, the way a hand-written configuration does; a map file would be faster |
| `large` | The backend answers with 100 KiB instead of 1 KiB (`RATES="1000 2500 5000 10000"`) | Copying bytes; at 10,000 req/s the proxy moves 1 GB/s |
| `huge` | 1 MiB answers (`RATES="100 250 500 1000"`) | The same at 1 GB/s with few requests; the bodies are random bytes made by `run.sh`, never committed |

For `lb`, each proxy uses its own round-robin: rdock `policy: round_robin`, NGINX's default weighted round-robin ([upstream module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html)), HAProxy `balance roundrobin` ([configuration manual](https://docs.haproxy.org/3.2/configuration.html#4.2-balance)), Caddy `lb_policy round_robin` ([reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#lb_policy)) and Traefik's default weighted round-robin ([services](https://doc.traefik.io/traefik/routing/services/)), all checked 2026-11-01. A check with 30 requests per proxy found each backend getting a third of them (NGINX 11/10/9, the others 10/10/10).

For the `tls` scenarios, k6 runs with `GODEBUG=http2client=0`, so every proxy is measured on HTTP/1.1; not all of them offer HTTP/2 by default.

## How load is generated

[k6](https://grafana.com/docs/k6/latest/) runs an **open model**: the `constant-arrival-rate` executor starts requests at a fixed rate whatever the latency ([k6 executors](https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/constant-arrival-rate/), checked 2026-10-29). A closed-loop tool waits for each answer before sending the next request, so a stalling proxy slows the load down and hides its own tail latency, which is called coordinated omission ([wrk2](https://github.com/giltene/wrk2), checked 2026-10-29). With an open model, a stall shows up in p99 and p99.9 as it would for real users.

Each proxy gets a 10-second warm-up at 2,000 req/s, then 30 seconds at each target rate. A rate the proxy cannot sustain shows as **achieved** below **target**, as **dropped** iterations (k6 ran out of virtual users waiting for answers), or as failures.

## Run it

```sh
docker build -t rdock:bench ..             # or RDOCK_IMAGE=ghcr.io/docker-hunterpedia/rdock:<version>
VERSION=0.4.0-alpha.1 ./run.sh             # all proxies at 5k, 10k, 20k, 40k req/s
PROXIES="rdock nginx" RATES="20000" DURATION=60s ./run.sh
SCENARIO=lb VERSION=0.4.0-alpha.1 ./run.sh # another scenario, see above
```

Results go to `results/<version>/<proxy>-<rate>.json` (`results/<version>/<scenario>/` for the other scenarios), and `report.md` in the same folder sums them up. Requirements: Docker with Compose and Python 3.

## Profiling

Release images strip symbols and have no frame pointers, so `perf` cannot show where the time goes. The `profiling` Cargo profile is the release build with line tables and symbols; built with frame pointers it gives call graphs at almost no cost ([rustc codegen options](https://doc.rust-lang.org/rustc/codegen-options/index.html), checked 2026-11-06). On the Linux benchmark host, with `perf` and `strace` installed:

```sh
docker build -t rdock:profiling --build-arg CARGO_PROFILE=profiling \
  --build-arg RUSTFLAGS="-C force-frame-pointers=yes" ..            # or: just docker-profiling
RDOCK_IMAGE=rdock:profiling PROXIES=rdock RATES=10000 DURATION=60s ./run.sh &
sleep 20                                                            # past the warm-up
pid=$(docker inspect -f '{{.State.Pid}}' rdock-bench-rdock-1)
perf record -F 999 --call-graph fp -p "$pid" -o rdock.perf -- sleep 30
perf report -i rdock.perf --no-children --sort symbol | head -60
perf stat -e task-clock,context-switches,cpu-migrations -p "$pid" -- sleep 30
timeout -s INT 30 strace -c -f -p "$pid" -o rdock.strace           # syscalls per request
```

Measure over the same 30 seconds as the `cpu.stat` ladder ([`cpu-ladder.sh`](cpu-ladder.sh); µs per request = `usage_usec` ÷ requests, which the hand-run ladders took as rate × 30) so the numbers line up, and divide context switches and syscalls by the requests completed in that window. `perf` resolves symbols through `/proc/<pid>/root`, so the distroless image needs nothing extra. The profiling image is for measurement only; its numbers include a small cost for frame pointers, so publish results from release images.

## Reading the results

- Numbers depend on the machine. Compare proxies within one run, never across runs on different hardware.
- On Docker Desktop (macOS, Windows) everything runs inside one Linux VM, so load generator, proxy and backend share its CPUs and network stack. Absolute numbers are lower than on bare-metal Linux; the comparison stays fair because all proxies share the same conditions.
- This is a proxying micro-benchmark: small responses, one route, no TLS. It measures the cost of the proxy itself, not of any feature.

## In CI

The [`bench`](../.github/workflows/bench.yml) workflow runs every night, on demand and on pull requests that change `benchmarks/`. It builds ReverseDock from the commit, runs it and NGINX in the same job at 5,000 and 10,000 req/s, reads each proxy's CPU time from its cgroup at every rate (`CPU_STAT=1`, [`cpu-stat.sh`](cpu-stat.sh)), and fails when [`compare.py`](compare.py) finds ReverseDock clearly behind NGINX: under 0.98× its throughput (not 1.0: the runner's achieved rate rounds below the target by different amounts for each proxy), a p99 above 2× NGINX's plus 5 ms, more than 1 % failed requests, or more than 1.6× NGINX's CPU time per request (the lab measured 1.36× in v0.5 and 1.43× in v0.6). Since [#93](https://github.com/Docker-Hunterpedia/ReverseDock/issues/93) ReverseDock completes as much as NGINX at these rates on 2 CPUs with a p99 within 1.4× of it, so the limits leave room for the runner's jitter only. The results are kept as a workflow artifact for 30 days and shown in the job summary.

GitHub's shared runners are virtual machines whose speed changes from run to run, so these numbers are a regression check only and are never published. Running both proxies in one job cancels most of that noise. Published reports below come from fixed hardware.

## Soak test

[`soak/`](soak/) runs ReverseDock for a long time under steady load and checks that it does not leak or slow down (H-ENG-02, H-ENG-03). By default it runs for 24 hours at 1,000 req/s, alternating plain HTTP and HTTPS. ReverseDock sits in front of three backends with active and passive health checks and retries, limited to 2 CPUs and 1 GiB. While the load runs:

- the configuration is rewritten and reloaded every 5 minutes;
- one backend is stopped every 15 minutes and started again a minute later;
- the certificate is replaced every 30 minutes.

A probe container shares ReverseDock's process namespace and records its memory, threads, file descriptors and TCP connections every 30 seconds. k6 records latency and failures in 10-minute windows.

[`analyze.py`](soak/analyze.py) treats the first tenth of the run as warm-up and fits a straight line through the rest. The run fails when:

- memory grows by more than 16 MiB, or 10 % of its warm size;
- file descriptors grow by more than 64;
- more than 0.1 % of requests fail or are dropped;
- a reload is rejected or missing, or the log shows a panic.

```sh
docker build -t rdock:bench ..
soak/run.sh                                                    # 24 h
DURATION=20m RELOAD_EVERY=60 FLAP_EVERY=180 CERT_EVERY=240 WINDOW=120 PROBE_EVERY=10 soak/run.sh   # a quick check
```

For a 24-hour run, copy `backend/` and `soak/` to a folder outside the checkout and start it there: bash reads `run.sh` while it runs, so switching branches in the checkout would break the run. Everything goes to `soak/work/`: `probe.csv`, the k6 windows, `events.csv`, ReverseDock's log and `report.md`. Requirements: Docker with Compose, Python 3 and `openssl`.

## Per-request cost without Docker

`rdock-perreq` measures one proxied HTTP/1.1 request on the machine it runs on, without Docker
and without k6, so a change to the request path can be checked in a development sandbox
(issue 181, ADR-0031). It starts a locally built `rdock` on a generated configuration, in front
of a backend inside the tool that answers every request with 1 KiB, and sends requests over
kept-alive connections.

Each measurement sends a warm-up (at least one request per route), then **N** and then **2N**
requests, and reports the second phase minus the first, divided by N, so start-up and anything
that does not grow with the request count cancel out.

| Reading | How | Exact? |
|---|---|---|
| Allocations | A binary built with the bench-only `alloc-count` cargo feature counts every allocation (the system allocator wrapped by `stats_alloc`) and answers on the Unix socket named by `RDOCK_ALLOC_COUNT_SOCKET`. The feature replaces mimalloc and does not compile with `--release`. | Yes |
| System calls | `strace -c -f` attached to the process for each phase. | The calls a request makes (`recvfrom`, `sendto`, `getpeername`, `writev`) are exact; `futex` and `epoll_wait` depend on timing and vary by a few tenths per request between runs. |
| CPU time | The sum of `/proc/<pid>/task/*/schedstat` (time on a CPU) over the process's threads, in a release build. | No: relative. Compare two builds on the same machine, interleaved, against an A/A noise floor. |

### Variants

`run.sh` measures five variants: 1, 1,000 and 10,000 routes (one host each, requests spread
over all of them), one route with 20 browser-like request headers instead of k6's three, and
HTTPS on a reused connection.

### Run it

```sh
# Counts (debug build: allocations and system calls do not depend on optimisation)
cargo build --locked -p rdock --features alloc-count && cp target/debug/rdock /tmp/rdock-alloc
cargo build --locked -p rdock-perreq
PERREQ=target/debug/rdock-perreq benchmarks/perreq/run.sh counts /tmp/rdock-alloc out/

# CPU time: two release builds, A (before) and B (after), interleaved
cargo build --locked --release -p rdock -p rdock-perreq
benchmarks/perreq/run.sh cpu /tmp/rdock-a /tmp/rdock-b out/ 5

# The TLS-tail experiment (issue 181 step 4), without and with a handshake bound
benchmarks/perreq/run.sh tail target/release/rdock out/
benchmarks/perreq/run.sh tail target/release/rdock out/ 32

python3 -I benchmarks/perreq/summarize.py counts out/          # or: counts before/ after/
python3 -I benchmarks/perreq/summarize.py cpu out/
python3 -I benchmarks/perreq/summarize.py tail out/
```

rdock runs on CPUs `0,1` and the tool on `2,3` (`RDOCK_CPUS`, `TOOL_CPUS`), as in the lab's 2-CPU
rung. Needs Linux, `strace` and `taskset`.

**CPU time.** Each round runs A, B, A for every variant. The spread of the A runs, (max − min)
÷ median, is the noise floor; `summarize.py` calls a B/A change a difference only when it is
larger than twice that, and "within noise" otherwise. Run it on an otherwise idle machine and
claim only relative numbers: no absolute microsecond figure from a sandbox stands for the lab.

**The tail experiment.** Eight established TLS connections send 2,000 requests a second on a
fixed schedule (latency counts from when a request was due). Three seconds in, a second process
on the other tool CPU opens 500 new TLS connections, all at once (as k6 does at the start of a
run) or spread over 2 s, and each sends one request and stays open. The output is the latency of
the established connections' requests during the burst and outside it, and the burst's own
handshake times.

Results: [results/2026-11-13-perreq/report.md](results/2026-11-13-perreq/report.md).

## Admin isolation test

[`isolation/`](isolation/) checks that the admin side cannot slow the proxy (H-ENG-04). Under a fixed 4,000 req/s on the proxy, each 60-second phase does one thing to the admin side:

- **login:** a flood of failed logins;
- **sse:** 10,000 log streams that never read;
- **apply:** configuration writes and rollbacks in a tight loop;
- **write-lock:** the configuration-write lock held, with writers waiting;
- **stall:** every admin thread blocked;
- **abort:** the admin runtime panics and stops.

A phase passes when the proxy's p99 stays within 25 % plus 2 ms of the baseline, failures do not rise and at most 0.1 % of requests are dropped. The stall, abort and write-lock faults come from the `fault-injection` Cargo feature, which release builds never have.

```sh
docker build -t rdock:fault --build-arg CARGO_FEATURES=fault-injection ..
isolation/run.sh
```

The first runs found that the admin side's own threads do not protect the proxy on their own: both share the container's CPU quota, and when the admin side uses too much of it the kernel pauses the whole process. One script making about 500 requests a second took the proxy's p99 from 0.65 to 92 ms. Limits on connections, on requests per caller and on configuration writes fixed it: [results](results/2026-11-01-isolation/report.md).

## Results

| Version | Machine | Report |
|---|---|---|
| 0.4.0-alpha.1 | Apple M5 Pro (15 cores), 24 GiB, Docker Desktop | [results/0.4.0-alpha.1/report.md](results/0.4.0-alpha.1/report.md) |
| main, 2026-10-30 (upstream pool, #86) | same | [results/2026-10-30-upstream-pool/report.md](results/2026-10-30-upstream-pool/report.md) |
| main at 36f64a9, 2026-11-02 (small CPUs, #93): all scenarios, all proxies, before and after, large bodies | Hetzner dedicated server, 8 vCPUs, 32 GiB, Ubuntu 26.04 | [results/2026-11-02-small-cpu/report.md](results/2026-11-02-small-cpu/report.md) |
| main at 36f64a9, 2026-11-02 to 11-03: 24-hour soak (v0.5 release candidate) | same | [results/2026-11-02-small-cpu/soak/report.md](results/2026-11-02-small-cpu/soak/report.md) |
| main at c71a538, 2026-11-07 (v0.6): six scenarios against NGINX and HAProxy, CPU ladder, 2-hour soak, 3-node Swarm | same | [results/2026-11-07-v06/report.md](results/2026-11-07-v06/report.md) |
| main at 5c7d7f8 (0.8.0-alpha.1) and the v0.9 per-request changes, 2026-11-13: allocations, system calls and CPU per request, TLS tail during a handshake burst (`perreq`, no Docker; CPU relative only) | Development sandbox, 4 shared vCPUs | [results/2026-11-13-perreq/report.md](results/2026-11-13-perreq/report.md) |
