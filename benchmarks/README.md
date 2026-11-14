# Benchmarks

Reproducible comparisons of ReverseDock with NGINX, HAProxy, Caddy and Traefik (H-ENG-01). Every proxy runs the same job with the same limits, and anyone with Docker can run it again.

## What is measured

One route forwards every request to one backend, an NGINX serving a fixed 1 KiB page. Each proxy:

- listens on plain HTTP on `:8080` and keeps connections to the backend alive;
- has access logging off, and no other feature turned on;
- runs in its own container limited to **2 CPUs and 1 GiB**; the backend gets 4 CPUs, k6 4 CPUs.

Configurations: [`configs/`](configs/), with a tuned variant of each in [`configs/tuned/`](configs/tuned/) ([below](#default-and-tuned-configurations)). Every TLS scenario follows the [TLS parity](#tls-parity) rules.

### Versions

Every image is pinned by tag **and** digest in [`compose.yaml`](compose.yaml): the newest stable release of each on 2026-11-14, with the multi-platform index digest read that day from the registry (`Docker-Content-Digest` of `HEAD /v2/<repo>/manifests/<tag>` on `registry-1.docker.io`, the same value Docker Hub's tag API lists). `run.sh` writes the digests Docker actually resolved to `images.txt` next to each result, and the `bench-report` workflow prints them in its summary.

| Image | Version | Source of the version (read 2026-11-14) |
|---|---|---|
| `nginx` (proxy and backend) | 1.30.6-alpine | Stable branch on [nginx.org](https://nginx.org/en/download.html); mainline is 1.31.8 |
| `haproxy` | 3.4.7-alpine | LTS, released 2026-10-14, [haproxy.org](https://www.haproxy.org/) |
| `traefik` | v3.7.19 | Newest v3.7 tag on [Docker Hub](https://hub.docker.com/_/traefik); v3.8.0 is a release candidate |
| `caddy` | 2.11.9-alpine | Newest 2.11 tag on [Docker Hub](https://hub.docker.com/_/caddy) |
| `grafana/k6` | 1.8.3 | Newest v1 tag on [Docker Hub](https://hub.docker.com/r/grafana/k6); 2.4.0 is a new major, not adopted until `load.js` is checked against it |
| `traefik/whoami` (`slow`) | v1.11.0 | Unchanged; v1.12.0 exists |

GitHub's release pages could not be read from the machine that made this change, so Traefik's and Caddy's versions come from the official images' tags, not from their release notes. The previous pins (NGINX 1.29.3, HAProxy 3.2.8, Traefik 3.5.4, Caddy 2.10.2, k6 1.3.0) are what every report before 2026-11-14 used.

### Scenarios

`SCENARIO=<name> ./run.sh` measures something other than the bare proxy. Results go to `results/<version>/<name>/`.

| Scenario | What changes | What it shows |
|---|---|---|
| `single` (default) | One route, one backend, plain HTTP | The cost of the proxy itself |
| `lb` | Three backends, round-robin; they share the same 4 CPUs (1.33 each) | The load balancer |
| `tls` | HTTPS with kept-alive connections, HTTP/1.1, TLS 1.3 ([TLS parity](#tls-parity)) | Encryption per request |
| `h2` | Like `tls`, on HTTP/2 negotiated by ALPN. k6 sends one request at a time on each connection, so this is HTTP/2 framing, HPACK and TLS on many connections, not many streams on few connections | The HTTP/2 path |
| `tls-ramped` | Like `tls`, with the rate reached over 2 s (`RAMP`) instead of at once, so k6 opens its connections gradually | Whether the `tls` tail is the burst of handshakes at the start of a run (issue 181) |
| `tls-new` | Like `tls`, with a new connection and TLS handshake for every request | Handshakes, the most expensive thing a proxy does. Latency here is k6's `iteration_duration`, because `http_req_duration` leaves out connecting and the handshake |
| `slow` | The backend answers after 100 ms ([traefik/whoami](https://github.com/traefik/whoami) `?wait=100ms`) | Holding many requests open at once. Subtract the 100 ms when reading latency |
| `routes` | 1,000 hosts, each with its own route, one chosen per request; [`gen-routes.py`](gen-routes.py) writes the configurations | Routing as a configuration grows. HAProxy uses plain ACLs in order, the way a hand-written configuration does; a map file would be faster |
| `large` | The backend answers with 100 KiB instead of 1 KiB (`RATES="1000 2500 5000 10000"`) | Copying bytes; at 10,000 req/s the proxy moves 1 GB/s |
| `huge` | 1 MiB answers (`RATES="100 250 500 1000"`) | The same at 1 GB/s with few requests; the bodies are random bytes made by `run.sh`, never committed |

For `lb`, each proxy uses its own round-robin: rdock `policy: round_robin`, NGINX's default weighted round-robin ([upstream module](https://nginx.org/en/docs/http/ngx_http_upstream_module.html)), HAProxy `balance roundrobin` ([configuration manual](https://docs.haproxy.org/3.2/configuration.html#4.2-balance)), Caddy `lb_policy round_robin` ([reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#lb_policy)) and Traefik's default weighted round-robin ([services](https://doc.traefik.io/traefik/routing/services/)), all checked 2026-11-01. A check with 30 requests per proxy found each backend getting a third of them (NGINX 11/10/9, the others 10/10/10).

In the `tls`, `tls-ramped` and `tls-new` scenarios k6 runs with `GODEBUG=http2client=0`, so every proxy is measured on HTTP/1.1; `h2` is the same configuration on HTTP/2.

The proxy `direct` (`PROXIES="direct rdock …"`) sends k6 straight to the backend, in the plain HTTP scenarios with one backend: the ceiling the generator and the backend reach on that machine without any proxy. A proxy row close to `direct` is limited by the machine, not by the proxy.

### TLS parity

Every proxy terminates TLS with the same parameters, or the comparison measures settings instead of proxies. The rules, as configured in `configs/tls/` and `configs/tuned/tls/`:

| What | Rule | How each proxy gets there |
|---|---|---|
| Certificate | One file for all: a self-signed ECDSA P-256 leaf made by `run.sh` | Mounted at `/certs` |
| Protocol | TLS 1.3 only | rdock `tls: { policy: modern }`; NGINX `ssl_protocols TLSv1.3`; HAProxy `ssl-min-ver TLSv1.3`; Caddy `protocols tls1.3`; Traefik `minVersion: VersionTLS13` |
| Cipher suite | `TLS_AES_128_GCM_SHA256` | NGINX `ssl_conf_command Ciphersuites`; HAProxy `ciphersuites` (it enforces the server's order by default); rdock, Caddy and Traefik cannot set TLS 1.3 suites and follow k6's order, AES-128-GCM first |
| Key exchange | X25519 | k6 offers no post-quantum hybrid (`GODEBUG=tlsmlkem=0,tlssecpmlkem=0`); NGINX `ssl_ecdh_curve X25519`, HAProxy `curves X25519`, Caddy `curves x25519`, Traefik `curvePreferences: [X25519]`; rdock's ring provider has X25519 first |
| ALPN | `h2` and `http/1.1` offered; k6 picks per scenario | NGINX `http2 on`; the others offer both by default |
| HTTP/2 streams | 100 per connection | NGINX `http2_max_concurrent_streams 100`, Traefik `maxConcurrentStreams: 100`; rdock and HAProxy default to 100; Caddy has no setting (Go's default) |
| Resumption | Each proxy's default (tickets on); k6 does not resume | Nothing set |
| To the backend | Plain HTTP/1.1, kept alive | As in the plain scenarios |

**Checked on every run.** In the TLS scenarios `load.js` reads the HTTP version, TLS version and cipher suite of each virtual user's first response and of every 50th after it, and `report.py` shows a **Negotiated** column: `ok`, or `parity mismatch` with what differed, which makes `run.sh` exit 3. k6 does not report the key exchange group, so that rule rests on the configuration of both ends. For rdock it was checked by hand on 2026-11-14 with Go 1.24.7's client (the library k6 uses): TLS 1.3, `TLS_AES_128_GCM_SHA256`, X25519, and `h2` or `http/1.1` as asked.

**What stays different.** The TLS library: rustls with ring (rdock), OpenSSL as built into the Alpine images (NGINX, HAProxy), Go's `crypto/tls` (Caddy, Traefik). That cannot be equalised and is part of what is measured.

Sources, read 2026-11-14: NGINX [ssl module](https://nginx.org/en/docs/http/ngx_http_ssl_module.html) and [HTTP/2 module](https://nginx.org/en/docs/http/ngx_http_v2_module.html); HAProxy [configuration manual 3.4](https://docs.haproxy.org/3.4/configuration.html) (`alpn` default "h2,http/1.1", `ciphersuites`, `curves`, `ssl-min-ver`, `prefer-client-ciphers`, `tune.h2.fe.max-concurrent-streams`); Caddy [`tls` directive](https://caddyserver.com/docs/caddyfile/directives/tls) ("cipher suites are not customizable for TLS 1.3"); Traefik [TLS options](https://doc.traefik.io/traefik/reference/routing-configuration/http/tls/tls-options/) ("With TLS 1.3, the cipher suites are not configurable") and [entry points](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/) (`http2.maxConcurrentStreams`, default 250); Go [GODEBUG settings](https://go.dev/doc/godebug) (`tlsmlkem`, Go 1.24; `tlssecpmlkem`, Go 1.26); k6 [SSL/TLS version and ciphers](https://grafana.com/docs/k6/latest/using-k6/protocols/ssl-tls/ssl-tls-version-and-ciphers/) and [Response](https://grafana.com/docs/k6/latest/javascript-api/k6-http/response/) (`proto`, `tls_version`, `tls_cipher_suite`).

### Default and tuned configurations

`CONFIG=default` (the default) runs the files in `configs/`: the shortest configuration that does the job, with access logging off, keep-alive to the backend and the worker count equal to the proxy's 2 CPUs. `CONFIG=tuned` runs `configs/tuned/` (scenarios `single`, `slow`, `large`, `huge`) and `configs/tuned/tls/` (`tls`, `tls-ramped`, `tls-new`, `h2`): the default plus what each project's own documentation recommends for throughput. Results go to `<scenario>-tuned/`. Each tuned setting and its source, read 2026-11-14:

| Proxy | Tuned setting | Source |
|---|---|---|
| rdock | `runtime.worker_threads: 2` (stated instead of derived from the CPUs); nothing else, because the guide says to leave socket options unset unless a measurement points at one | [Sockets and threads](../apps/website/src/content/docs/docs/guides/sockets-and-threads.mdx) |
| NGINX | `worker_cpu_affinity auto` | [core module](https://nginx.org/en/docs/ngx_core_module.html#worker_cpu_affinity) |
| NGINX | `listen … reuseport` | [`listen`](https://nginx.org/en/docs/http/ngx_http_core_module.html#listen); F5 blog "Socket Sharding in NGINX Release 1.9.1" (2015-05-26) |
| NGINX | `keepalive_requests 100000` (client and upstream; default 1000) | F5 blog "Tuning NGINX for Performance" (2014-10-10): "especially useful for testing with a load-generation tool" |
| NGINX (TLS) | `ssl_session_cache shared:SSL:10m` | ["HTTPS server optimization"](https://nginx.org/en/docs/http/configuring_https_servers.html); k6 does not resume sessions, so it changes nothing measured here |
| HAProxy | none: the tuned file is the default file | The manual documents the relevant defaults as the recommended values: `nbthread` follows the CPUs the process is bound to, `cpu-policy performance` is the default, and for `tune.h2.fe.max-concurrent-streams` "it is recommended not to change this value" ([manual 3.4](https://docs.haproxy.org/3.4/configuration.html)) |
| Caddy | `keepalive_idle_conns_per_host 256` (default 32) | [`reverse_proxy`](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) |
| Traefik | none: the tuned files are the default files | No throughput setting is documented; `serversTransport.maxIdleConnsPerHost` already defaults to 200 ([configuration options](https://doc.traefik.io/traefik/reference/install-configuration/configuration-options/)) |

The tuned files are a starting point for review: the plan (ADR-0033 research, Q7) is to ask each project's maintainers to review theirs before numbers are published, and to record whether they answered. That has not been done.

## How load is generated

[k6](https://grafana.com/docs/k6/latest/) runs an **open model**: the `constant-arrival-rate` executor starts requests at a fixed rate whatever the latency ([k6 executors](https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/constant-arrival-rate/), checked 2026-10-29). A closed-loop tool waits for each answer before sending the next request, so a stalling proxy slows the load down and hides its own tail latency, which is called coordinated omission ([wrk2](https://github.com/giltene/wrk2), checked 2026-10-29). With an open model, a stall shows up in p99 and p99.9 as it would for real users.

Each proxy gets a 10-second warm-up at 2,000 req/s, then 30 seconds at each target rate. A rate the proxy cannot sustain shows as **achieved** below **target**, as **dropped** iterations (k6 ran out of virtual users waiting for answers), or as failures.

## Run it

```sh
docker build -t rdock:bench ..             # or RDOCK_IMAGE=ghcr.io/docker-hunterpedia/rdock:<version>
VERSION=0.4.0-alpha.1 ./run.sh             # all proxies at 5k, 10k, 20k, 40k req/s
PROXIES="rdock nginx" RATES="20000" DURATION=60s ./run.sh
SCENARIO=lb VERSION=0.4.0-alpha.1 ./run.sh # another scenario, see above
SCENARIO=h2 CONFIG=tuned ./run.sh          # HTTP/2 with the tuned configurations
PIN=1 PROXIES="direct rdock nginx" ./run.sh   # cores pinned, with the no-proxy ceiling
python3 -I test_reports.py                 # tests of report.py and hosted_report.py
```

Results go to `results/<version>/<proxy>-<rate>.json` (`results/<version>/<scenario>/` for the other scenarios, `<scenario>-tuned/` with `CONFIG=tuned`), and `report.md` in the same folder sums them up, next to `machine.txt` (CPU, kernel, pinning) and `images.txt` (the digests that ran). Requirements: Docker with Compose and Python 3.

`PIN=1` adds [`compose.pinned.yaml`](compose.pinned.yaml): the proxy on CPUs 0–1 (`PROXY_CPUSET`), the backend and k6 on 2–3 (`LOAD_CPUSET`), so they never share a core with the proxy. It needs 4 CPUs unless both sets are given. Pinning is used instead of relying on the CPU quota alone, because a quota lets a process run on every core and then pauses all of it, which distorts tail latency ([isolation results](results/2026-11-01-isolation/report.md)).

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

The [`bench`](../.github/workflows/bench.yml) workflow runs every night, on demand and on pull requests that change `benchmarks/`. It builds ReverseDock from the commit, runs it and NGINX in the same job at 5,000 and 10,000 req/s, reads each proxy's CPU time from its cgroup at every rate (`CPU_STAT=1`, [`cpu-stat.sh`](cpu-stat.sh)), and fails when [`compare.py`](compare.py) finds ReverseDock clearly behind NGINX: under 0.98× its throughput (not 1.0: the runner's achieved rate rounds below the target by different amounts for each proxy), a p99 above 2× NGINX's plus 5 ms, more than 1 % failed requests, or more than 2.4× NGINX's CPU time per request (the lab measured 1.36× in v0.5 and 1.43× in v0.6; hosted runners read 1.32× to 2.18× for the same code on 2026-11-13, depending on the machine drawn, so the limit there only catches a large regression). Since [#93](https://github.com/Docker-Hunterpedia/ReverseDock/issues/93) ReverseDock completes as much as NGINX at these rates on 2 CPUs with a p99 within 1.4× of it, so the limits leave room for the runner's jitter only. The results are kept as a workflow artifact for 30 days and shown in the job summary.

GitHub's shared runners are virtual machines whose speed changes from run to run, so these numbers are a regression check only and are never published. Running both proxies in one job cancels most of that noise. Published reports below come from fixed hardware.

The images were updated on 2026-11-14 (NGINX 1.29.3 → 1.30.6 among them), so the nightly ratios are against a newer NGINX from that day on; the gates in `compare.py` are unchanged. The nightly job runs only the plain `single` scenario and does not use pinning.

## On a hosted runner: all five proxies

The [`bench-report`](../.github/workflows/bench-report.yml) workflow (weekly and by hand, not a required check) runs ReverseDock, NGINX, HAProxy, Caddy, Traefik and `direct` in one job on one free GitHub-hosted runner: the scenarios `single`, `tls`, `tls-new` and `h2` (inputs choose others), each with the default and the tuned configurations, `PIN=1`, 2,500, 5,000 and 10,000 req/s (500, 1,000 and 2,000 for `tls-new`), 30 s each, CPU per request from each proxy's cgroup. It fails when a proxy breaks TLS parity. [`hosted_report.py`](hosted_report.py) joins the results into `hosted-report.md`, shown in the job summary and kept as an artifact for 90 days.

**What that report can claim, and its limit.** GitHub's standard Linux runner for public repositories is one virtual machine with 4 vCPUs and 16 GB ([GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), read 2026-11-14), shared with other tenants. The proxy gets 2 pinned vCPUs; the backend and k6 share the other 2, so at the higher rates the generator can be the limit (compare with `direct`, read dropped iterations). Whether the vCPUs are SMT siblings and which CPU model is drawn change from run to run (`machine.txt`). One repetition per cell. The numbers compare the five proxies **within one run** under identical conditions; they are not absolute numbers and must not be compared with another run or with the dedicated-lab reports. `hosted_report.py` puts these limits at the top of every report it writes, so they travel with the numbers.

**What a dedicated three-machine run would add (open).** Load generator, proxy and backend on three dedicated machines on a private network of 10 Gbit/s or more, the way HAProxy's own report does ([HAProxy blog, 2021-04-08](https://www.haproxy.com/blog/haproxy-forwards-over-2-million-http-requests-per-second-on-a-single-aws-arm-instance)): no shared kernel or network stack, the generator-to-backend ceiling measured first, the proxy pinned to 2, 4 and 8 cores, host tuning applied and recorded, 5 repetitions per cell with the proxies interleaved, latency at fixed rates and at 50 % of each proxy's own peak, an HTTP/2 multiplexing scenario with a closed-loop tool such as h2load, and absolute numbers that can be quoted. That run needs rented hardware ([research note](../docs/research/v1.0-stable.md), Part C §2.5 and question Q5) and has not been done.

The workflow has not run yet: no hosted-runner results exist at the time of writing.

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

## Hosted soak

[`soak/hosted/`](soak/hosted/) is the soak that runs on a free GitHub-hosted runner, without Docker (H-ENG-02, H-ENG-03, ADR-0031 step 9). The weekly [`soak`](../.github/workflows/soak.yml) workflow runs it for 5 h 20 min; it can also be run by hand on any Linux machine.

**What it stands in for, and what it does not show.** The roadmap's v0.9 criterion is a 24-hour soak at target RPS on a dedicated machine. Nobody has rented one, so that criterion is **open**. This job is a stand-in with a different, weaker claim: *in about five and a half hours on a shared 2- to 4-vCPU virtual machine, with 400 req/s, reloads and binary upgrades, rdock's memory, descriptors and threads showed no sustained rise, no request failed outside a tiny budget, and every upgrade kept its promises about held connections.* It does not show that nothing grows over 24 hours (see "What a 5-hour window can see" below), it says nothing about throughput or latency on real hardware (a hosted runner's speed changes from run to run), and it does not run at the rate or with the traffic of any production site. It has not run on a hosted runner yet at the time of writing: the weekly schedule starts after this is merged.

### What runs

`run.sh` starts, on loopback, two backends (`backend.py`, one asyncio process), one `rdock` copied from the release binary under test, and the load generator (`load.py`). Everything is Python 3 standard library and `openssl` (for a throw-away certificate); no new tool is pinned.

- **rdock** ([`rdock.yaml`](soak/hosted/rdock.yaml)): an HTTP and an HTTPS listener; three routes (`/`, `/cached/` with the memory cache, `/stream/` for a WebSocket and an event stream), two backends behind `least_requests` with active and passive health checks and retries; a `rate_limit` keyed by a request header with 5,000 distinct values (far above the load, so nothing is refused, but every request goes through a bucket); a `headers` middleware that stamps the configuration generation; the JSON access log for every request (to `/dev/null`: five hours at 400 req/s are a few GB, and the formatting and the write still happen, but a slow log consumer is not tested); the admin API.
- **Load**: open model, 400 req/s (`RATE`), one request due every 2.5 ms whatever the latency, latency counted from the due time. 35 % plain HTTP `/`, 30 % HTTPS `/`, 20 % and 10 % the cached route over HTTP and HTTPS, 5 % HTTPS with `Connection: close` (a new handshake each). Kept-alive connections are reused. A request fails when there is no answer, no 200, a wrong body, or no answer within 10 s. An idle kept-alive connection that the server had already closed (it answers nothing at all) is retried once on a new connection, as HTTP clients do for an idempotent GET ([RFC 9110 §9.2.2](https://www.rfc-editor.org/rfc/rfc9110#section-9.2.2)), and **counted** (`stale` in `load.csv`, shown in the report) instead of hidden.
- **Held connections**: a WebSocket (over HTTPS) and a server-sent event stream (over HTTP) are kept open all the time and reopened when they close.
- **Reload** every 5 minutes (`RELOAD_EVERY`): the configuration is rewritten with a new generation, reloaded over the admin socket, and the new generation must answer within 15 s.
- **Binary upgrade** every 30 minutes (`UPGRADE_EVERY`) during the first half of the run (`UPGRADE_UNTIL`, 0.5): `POST /api/v1/upgrade` over the admin socket, the same file to itself, `upgrade.drain` 30 s. The driver follows the handover (the new pid comes from `/api/v1/status`), so sampling continues on it, and checks what the [upgrade guide](../apps/website/src/content/docs/docs/guides/upgrades.mdx) promises: the WebSocket and the event stream opened before the upgrade still deliver while the old process drains; they are closed when the drain ends (between `drain − 6 s` and `drain + 15 s` after the swap); the old process then exits; new held connections open and the new pid answers. The second half of the run has no upgrades, so one process runs alone for the memory judgment below. The ADR's "an upgrade every 30 minutes" is kept for the first half; the second half deliberately trades upgrades for sensitivity (every upgrade starts a fresh process, which resets a slow leak to zero).
- **Samples** every 30 s (`SAMPLE_EVERY`) into `samples.csv`: RSS and PSS (`/proc/<pid>/smaps_rollup`; PSS is the memory rdock alone is charged for), open file descriptors, threads, the size of the data directory, and from rdock's own `/metrics` over the admin socket the counters of requests, 5xx answers, upstream errors and connections, the open connections and the cache's objects and bytes.

Outputs in the work folder (`OUT`, `soak/hosted/work/` by default, ignored by git): `samples.csv`, `load.csv` (one row per 10 s), `failures.csv`, `events.csv` (every reload, upgrade and check), `meta.json`, `rdock.log`, `report.md`, `analysis.json`. The workflow uploads them (not the copy of the binary, the data directory or the throw-away TLS key) as an artifact for 90 days and shows the report in the job summary.

### What fails the run

`analyze.py` exits 1 when any of these fails (3 when a trend had too little data, which a full run never has):

| Check | Rule |
|---|---|
| Run completed | At least 98 % of the time, rdock never down, at least 85 % of the samples |
| Failed requests | At most 0.001 % (⌊10⁻⁵ × requests⌋), counted **separately** for requests inside an upgrade window (2 s before the call to 10 s after it) or a reload window (2 s before to 5 s after) and for all others. A full run sends about 7.7 million requests (400 × 19,200 s); the windows cover roughly 3 % of them (63 reloads and 5 upgrades), so the rule allows about 75 failures outside the windows and about 2 inside (arithmetic from the schedule, not a measurement). The upgrade guide promises that no connection attempt is refused or reset, so any failure inside an upgrade window is a finding to read, not noise; the allowance is for a shared machine's stalls |
| Upgrades | Every one answers 200 with a new pid that then serves; at least `MIN_UPGRADES` |
| Held connections | Every check of "Held connections" above passes |
| Reloads | Every one answers 200 and the new generation answers |
| Log | No `panicked`, no `configuration rejected` |
| Memory (PSS), descriptors, threads | The trend rules below |
| Latency | The median window p99 of the last quarter is at most 3 × the first quarter's plus 5 ms |

### The memory rule

An upgrade starts a new process with nothing in it, so growth is judged **per process**, never across the run. For each process:

1. discard its first 600 s (the cache fills, pools and the allocator settle);
2. judge it only when at least 900 s and 20 samples remain (a 30-minute process leaves 20 minutes);
3. take **level** = the median of the first quarter of what remains, **slope** = the Theil–Sen estimate (the median of the slopes between all pairs of points), and **delta** = the median of the last quarter minus the median of the second;
4. flag **memory** when both hold: the slope projected over 24 h exceeds **10 % of the level**, and delta exceeds **max(1 MiB, 1 % of the level)**. Descriptors are flagged when slope × window and delta both exceed max(16, 5 % of the level), threads when both exceed max(4, 10 % of the level).

The run **fails** when the longest judged process is flagged (the run ends with one long process, about 2 h 50 min in the default run), or when at least three processes were judged and more than half are flagged (a leak in every generation, however short).

*Why this shape.* The projection alone would turn a few hundred KiB of noise over a 15-minute window into tens of MiB a day (a 5-hour run extrapolated to 24 h multiplies noise by five or more); delta alone would flag a step that already settled. Together they ask for growth that continues and is larger than noise. The Theil–Sen slope is used instead of least squares because spikes (a transient burst of memory the allocator keeps for a while) move a least-squares line and barely move this one; a step early or late in the window also moves it little. The unit tests in [`test_analyze.py`](soak/hosted/test_analyze.py) pin the behaviour on synthetic series: flat, noisy flat (with spikes), a cache-fill step early and later, a slow leak, a sawtooth, descriptor and thread growth, restarts with warm-up, a leak in every short process, and the failure budget. They run in the workflow before the soak (and on pull requests that touch the soak), and `run.sh` runs them first.

*What a 5-hour window can see.* On the shape of the default run, the tests show that a leak of 0.5 MiB an hour on a 100 MiB process (12 % a day) **passes** and 1 MiB an hour (24 % a day) **fails**. 1 MiB an hour at 400 req/s is about 0.7 bytes per request, or 85 KiB per reload, so a per-request or per-reload leak of any size is visible. A leak that is slower, or one that only shows after many hours (a table that fills over a day, a certificate store, a log of events), is not, and a **24-hour soak is still needed for those** (open). A step in the middle of the run (a one-off rise of 20 % half way) is indistinguishable from growth by these statistics and is flagged.

*False alarms to expect.* Allocators keep freed memory (per-thread caches, arenas, pages returned lazily) and return it on their own schedule, so after a change in traffic PSS can step up, creep for a while and fall back later; a creep that has not finished 10 minutes after the start can pass the rule on a short window and be a false alarm. The cache (400 objects of 2 KiB with a 30 s lifetime) and the rate limit's bucket table (5,000 keys) churn constantly, which fragments memory slowly; a very slow creep that stops is the typical case. Hosted runners are shared virtual machines: a noisy neighbour changes timing (latency, the stale-connection count, an occasional failure) but not rdock's PSS, descriptors or threads, so the trend checks are less affected than the request checks. When the job fails on a trend, read the `Over time` table and the per-process table of `report.md` before concluding that it is a leak; if one is real, it repeats the next week.

### Run it

```sh
cargo build --locked --release -p rdock
benchmarks/soak/hosted/run.sh                       # 5 h 20 min, like the weekly job
# A smoke run (what the 2026-11-13 results are), with a short warm-up so the trend checks have data:
DURATION=10m RATE=400 SAMPLE_EVERY=10 RELOAD_EVERY=90 UPGRADE_EVERY=150 UPGRADE_UNTIL=0.7 MIN_UPGRADES=2 MIN_RELOADS=2 \
  ANALYZE_ARGS="--warmup 60 --min-tail 120 --allow-inconclusive" benchmarks/soak/hosted/run.sh
python3 -I benchmarks/soak/hosted/test_analyze.py   # the analysis rules, against synthetic runs
```

`run.sh` documents its settings (`RDOCK`, `OUT`, `DURATION`, `RATE`, `SAMPLE_EVERY`, `RELOAD_EVERY`, `UPGRADE_EVERY`, `UPGRADE_UNTIL`, `DRAIN`, `LABEL`, `MIN_UPGRADES`, `MIN_RELOADS`, `ANALYZE_ARGS`). Needs Linux, Python 3 and `openssl`. The soak runs a copy of the binary, so rebuilding `target/release/rdock` meanwhile is harmless.

Results of the smoke run: [results/2026-11-13-soak-smoke/](results/2026-11-13-soak-smoke/report.md). **It is a smoke run on a shared 4-vCPU development sandbox: it proves that the driver, the pid-following and the analysis work end to end. It is not a result.**

## CPU scaling

How throughput and CPU per request change with the CPUs given to rdock (H-PERF-01, ADR-0031 step 9). `perreq/run.sh scaling` runs one `rdock` pinned (`taskset`) to the first 1, 2 and 4 CPUs with `runtime.worker_threads` set to the same number, and `rdock-perreq scale` drives it by **closed-loop saturation** (64 kept-alive connections, each sending the next request as soon as the last answer is in) for 20 s after a 5 s warm-up, three rounds with the sizes in alternating order. The backend (1 KiB answers) and the generator are one process on the other CPUs.

It reports, per size: requests per second and CPU time per request (`/proc/<pid>/task/*/schedstat` over the measured phase) as a median and a range over the rounds; how busy rdock's CPUs were and how busy the tool's (the tool is the client and the backend together); the ratio to one CPU and the efficiency (ratio ÷ CPUs); and a **Reading** column that says when a figure cannot be taken at face value:

- **At 4 CPUs on a 4-vCPU machine nothing is left for the generator**, so it shares the cores with the proxy: that row is a **lower bound**, not a clean measurement, and says so. The same holds for any size equal to the machine's CPU count. The 1- and 2-CPU rows leave 3 and 2 CPUs to the tool.
- A row where rdock's CPUs were not (nearly) all busy says rdock was not the limit.
- A row where the tool used 90 % or more of its CPUs says the tool may have been the limit.

This measures peak throughput, not latency (a closed loop hides a stalling proxy's tail; the k6 scenarios and the soak measure latency). It is plain HTTP/1.1 with one route and no features, so it is the scaling of the proxy's core path only. **8 CPUs are not measured** (no free hosted runner has them), and **no dedicated-hardware number exists yet**: the 4- and 8-CPU measurements of the roadmap stay open.

```sh
cargo build --locked --release -p rdock -p rdock-perreq
benchmarks/perreq/run.sh scaling target/release/rdock out/ 3        # SIZES="1 2 4" SCALE_SECONDS=20 SCALE_WARMUP=5 SCALE_CONNS=64
python3 -I benchmarks/perreq/summarize.py scaling out/
```

The [`scaling`](../.github/workflows/scaling.yml) workflow does this on a hosted runner, by hand only (`workflow_dispatch`), uploads `scaling.jsonl` and `machine.txt` and shows the table in the job summary; it gates nothing. Hosted runners are noisy: read the ranges, and do not compare a hosted-runner run with the lab's. Results of the smoke run: [results/2026-11-13-scaling-smoke/](results/2026-11-13-scaling-smoke/report.md), on the same shared sandbox as the soak smoke: **not a result**.

## Allocator comparison

mimalloc is the allocator of every release build. For H-PERF-06 the binary has a cargo feature `jemalloc` (`tikv-jemallocator`, off by default, never in a release build or image; it builds jemalloc from C source and needs `make`): `cargo build --locked --release -p rdock --features jemalloc` replaces mimalloc. Pass `LABEL=jemalloc` to the soak so the report says which allocator ran, and run `scaling` or the soak with that binary and with the default one, on the same machine, one after the other. jemalloc's runtime options go in `_RJEM_MALLOC_CONF` (this crate prefixes them), for example `background_thread:true`. The comparison matrix itself, and the sizing page that would come from it, are **not done**: they need measurements on hardware that is not a shared runner.

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
