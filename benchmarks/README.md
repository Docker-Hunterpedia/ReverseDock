# Benchmarks

Reproducible comparisons of ReverseDock with NGINX, HAProxy, Caddy and Traefik (H-ENG-01). Every proxy runs the same job with the same limits, and anyone with Docker can run it again.

## What is measured

One route forwards every request to one backend, an NGINX serving a fixed 1 KiB page. Each proxy:

- listens on plain HTTP on `:8080` and keeps connections to the backend alive;
- has access logging off, and no other feature turned on;
- runs in its own container limited to **2 CPUs and 1 GiB**; the backend gets 4 CPUs, k6 4 CPUs.

Configurations: [`configs/`](configs/). Versions are pinned in [`compose.yaml`](compose.yaml).

## How load is generated

[k6](https://grafana.com/docs/k6/latest/) runs an **open model**: the `constant-arrival-rate` executor starts requests at a fixed rate whatever the latency ([k6 executors](https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/constant-arrival-rate/), checked 2026-10-29). A closed-loop tool waits for each answer before sending the next request, so a stalling proxy slows the load down and hides its own tail latency, which is called coordinated omission ([wrk2](https://github.com/giltene/wrk2), checked 2026-10-29). With an open model, a stall shows up in p99 and p99.9 as it would for real users.

Each proxy gets a 10-second warm-up at 2,000 req/s, then 30 seconds at each target rate. A rate the proxy cannot sustain shows as **achieved** below **target**, as **dropped** iterations (k6 ran out of virtual users waiting for answers), or as failures.

## Run it

```sh
docker build -t rdock:bench ..             # or RDOCK_IMAGE=ghcr.io/docker-hunterpedia/rdock:<version>
VERSION=0.4.0-alpha.1 ./run.sh             # all proxies at 5k, 10k, 20k, 40k req/s
PROXIES="rdock nginx" RATES="20000" DURATION=60s ./run.sh
```

Results go to `results/<version>/<proxy>-<rate>.json`, and `results/<version>/report.md` sums them up. Requirements: Docker with Compose and Python 3.

## Reading the results

- Numbers depend on the machine. Compare proxies within one run, never across runs on different hardware.
- On Docker Desktop (macOS, Windows) everything runs inside one Linux VM, so load generator, proxy and backend share its CPUs and network stack. Absolute numbers are lower than on bare-metal Linux; the comparison stays fair because all proxies share the same conditions.
- This is a proxying micro-benchmark: small responses, one route, no TLS. It measures the cost of the proxy itself, not of any feature.

## In CI

The [`bench`](../.github/workflows/bench.yml) workflow runs every night, on demand and on pull requests that change `benchmarks/`. It builds ReverseDock from the commit, runs it and NGINX in the same job at 2,500 and 5,000 req/s, and fails when [`compare.py`](compare.py) finds ReverseDock clearly behind NGINX: under 0.95× its throughput, a p99 above 4× NGINX's plus 25 ms, or more than 1 % failed requests. The rates stay below what ReverseDock sustains on a 4-CPU runner today (about 6,300 req/s, against NGINX's 10,000; see [#91](https://github.com/Docker-Hunterpedia/ReverseDock/issues/91)), so the check catches regressions from the current state. Raise the rates and lower the limits as that gap closes. The results are kept as a workflow artifact for 30 days and shown in the job summary.

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

## Results

| Version | Machine | Report |
|---|---|---|
| 0.4.0-alpha.1 | Apple M5 Pro (15 cores), 24 GiB, Docker Desktop | [results/0.4.0-alpha.1/report.md](results/0.4.0-alpha.1/report.md) |
| main, 2026-10-30 (upstream pool, #86) | same | [results/2026-10-30-upstream-pool/report.md](results/2026-10-30-upstream-pool/report.md) |
