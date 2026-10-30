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

## Results

| Version | Machine | Report |
|---|---|---|
| 0.4.0-alpha.1 | Apple M5 Pro (15 cores), 24 GiB, Docker Desktop | [results/0.4.0-alpha.1/report.md](results/0.4.0-alpha.1/report.md) |
| main, 2026-10-30 (upstream pool, #86) | same | [results/2026-10-30-upstream-pool/report.md](results/2026-10-30-upstream-pool/report.md) |
