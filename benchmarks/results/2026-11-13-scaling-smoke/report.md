# CPU scaling, smoke run, 2026-11-13

**This is a smoke run on a shared 4-vCPU development sandbox, not a result.** It shows that `perreq/run.sh scaling` and `summarize.py scaling` work. Numbers from a shared sandbox cannot be compared with the lab's or with a hosted runner's, and the machine was otherwise idle only to the extent a shared sandbox is.

Commit `a1d7b82` plus the uncommitted step-9 files; release build. Three rounds of 1, 2 and 4 CPUs (alternating order), 5 s warm-up and 20 s measured per run, 64 connections, closed-loop saturation, 1 KiB answers, plain HTTP/1.1, one route:

```sh
benchmarks/perreq/run.sh scaling target/release/rdock out/ 3
python3 -I benchmarks/perreq/summarize.py scaling out/
```

Layout: rdock on CPUs 0, 0-1, 0-3; the tool (generator and backend) on CPUs 1-3, 2-3 and **0-3 (shared with rdock)**. **The 4-CPU row is a lower bound, not a clean measurement**: nothing is left for the generator. In it rdock's CPUs were only 61 % busy, so the figure says what this closed loop achieved with the cores shared, not what 4 CPUs can do. Read the 1 and 2 CPU rows as the cleaner ones (rdock's CPUs 100 % and 99 % busy, the tool at 10 % and 35 % of its CPUs).

Machine: cpus: 4; sizes: 1 2 4; model: Intel(R) Xeon(R) Processor @ 2.30GHz; kernel: 6.18.44-fc-v445; cgroup cpu.max: n/a

| rdock CPUs | Tool CPUs | Rounds | Requests/s median (min–max) | CPU µs per request median (min–max) | rdock CPUs busy | Tool CPUs busy | vs smallest | Efficiency | Errors | Reading |
|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---|
| 1 | 3 | 3 | 18,485 (16,378–18,877) | 53.9 (52.7–60.7) | 100% | 10% | 1.00× | 100% | 0 | clean |
| 2 | 2 | 3 | 31,628 (30,916–34,264) | 62.4 (57.8–64.1) | 99% | 35% | 1.71× | 86% | 0 | clean |
| 4 | 4 | 3 | 42,949 (41,889–45,486) | 57.0 (53.2–58.5) | 61% | 16% | 2.32× | 58% | 0 | the tool shares these CPUs with rdock: a lower bound, not a clean measurement; rdock's CPUs were not all busy: it was not the limit |
