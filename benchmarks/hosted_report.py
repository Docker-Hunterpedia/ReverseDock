"""Joins the results of one hosted-runner session into one report that states its limits.

    python3 -I hosted_report.py results/ci > results/ci/hosted-report.md

Reads every folder under the given one that holds a report.md written by run.sh (the default
`single` results sit in the folder itself), with its machine.txt and images.txt. The text of the
"Read with care" section is part of the report on purpose: whoever publishes a hosted run publishes
its limits with it (ADR-0033, "Benchmarks").
"""
import pathlib
import sys

LIMITS = """\
## Read with care: what this run is and is not

- **A free GitHub-hosted runner, not dedicated hardware.** One virtual machine with 4 vCPUs
  (GitHub's standard Linux runner for public repositories), shared with other tenants. The proxy
  is pinned to 2 vCPUs (`cpuset` 0-1); the backend (NGINX serving 1 KiB) and k6 share the other 2.
  Whether the vCPUs are SMT siblings of one core, which CPU model is drawn and what the neighbours
  do change from run to run; machine.txt records what this run got.
- **Generator, backend and proxy share one kernel and one Docker bridge network.** At high rates
  the generator or the backend, not the proxy, can be the limit: compare each row with `direct`
  (k6 straight to the backend) and read dropped iterations as "the generator could not keep up".
- **Compare proxies within this run only.** Each proxy ran minutes after the others on the same
  machine; never compare these numbers with another run or with the dedicated-lab reports.
- **One repetition per cell, 30 s per rate.** Run-to-run noise on hosted runners is larger than the
  10 % the dedicated lab saw; small differences mean nothing.
- **HTTP/2 here is one request at a time per connection** (k6 sends no concurrent streams on a
  connection), so it measures HTTP/2 framing, HPACK and TLS on many connections, not multiplexing.

## What a dedicated three-machine run would add (open)

A load generator, the proxy and the backend on three dedicated machines on a private network of
10 Gbit/s or more, as HAProxy's 2021 Graviton report does: no shared kernel or network stack, the
direct generator-to-backend ceiling measured first, the proxy pinned to 2, 4 and 8 cores, host
tuning recorded, 5 repetitions per cell with proxies interleaved, latency at fixed rates and at
50 % of each proxy's own peak, an HTTP/2 multiplexing scenario with a closed-loop tool (h2load),
and absolute numbers that can be quoted. That run needs rented hardware and stays open
(docs/research/v1.0-stable.md Part C §2.5, question Q5).
"""


def sections(root):
    root = pathlib.Path(root)
    found = []
    if (root / "report.md").exists():
        found.append(("single", root))
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        if (sub / "report.md").exists():
            found.append((sub.name, sub))
    return found


def read(path):
    return path.read_text().strip() if path.exists() else "(not recorded)"


def render(root):
    parts = ["# Benchmarks on a hosted runner", "", LIMITS]
    found = sections(root)
    if found:
        first = found[0][1]
        parts += ["## Machine", "", "```text", read(first / "machine.txt"), "```", ""]
        parts += ["## Images", "", "```text", read(first / "images.txt"), "```", ""]
    for name, path in found:
        parts += [f"## {name}", "", read(path / "report.md"), ""]
    if not found:
        parts += ["No results found.", ""]
    return "\n".join(parts)


if __name__ == "__main__":
    print(render(sys.argv[1]))
