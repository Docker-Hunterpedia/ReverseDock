#!/usr/bin/env bash
# Per-request cost of ReverseDock without Docker: allocations, system calls and CPU time.
#
#   perreq/run.sh counts <alloc-count rdock> <out-dir>          # exact counts, every variant
#   perreq/run.sh cpu <rdock A> <rdock B> <out-dir> [rounds]     # interleaved A/B with an A/A floor
#   perreq/run.sh tail <rdock> <out-dir> [max_handshakes]        # TLS tail during a handshake burst
#   perreq/run.sh scaling <rdock> <out-dir> [rounds]             # rdock on 1, 2, 4 CPUs: throughput and CPU per request
#
# Build the binaries first (benchmarks/README.md, "Per-request cost without Docker"):
#   cargo build --locked -p rdock --features alloc-count        # counts (debug build)
#   cargo build --locked --release -p rdock -p rdock-perreq     # CPU time
# PERREQ names the measurement tool (default: target/release/rdock-perreq, else target/debug).
# Output: one JSON line per run in <out-dir>/*.jsonl; summarize.py turns them into tables.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
perreq=${PERREQ:-}
if [[ -z "$perreq" ]]; then
  if [[ -x "$root/target/release/rdock-perreq" ]]; then perreq="$root/target/release/rdock-perreq"
  else perreq="$root/target/debug/rdock-perreq"; fi
fi
# rdock on two CPUs, the tool (client and backend) on two others, as in the lab's 2-CPU rung.
RDOCK_CPUS=${RDOCK_CPUS:-0,1}
TOOL_CPUS=${TOOL_CPUS:-2,3}
N=${N:-2000}          # requests in the first phase of a count (the second sends 2N)
CPU_N=${CPU_N:-20000} # the same for CPU time

# label | arguments
variants=(
  "routes-1|--routes 1"
  "routes-1000|--routes 1000"
  "routes-10000|--routes 10000"
  "headers-20|--routes 1 --headers 20"
  "tls|--routes 1 --tls"
)

tool() { taskset -c "$TOOL_CPUS" "$perreq" "$@"; }

cmd=${1:-}
case "$cmd" in
  counts)
    bin=$2 out=$3
    mkdir -p "$out"
    for v in "${variants[@]}"; do
      label=${v%%|*} args=${v#*|}
      # shellcheck disable=SC2086
      tool measure --rdock "$bin" --cpus "$RDOCK_CPUS" --measure allocs --n "$N" --label "$label" $args >>"$out/allocs.jsonl"
      # shellcheck disable=SC2086
      tool measure --rdock "$bin" --cpus "$RDOCK_CPUS" --measure syscalls --n "$N" --label "$label" $args >>"$out/syscalls.jsonl"
      echo "counted $label" >&2
    done
    ;;
  cpu)
    a=$2 b=$3 out=$4 rounds=${5:-5}
    mkdir -p "$out"
    # Each round runs A, B, A for every variant: the two A runs give the A/A spread (the noise
    # floor), and A and B alternate so drift in the machine's load hits both.
    for round in $(seq 1 "$rounds"); do
      for v in "${variants[@]}"; do
        label=${v%%|*} args=${v#*|}
        for which in A B A; do
          bin=$a; [[ $which == B ]] && bin=$b
          # shellcheck disable=SC2086
          tool measure --rdock "$bin" --cpus "$RDOCK_CPUS" --measure cpu --n "$CPU_N" --label "$label/$which" $args >>"$out/cpu.jsonl"
        done
      done
      echo "round $round done" >&2
    done
    ;;
  tail)
    bin=$2 out=$3 limit=${4:-}
    mkdir -p "$out"
    extra=()
    [[ -n "$limit" ]] && extra=(--max-handshakes "$limit")
    # The measuring client on one tool CPU, the burst process on the other.
    measure_cpu=${TOOL_CPUS##*,} burst_cpu=${TOOL_CPUS%%,*}
    for round in 1 2 3; do
      for ramp in 0 2000; do
        taskset -c "$measure_cpu" "$perreq" tail --rdock "$bin" --cpus "$RDOCK_CPUS" --burst-cpus "$burst_cpu" --tls \
          --ramp "$ramp" --label "ramp-$ramp${limit:+/limit-$limit}" "${extra[@]}" >>"$out/tail.jsonl"
      done
      echo "tail round $round done" >&2
    done
    ;;
  scaling)
    # rdock on the first n CPUs (n in SIZES), `runtime.worker_threads` = n; the tool (generator and
    # backend together) on the CPUs that are left, or, when none are (n = every CPU), on all of
    # them, sharing with rdock: that size is then a lower bound, not a clean measurement. Each
    # round runs every size once, in alternating order, so drift in the machine hits all sizes.
    bin=$2 out=$3 rounds=${4:-3}
    mkdir -p "$out"
    total=$(nproc)
    sizes=${SIZES:-"1 2 4"}
    {
      echo "cpus: $total"
      echo "sizes: $sizes"
      echo "model: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
      echo "kernel: $(uname -r)"
      echo "cgroup cpu.max: $(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo n/a)"
    } >"$out/machine.txt"
    for round in $(seq 1 "$rounds"); do
      order=$sizes
      if ((round % 2 == 0)); then order=$(echo "$sizes" | tr ' ' '\n' | tac | tr '\n' ' '); fi
      for n in $order; do
        ((n <= total)) || { echo "skipping $n CPUs: this machine has $total" >&2; continue; }
        rdock_cpus="0-$((n - 1))"
        label="cpus-$n"
        if ((n < total)); then
          tool_cpus="$n-$((total - 1))"
          tool_n=$((total - n))
        else
          tool_cpus="0-$((total - 1))"
          tool_n=$total
          label="cpus-$n/shared"
        fi
        taskset -c "$tool_cpus" "$perreq" scale --rdock "$bin" --cpus "$rdock_cpus" \
          --config-extra "runtime: { worker_threads: $n }" --tool-threads "$tool_n" --tool-cpus "$tool_cpus" \
          --conns "${SCALE_CONNS:-64}" --warmup "${SCALE_WARMUP:-5}" --seconds "${SCALE_SECONDS:-20}" \
          --label "$label" >>"$out/scaling.jsonl"
        echo "scaling round $round: $n CPUs done" >&2
      done
    done
    ;;
  *)
    sed -n '2,14p' "$0" >&2
    exit 2
    ;;
esac
