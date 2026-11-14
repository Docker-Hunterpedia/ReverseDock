#!/usr/bin/env bash
# Prints the CPU counters of a running container's cgroup as one line:
#   usage_usec nr_periods nr_throttled throttled_usec
# from cgroup v2's cpu.stat (Docker with the systemd or the cgroupfs cgroup driver). Exits 1 when
# the container's cpu.stat cannot be found, e.g. on cgroup v1.
#   ./cpu-stat.sh rdock-bench-rdock-1
set -euo pipefail
id=$(docker inspect -f '{{.Id}}' "$1")
for dir in "/sys/fs/cgroup/system.slice/docker-$id.scope" "/sys/fs/cgroup/docker/$id"; do
  if [ -r "$dir/cpu.stat" ]; then
    awk '{ v[$1] = $2 } END { printf "%d %d %d %d\n", v["usage_usec"], v["nr_periods"], v["nr_throttled"], v["throttled_usec"] }' "$dir/cpu.stat"
    exit 0
  fi
done
echo "no cgroup v2 cpu.stat for container $1" >&2
exit 1
