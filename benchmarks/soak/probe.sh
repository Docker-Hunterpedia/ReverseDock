#!/bin/sh
# Samples rdock, PID 1 in the shared PID namespace, every $EVERY seconds. /proc/1/net shows
# rdock's network namespace, so `tcp` counts its established TCP connections.
out=/out/probe.csv
[ -s "$out" ] || echo "time,rss_kib,threads,fds,tcp" > "$out"
while true; do
  rss=$(awk '/^VmRSS/ {print $2}' /proc/1/status)
  threads=$(awk '/^Threads/ {print $2}' /proc/1/status)
  fds=$(find /proc/1/fd -mindepth 1 -maxdepth 1 | wc -l)
  tcp=$(cat /proc/1/net/tcp /proc/1/net/tcp6 2>/dev/null | awk '$4 == "01"' | wc -l)
  echo "$(date +%s),$rss,$threads,$fds,$tcp" >> "$out"
  sleep "$EVERY"
done
