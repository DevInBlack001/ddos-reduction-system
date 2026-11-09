#!/bin/sh
# benchmark_latency_probe.sh: sends one ICMP echo at a time to a target that
# sits behind the gateway and logs the round trip time, so
# scripts/benchmark_live.sh can report packet latency through the gateway in
# every phase.
#
# Runs on a generator host, copied there and started and stopped by
# benchmark_live.sh over SSH. Plain POSIX sh with busybox compatible ping and
# sleep. Each line is "<epoch seconds on this host>,<round trip in ms>", with
# the round trip empty when the echo got no answer within one second.
#
# Usage:
#   benchmark_latency_probe.sh <target-ip> <interval-secs> <output-csv>
set -u

TARGET="${1:?target address required}"
INTERVAL="${2:?interval seconds required}"
OUT="${3:?output csv path required}"

case "$TARGET" in
    *[!0-9A-Fa-f:.]*|'') echo "invalid target: $TARGET" >&2; exit 1 ;;
esac
case "$INTERVAL" in
    *[!0-9.]*|'') echo "invalid interval: $INTERVAL" >&2; exit 1 ;;
esac

echo "epoch,rtt_ms" > "$OUT"
while true; do
    now=$(date +%s)
    rtt=$(ping -c 1 -W 1 "$TARGET" 2>/dev/null | sed -n 's/.*time[=<]\([0-9.]*\) *ms.*/\1/p' | head -1)
    echo "$now,$rtt" >> "$OUT"
    sleep "$INTERVAL"
done
