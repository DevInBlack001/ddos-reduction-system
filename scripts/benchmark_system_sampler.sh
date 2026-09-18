#!/usr/bin/env bash
# benchmark_system_sampler.sh: polls CPU time and memory for the FLOD
# services while scripts/benchmark_live.sh runs, so a live benchmark
# session also has a system-health record, not just detection outcomes.
#
# Runs on the gateway itself, copied there and started/stopped by
# benchmark_live.sh over SSH. Not meant to be run by hand, though nothing
# stops it: it just polls and appends CSV lines until killed.
#
# Usage:
#   benchmark_system_sampler.sh <interval-secs> <stage1-unit> <stage2-unit> <output-csv>
set -uo pipefail

INTERVAL="${1:?interval seconds required}"
STAGE1_UNIT="${2:?stage1 unit name required}"
STAGE2_UNIT="${3:?stage2 unit name required}"
OUT="${4:?output csv path required}"

echo "timestamp,stage1_pid,stage1_cpu_ticks,stage1_rss_kb,stage2_pid,stage2_cpu_ticks,stage2_rss_kb" > "$OUT"

# CPU time is recorded as cumulative jiffies (utime+stime from
# /proc/<pid>/stat), not an instantaneous percentage. ps's own %cpu is a
# decaying average since process start, not a clean per-interval figure;
# turning two cumulative samples into a real per-interval percentage is
# left to the offline analysis, where the sample interval and this host's
# clock tick rate are both known precisely.
sample_one() {
    local pid="$1"
    if [ -z "$pid" ] || [ "$pid" = "0" ] || [ ! -r "/proc/$pid/stat" ]; then
        echo ",,"
        return
    fi
    local stat_line rest utime stime rss
    stat_line=$(cat "/proc/$pid/stat" 2>/dev/null) || { echo ",,"; return; }
    # comm (the second field) is parenthesized and can itself contain
    # spaces or parens, so split after the LAST ")" rather than assume
    # fixed field positions from the start of the line.
    rest="${stat_line##*) }"
    utime=$(echo "$rest" | awk '{print $12}')
    stime=$(echo "$rest" | awk '{print $13}')
    rss=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null)
    if [ -z "$utime" ] || [ -z "$stime" ]; then
        echo ",,"
        return
    fi
    echo "${pid},$((utime + stime)),${rss:-0}"
}

while true; do
    ts=$(date -u +"%Y-%m-%d %H:%M:%S")
    s1_pid=$(systemctl show -p MainPID --value "$STAGE1_UNIT" 2>/dev/null)
    s2_pid=$(systemctl show -p MainPID --value "$STAGE2_UNIT" 2>/dev/null)
    echo "${ts},$(sample_one "$s1_pid"),$(sample_one "$s2_pid")" >> "$OUT"
    sleep "$INTERVAL"
done
