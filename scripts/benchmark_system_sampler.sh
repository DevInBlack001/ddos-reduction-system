#!/usr/bin/env bash
# benchmark_system_sampler.sh: polls CPU time, context switches, memory, and
# network interface counters for the FLOD services while
# scripts/benchmark_live.sh runs, so a live benchmark session also has a
# system-health record as well as detection outcomes.
#
# Runs on the gateway itself, copied there and started/stopped by
# benchmark_live.sh over SSH. Not meant to be run by hand, though nothing
# stops it: it just polls and appends CSV lines until killed.
#
# Usage:
#   benchmark_system_sampler.sh <interval-secs> <stage1-unit> <stage2-unit> <output-csv> [ingress-iface] [egress-iface]
set -uo pipefail

INTERVAL="${1:?interval seconds required}"
STAGE1_UNIT="${2:?stage1 unit name required}"
STAGE2_UNIT="${3:?stage2 unit name required}"
OUT="${4:?output csv path required}"
INGRESS_IFACE="${5:-}"
EGRESS_IFACE="${6:-}"

cat > "$OUT" <<'EOF'
timestamp,stage1_pid,stage1_cpu_ticks,stage1_rss_kb,stage2_pid,stage2_cpu_ticks,stage2_rss_kb,stage1_vol_ctxt,stage1_nonvol_ctxt,stage2_vol_ctxt,stage2_nonvol_ctxt,sys_user,sys_nice,sys_system,sys_idle,sys_iowait,sys_irq,sys_softirq,sys_steal,sys_ctxt,ingress_rx_packets,ingress_rx_bytes,ingress_rx_dropped,ingress_rx_errors,egress_tx_packets,egress_tx_bytes,egress_tx_dropped
EOF

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

# Cumulative voluntary and involuntary context switches for one process
# (the main thread's own counters plus every other thread's, summed).
ctxt_one() {
    local pid="$1"
    if [ -z "$pid" ] || [ "$pid" = "0" ] || [ ! -d "/proc/$pid/task" ]; then
        echo ","
        return
    fi
    cat /proc/"$pid"/task/*/status 2>/dev/null | awk '
        /^voluntary_ctxt_switches:/ { v += $2 }
        /^nonvoluntary_ctxt_switches:/ { n += $2 }
        END { printf "%d,%d", v, n }'
}

# System-wide cumulative CPU jiffies and context switches. The kernel
# backend does its counting in softirq context under XDP, which no
# per-process figure attributes to Stage 1, so a backend comparison needs
# these as well.
sys_cpu() {
    awk '/^cpu / { printf "%d,%d,%d,%d,%d,%d,%d,%d", $2, $3, $4, $5, $6, $7, $8, $9 }' /proc/stat
}
sys_ctxt() { awk '/^ctxt / { print $2 }' /proc/stat; }

iface_stat() {
    local iface="$1" name="$2"
    if [ -n "$iface" ] && [ -r "/sys/class/net/$iface/statistics/$name" ]; then
        cat "/sys/class/net/$iface/statistics/$name"
    fi
}

while true; do
    ts=$(date -u +"%Y-%m-%d %H:%M:%S")
    s1_pid=$(systemctl show -p MainPID --value "$STAGE1_UNIT" 2>/dev/null)
    s2_pid=$(systemctl show -p MainPID --value "$STAGE2_UNIT" 2>/dev/null)
    line=$(
        printf '%s,%s,%s,' "$ts" "$(sample_one "$s1_pid")" "$(sample_one "$s2_pid")"
        printf '%s,%s,' "$(ctxt_one "$s1_pid")" "$(ctxt_one "$s2_pid")"
        printf '%s,%s,' "$(sys_cpu)" "$(sys_ctxt)"
        printf '%s,%s,%s,%s,' \
            "$(iface_stat "$INGRESS_IFACE" rx_packets)" "$(iface_stat "$INGRESS_IFACE" rx_bytes)" \
            "$(iface_stat "$INGRESS_IFACE" rx_dropped)" "$(iface_stat "$INGRESS_IFACE" rx_errors)"
        printf '%s,%s,%s' \
            "$(iface_stat "$EGRESS_IFACE" tx_packets)" "$(iface_stat "$EGRESS_IFACE" tx_bytes)" \
            "$(iface_stat "$EGRESS_IFACE" tx_dropped)"
    )
    echo "$line" >> "$OUT"
    sleep "$INTERVAL"
done
