#!/bin/bash
# benchmark_limit_flood.sh: one step of the gateway limit ladder in
# scripts/benchmark_live.sh. Sends TCP SYN packets with hping3 at a chosen
# rate and payload size for a fixed time, spread over several worker
# processes because one hping3 cannot hold a paced rate much above 10,000
# packets a second.
#
# Runs on an attacker or generator host, copied there by hand like the other
# lab generators. Needs bash (busybox sh has no mapfile) and hping3.
#
# Usage:
#   benchmark_limit_flood.sh <pps|max> <payload-bytes> <secs> <targets-file> <sources-file>
#
# <pps> is the total rate for this host, or "max" for an unpaced flood. The
# files hold one address per line. Each worker takes the next source address
# (spoofed with -a) and the next target. Set LIMIT_FLOOD_WORKERS to change the
# worker count (default 4) and LIMIT_FLOOD_DRY_RUN=1 to print the commands
# without sending anything.
set -u

PPS="${1:?pps or max required}"
PAYLOAD="${2:?payload bytes required}"
SECS="${3:?seconds required}"
TARGETS_FILE="${4:?targets file required}"
SOURCES_FILE="${5:?sources file required}"
WORKERS="${LIMIT_FLOOD_WORKERS:-4}"

[[ "$PPS" =~ ^([0-9]{1,9}|max)$ ]] || { echo "invalid pps: $PPS" >&2; exit 1; }
for v in "$PAYLOAD" "$SECS" "$WORKERS"; do
    [[ "$v" =~ ^[0-9]{1,6}$ ]] || { echo "invalid number: $v" >&2; exit 1; }
done
[ "$WORKERS" -ge 1 ] || { echo "workers must be at least 1" >&2; exit 1; }

mapfile -t targets < <(grep -v '^[[:space:]]*$' "$TARGETS_FILE")
mapfile -t sources < <(grep -v '^[[:space:]]*$' "$SOURCES_FILE")
[ "${#targets[@]}" -gt 0 ] || { echo "no targets in $TARGETS_FILE" >&2; exit 1; }
[ "${#sources[@]}" -gt 0 ] || { echo "no sources in $SOURCES_FILE" >&2; exit 1; }

if [ "$PPS" = max ]; then
    pacing=(--flood)
else
    [ "$PPS" -ge 1 ] || { echo "pps must be at least 1" >&2; exit 1; }
    interval_us=$(( 1000000 * WORKERS / PPS ))
    [ "$interval_us" -ge 1 ] || interval_us=1
    pacing=(-i "u$interval_us")
fi

pids=()
for ((w = 0; w < WORKERS; w++)); do
    cmd=(timeout "$SECS" hping3 -S -p 80 -d "$PAYLOAD" -a "${sources[$((w % ${#sources[@]}))]}" "${pacing[@]}" "${targets[$((w % ${#targets[@]}))]}")
    if [ "${LIMIT_FLOOD_DRY_RUN:-0}" = 1 ]; then
        echo "${cmd[*]}"
    else
        "${cmd[@]}" >/dev/null 2>&1 &
        pids+=("$!")
    fi
done
[ "${#pids[@]}" -eq 0 ] || wait "${pids[@]}"
