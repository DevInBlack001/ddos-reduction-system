#!/usr/bin/env bash
# benchmark_mode_switch.sh: switches the Stage 1 capture backend for one
# benchmark run and restores the original configuration afterwards, timing
# each step.
#
# Runs on the gateway itself, copied there and called over SSH by
# scripts/benchmark_live.sh. All timestamps come from this host's clock, so
# SSH latency never enters a measurement.
#
# The switch appends --capture-mode and --baseline-path to FLOD_TUNING in
# /etc/ddos_stage1/tuning.env. The sensor's parser takes the last value given
# for a flag, so the unit file stays untouched, and the benchmark's own
# baseline file keeps the production baseline out of the run. Rollback puts
# the original tuning.env back byte for byte.
#
# Usage:
#   benchmark_mode_switch.sh switch <pcap|kernel> <baseline-path> <stage1-unit> <out-file>
#   benchmark_mode_switch.sh rollback <stage1-unit> <out-file> <original-mode> [benchmark-baseline-glob]
#   benchmark_mode_switch.sh verify <stage1-unit> <stage2-unit> <ingress-iface> <expected-mode> <blocklist-set> <ratelimit-set>
#   benchmark_mode_switch.sh snapshot
set -uo pipefail

TUNING_FILE="${FLOD_TUNING_FILE:-/etc/ddos_stage1/tuning.env}"
BACKUP="${TUNING_FILE}.flod-benchmark-backup"
ABSENT_MARK="${TUNING_FILE}.flod-benchmark-absent"
READY_TIMEOUT_SECS="${READY_TIMEOUT_SECS:-60}"

now() { date +%s.%N; }
diff_secs() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", b - a }'; }

# first_line_time <unit> <since-epoch> <regex>: epoch time of the first
# journal line at or after <since-epoch> matching the regex, empty if none.
first_line_time() {
    local unit="$1" since="$2" pattern="$3"
    journalctl -u "$unit" --no-pager -o short-unix --since "@${since%.*}" 2>/dev/null \
        | awk -v since="$since" -v pat="$pattern" '$1 >= since && $0 ~ pat { print $1; exit }'
}

wait_for_line() {
    local unit="$1" since="$2" pattern="$3" deadline found
    deadline=$(awk -v n="$(now)" -v t="$READY_TIMEOUT_SECS" 'BEGIN { print n + t }')
    while true; do
        found=$(first_line_time "$unit" "$since" "$pattern")
        if [ -n "$found" ]; then echo "$found"; return 0; fi
        if awk -v n="$(now)" -v d="$deadline" 'BEGIN { exit !(n >= d) }'; then return 1; fi
        sleep 0.25
    done
}

# start_and_time <unit> <t_issue> <t_stopped> <out-file> <expected-mode-or-empty>
start_and_time() {
    local unit="$1" t_issue="$2" t_stopped="$3" out="$4" mode="$5"
    local t_started t_backend t_status timed_out=0 restored
    t_started=$(now)
    systemctl start "$unit"
    if [ "$mode" = "kernel" ]; then
        t_backend=$(wait_for_line "$unit" "$t_started" "Kernel: XDP attached") || t_backend=""
    else
        t_backend=$(wait_for_line "$unit" "$t_started" "main: capture backend = ") || t_backend=""
    fi
    t_status=$(wait_for_line "$unit" "$t_started" "(Kernel|Capture): status") || t_status=""
    if [ -z "$t_status" ]; then timed_out=1; fi
    restored=$(journalctl -u "$unit" --no-pager -o cat --since "@${t_started%.*}" 2>/dev/null \
        | grep -c "restored baseline from persisted state")
    {
        echo "t_issue=$t_issue"
        echo "t_stopped=$t_stopped"
        echo "t_started=$t_started"
        echo "t_capture_attached=${t_backend:-}"
        echo "t_first_status=${t_status:-}"
        echo "stop_secs=$(diff_secs "$t_issue" "$t_stopped")"
        [ -n "$t_backend" ] && echo "downtime_to_attach_secs=$(diff_secs "$t_issue" "$t_backend")"
        [ -n "$t_status" ] && echo "downtime_to_first_status_secs=$(diff_secs "$t_issue" "$t_status")"
        echo "baselines_restored=$restored"
        echo "timed_out=$timed_out"
    } >> "$out"
}

cmd_switch() {
    local mode="$1" baseline="$2" unit="$3" out="$4" orig t_issue t_stopped
    case "$mode" in pcap|kernel) ;; *) echo "mode must be pcap or kernel" >&2; exit 2 ;; esac
    : > "$out"
    echo "action=switch" >> "$out"
    echo "mode=$mode" >> "$out"
    mkdir -p "$(dirname "$TUNING_FILE")"
    if [ ! -e "$BACKUP" ] && [ ! -e "$ABSENT_MARK" ]; then
        if [ -f "$TUNING_FILE" ]; then cp -p "$TUNING_FILE" "$BACKUP"; else : > "$ABSENT_MARK"; fi
    fi
    orig=""
    if [ -f "$BACKUP" ]; then
        orig=$(grep -E '^FLOD_TUNING=' "$BACKUP" | tail -1 | cut -d= -f2-)
    fi
    orig="${orig%\"}"; orig="${orig#\"}"

    t_issue=$(now)
    systemctl stop "$unit"
    t_stopped=$(now)
    {
        if [ -f "$BACKUP" ]; then grep -vE '^FLOD_TUNING=' "$BACKUP"; fi
        echo "FLOD_TUNING=$orig --capture-mode $mode --baseline-path $baseline"
    } > "${TUNING_FILE}.new"
    chmod 644 "${TUNING_FILE}.new"
    mv "${TUNING_FILE}.new" "$TUNING_FILE"
    start_and_time "$unit" "$t_issue" "$t_stopped" "$out" "$mode"
}

cmd_rollback() {
    local unit="$1" out="$2" mode="${3:-}" glob="${4:-}" t_issue t_stopped restored_ok="none"
    : > "$out"
    echo "action=rollback" >> "$out"
    t_issue=$(now)
    systemctl stop "$unit"
    t_stopped=$(now)
    if [ -f "$BACKUP" ]; then
        cp -p "$BACKUP" "${TUNING_FILE}.restore" && mv "${TUNING_FILE}.restore" "$TUNING_FILE"
        if cmp -s "$BACKUP" "$TUNING_FILE"; then restored_ok="identical"; else restored_ok="differs"; fi
        rm -f "$BACKUP"
    elif [ -e "$ABSENT_MARK" ]; then
        rm -f "$TUNING_FILE" "$ABSENT_MARK"
        restored_ok="removed"
    fi
    if [ -n "$glob" ]; then
        # shellcheck disable=SC2086
        rm -f $glob
    fi
    echo "tuning_restore=$restored_ok" >> "$out"
    start_and_time "$unit" "$t_issue" "$t_stopped" "$out" "$mode"
}

cmd_verify() {
    local unit="$1" unit2="$2" iface="$3" expected="$4" blocklist="$5" ratelimit="$6"
    local actual xdp started
    check() { echo "check=$1 result=$2 detail=$3"; }
    if [ "$(systemctl is-active "$unit")" = "active" ]; then check stage1_active pass active; else check stage1_active fail "$(systemctl is-active "$unit")"; fi
    if [ "$(systemctl is-active "$unit2")" = "active" ]; then check stage2_active pass active; else check stage2_active fail "$(systemctl is-active "$unit2")"; fi
    started=$(systemctl show -p ActiveEnterTimestamp --value "$unit" 2>/dev/null)
    actual=$(journalctl -u "$unit" --no-pager -o cat ${started:+--since "$started"} -g 'main: capture backend = ' 2>/dev/null \
        | grep -oE 'main: capture backend = [a-z]+' | tail -1 | awk '{print $NF}')
    if [ -z "$expected" ]; then
        check capture_mode info "${actual:-unknown}"
    elif [ "$actual" = "$expected" ]; then
        check capture_mode pass "$actual"
    else
        check capture_mode fail "expected=$expected actual=${actual:-unknown}"
    fi
    if [ -n "$iface" ] && command -v ip >/dev/null 2>&1; then
        if ip -d link show "$iface" 2>/dev/null | grep -q "xdp"; then xdp="attached"; else xdp="absent"; fi
        if [ "$expected" = "kernel" ] && [ "$xdp" = "attached" ]; then check xdp_program pass "$xdp"
        elif [ "$expected" = "pcap" ] && [ "$xdp" = "absent" ]; then check xdp_program pass "$xdp"
        elif [ -z "$expected" ]; then check xdp_program info "$xdp"
        else check xdp_program fail "$xdp"; fi
    fi
    for set_name in "$blocklist" "$ratelimit"; do
        if [ -n "$set_name" ]; then
            if ipset list -n 2>/dev/null | grep -qx "$set_name"; then check "ipset_$set_name" pass present; else check "ipset_$set_name" fail missing; fi
        fi
    done
}

# snapshot: the current UTC time with microseconds on the first line, then one
# tab separated line per iptables rule that matches a ddos_ ipset:
# chain, set, target, packets, bytes. Read only, run at each phase boundary.
cmd_snapshot() {
    date -u +"%Y-%m-%d %H:%M:%S.%6N"
    for chain in INPUT FORWARD; do
        iptables -w 2 -nvxL "$chain" 2>/dev/null | awk -v c="$chain" '
            /match-set ddos_/ {
                match($0, /ddos_[a-z]+/)
                printf "%s\t%s\t%s\t%s\t%s\n", c, substr($0, RSTART, RLENGTH), $3, $1, $2
            }'
    done
}

case "${1:-}" in
    snapshot) cmd_snapshot ;;
    switch)   shift; cmd_switch "${1:?mode}" "${2:?baseline path}" "${3:?stage1 unit}" "${4:?out file}" ;;
    rollback) shift; cmd_rollback "${1:?stage1 unit}" "${2:?out file}" "${3:-}" "${4:-}" ;;
    verify)   shift; cmd_verify "${1:?stage1 unit}" "${2:?stage2 unit}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" ;;
    *) echo "Usage: $0 switch|rollback|verify ..." >&2; exit 2 ;;
esac
