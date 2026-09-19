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
#   benchmark_mode_switch.sh switch <pcap|kernel> <baseline-path> <stage1-unit> <out-file> [stage2-unit blocklist-set ratelimit-set]
#   benchmark_mode_switch.sh rollback <stage1-unit> <out-file> <original-mode> [baseline-dir] [stage2-unit blocklist-set ratelimit-set]
#   benchmark_mode_switch.sh verify <stage1-unit> <stage2-unit> <ingress-iface> <expected-mode> <blocklist-set> <ratelimit-set>
#   benchmark_mode_switch.sh snapshot
#   benchmark_mode_switch.sh reset-enforcement <stage2-unit> <blocklist-set> <ratelimit-set>
#   benchmark_mode_switch.sh apply-floors <flags> <stage1-unit> <out-file> <mode>
set -uo pipefail

TUNING_FILE="${FLOD_TUNING_FILE:-/etc/ddos_stage1/tuning.env}"
BACKUP="${TUNING_FILE}.flod-benchmark-backup"
ABSENT_MARK="${TUNING_FILE}.flod-benchmark-absent"
# The debug logging drop-in that calibrate.py --auto-debug writes. Rollback
# removes it only when this benchmark started without one, so an interrupted
# calibration cannot leave the sensor logging at debug level.
DEBUG_DROPIN="${FLOD_DEBUG_DROPIN:-/etc/systemd/system/ddos-stage1.service.d/10-calibration-debug.conf}"
DROPIN_MARK="${TUNING_FILE}.flod-benchmark-dropin-present"
READY_TIMEOUT_SECS="${READY_TIMEOUT_SECS:-60}"

# Every value that reaches a command line, a file path, or the sensor's flag
# line is checked against a strict pattern first. This script runs as root and
# its arguments come from the benchmark config, so nothing is passed on
# unchecked: a space in a path would add extra sensor flags, and a wildcard
# would widen a delete.
die() { echo "benchmark_mode_switch.sh: $*" >&2; exit 2; }
UNIT_RE='^[A-Za-z0-9@:._-]{1,100}$'
SET_RE='^[A-Za-z0-9_.-]{1,31}$'
IFACE_RE='^[A-Za-z0-9_.:-]{1,15}$'
PATH_RE='^/[A-Za-z0-9_./-]{1,200}$'
NUM_RE='[0-9]+(\.[0-9]+)?'
FLOORS_RE="^--rate-sigma-floor ${NUM_RE}( --entropy-sigma-floor ${NUM_RE})?( --entropy-sigma-ceiling ${NUM_RE})?\$"
require() { [[ "$2" =~ $3 ]] || die "invalid $1: '$2'"; }
require_optional() { [ -z "$2" ] || require "$1" "$2" "$3"; }
require_path() {
    require "$1" "$2" "$PATH_RE"
    case "$2" in *..*|/) die "invalid $1: '$2'" ;; esac
}
require_mode() { [[ "$2" =~ ^(pcap|kernel)$ ]] || die "invalid $1: '$2'"; }
refuse_symlink() { [ ! -L "$1" ] || die "refusing to write through a symlink: $1"; }

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
    deadline=$(awk -v n="$(now)" -v t="$READY_TIMEOUT_SECS" 'BEGIN { printf "%.3f", n + t }')
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

# reset_enforcement <stage2-unit> <blocklist-set> <ratelimit-set>: empties both
# ipsets and restarts Stage 2, so every run starts with no blocks left over
# from an earlier one (a block lasts an hour) and no in-memory enforcement
# state. Runs before the sensor swap, so the swap's own timing excludes it.
reset_enforcement() {
    local unit2="${1:-}" blocklist="${2:-}" ratelimit="${3:-}" t0
    [ -n "$blocklist" ] && ipset flush "$blocklist" 2>/dev/null
    [ -n "$ratelimit" ] && ipset flush "$ratelimit" 2>/dev/null
    if [ -n "$unit2" ]; then
        t0=$(now)
        systemctl restart "$unit2"
        wait_for_line "$unit2" "$t0" "IPC socket listening" >/dev/null || true
    fi
}

cmd_switch() {
    local mode="$1" baseline="$2" unit="$3" out="$4" unit2="${5:-}" blocklist="${6:-}" ratelimit="${7:-}" orig t_issue t_stopped
    require_mode mode "$mode"
    require_path baseline-path "$baseline"
    require unit "$unit" "$UNIT_RE"
    require_path out-file "$out"
    require_optional stage2-unit "$unit2" "$UNIT_RE"
    require_optional blocklist-set "$blocklist" "$SET_RE"
    require_optional ratelimit-set "$ratelimit" "$SET_RE"
    refuse_symlink "$out"
    : > "$out"
    echo "action=switch" >> "$out"
    echo "mode=$mode" >> "$out"
    mkdir -p "$(dirname "$TUNING_FILE")"
    if [ ! -e "$BACKUP" ] && [ ! -e "$ABSENT_MARK" ]; then
        if [ -f "$TUNING_FILE" ]; then cp -p "$TUNING_FILE" "$BACKUP"; else : > "$ABSENT_MARK"; fi
        if [ -e "$DEBUG_DROPIN" ]; then : > "$DROPIN_MARK"; else rm -f "$DROPIN_MARK"; fi
    fi
    orig=""
    if [ -f "$BACKUP" ]; then
        orig=$(grep -E '^FLOD_TUNING=' "$BACKUP" | tail -1 | cut -d= -f2-)
    fi
    orig="${orig%\"}"; orig="${orig#\"}"

    reset_enforcement "$unit2" "$blocklist" "$ratelimit"
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

# apply-floors: adds calibrated sigma floors to the tuning line and restarts
# the sensor, timing the restart. The floors are appended after the flags
# already there, so the capture mode and baseline path from the switch stay in
# force (the sensor takes the last value given for a flag).
cmd_apply_floors() {
    local flags="$1" unit="$2" out="$3" mode="${4:-}" before t_issue t_stopped
    require flags "$flags" "$FLOORS_RE"
    require unit "$unit" "$UNIT_RE"
    require_path out-file "$out"
    [ -z "$mode" ] || require_mode mode "$mode"
    [ -f "$TUNING_FILE" ] || die "no tuning file to extend, run switch first"
    refuse_symlink "$out"
    before=$(grep -E '^FLOD_TUNING=' "$TUNING_FILE" | tail -1 | cut -d= -f2-)
    : > "$out"
    echo "action=apply-floors" >> "$out"
    echo "applied_flags=$flags" >> "$out"
    echo "tuning_before=$before" >> "$out"
    t_issue=$(now)
    systemctl stop "$unit"
    t_stopped=$(now)
    {
        grep -vE '^FLOD_TUNING=' "$TUNING_FILE"
        echo "FLOD_TUNING=$before $flags"
    } > "${TUNING_FILE}.new"
    chmod 644 "${TUNING_FILE}.new"
    mv "${TUNING_FILE}.new" "$TUNING_FILE"
    echo "tuning_after=$before $flags" >> "$out"
    start_and_time "$unit" "$t_issue" "$t_stopped" "$out" "$mode"
}

cmd_rollback() {
    local unit="$1" out="$2" mode="${3:-}" dir="${4:-}" unit2="${5:-}" blocklist="${6:-}" ratelimit="${7:-}"
    local t_issue t_stopped restored_ok="none"
    require unit "$unit" "$UNIT_RE"
    require_path out-file "$out"
    [ -z "$mode" ] || require_mode original-mode "$mode"
    [ -z "$dir" ] || require_path baseline-dir "$dir"
    require_optional stage2-unit "$unit2" "$UNIT_RE"
    require_optional blocklist-set "$blocklist" "$SET_RE"
    require_optional ratelimit-set "$ratelimit" "$SET_RE"
    refuse_symlink "$out"
    : > "$out"
    echo "action=rollback" >> "$out"
    reset_enforcement "$unit2" "$blocklist" "$ratelimit"
    t_issue=$(now)
    systemctl stop "$unit"
    t_stopped=$(now)
    if { [ -f "$BACKUP" ] || [ -e "$ABSENT_MARK" ]; } && [ -e "$DEBUG_DROPIN" ] && [ ! -e "$DROPIN_MARK" ]; then
        rm -f "$DEBUG_DROPIN"
        systemctl daemon-reload
        echo "removed_debug_dropin=1" >> "$out"
    fi
    rm -f "$DROPIN_MARK"
    if [ -f "$BACKUP" ]; then
        cp -p "$BACKUP" "${TUNING_FILE}.restore" && mv "${TUNING_FILE}.restore" "$TUNING_FILE"
        if cmp -s "$BACKUP" "$TUNING_FILE"; then restored_ok="identical"; else restored_ok="differs"; fi
        rm -f "$BACKUP"
    elif [ -e "$ABSENT_MARK" ]; then
        rm -f "$TUNING_FILE" "$ABSENT_MARK"
        restored_ok="removed"
    fi
    if [ -n "$dir" ]; then
        find "$dir" -maxdepth 1 -type f -name 'flod_benchmark_*.json' -delete 2>/dev/null
    fi
    echo "tuning_restore=$restored_ok" >> "$out"
    start_and_time "$unit" "$t_issue" "$t_stopped" "$out" "$mode"
}

cmd_verify() {
    local unit="$1" unit2="$2" iface="$3" expected="$4" blocklist="$5" ratelimit="$6"
    local actual xdp started
    require unit "$unit" "$UNIT_RE"
    require unit "$unit2" "$UNIT_RE"
    require_optional interface "$iface" "$IFACE_RE"
    [ -z "$expected" ] || require_mode expected-mode "$expected"
    require_optional blocklist-set "$blocklist" "$SET_RE"
    require_optional ratelimit-set "$ratelimit" "$SET_RE"
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
    apply-floors) shift; cmd_apply_floors "${1:?flags}" "${2:?stage1 unit}" "${3:?out file}" "${4:-}" ;;
    reset-enforcement)
        shift
        require unit "${1:?stage2 unit}" "$UNIT_RE"
        require blocklist-set "${2:?blocklist set}" "$SET_RE"
        require ratelimit-set "${3:?ratelimit set}" "$SET_RE"
        reset_enforcement "$1" "$2" "$3" ;;
    switch)   shift; cmd_switch "${1:?mode}" "${2:?baseline path}" "${3:?stage1 unit}" "${4:?out file}" "${5:-}" "${6:-}" "${7:-}" ;;
    rollback) shift; cmd_rollback "${1:?stage1 unit}" "${2:?out file}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" "${7:-}" ;;
    verify)   shift; cmd_verify "${1:?stage1 unit}" "${2:?stage2 unit}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" ;;
    *) echo "Usage: $0 switch|rollback|verify ..." >&2; exit 2 ;;
esac
