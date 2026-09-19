#!/usr/bin/env bash
# =============================================================================
# benchmark_live.sh: the live-traffic counterpart to
# scripts/benchmark_fixed_threshold.py, run once per capture backend.
# =============================================================================
#
# That script replays an already-captured CSV offline; this one drives real
# traffic at a real, running deployment and reports what the deployed system
# actually did: detection counts, misclassifications, enforcement actions,
# and the resulting firewall state. Where the offline benchmark answers "does
# the trained model generalize," this answers "does the deployed pipeline,
# warm-up, hysteresis, block tiers and all, behave the way that implies."
#
# One session runs the full seven phase set for each capture backend in
# CAPTURE_MODES (default "kernel pcap"), so the two backends see the same
# phases and the same generators, and the analysis compares them. Between
# backends the script switches Stage 1's capture mode through
# /etc/ddos_stage1/tuning.env, times the downtime, and at the end restores the
# original configuration and times that rollback too. Each run starts from a
# clean enforcement state (both ipsets emptied, Stage 2 restarted), so blocks
# from an earlier run cannot change a later run's results. If the script is
# interrupted, an exit trap performs the same rollback.
#
# Per phase and per backend it records: traffic and throughput (packets and
# bits per second, from the capture counters and from the network interface),
# packets dropped at capture and by the firewall, CPU (per service and
# system wide, softirq included), context switches, memory, Stage 2 latency
# (window handoff, inference, enforcement, window close to rule applied),
# and the time from the start of an attack phase to the first detection and
# the first block.
#
# Traffic generation is deliberately not prescribed here either, matching
# docs/training.md's own stance: this script orchestrates phase timing,
# warm-up detection, log capture, and reporting, but the actual Normal /
# Flash Crowd / Attacker traffic comes from whatever start/stop commands you
# configure, run over SSH on your own generator hosts.
#
# Seven phases, each traffic type introduced alone first, then every pairwise
# combination, then all three together: Normal, Flash Crowd, Attacker,
# Normal+Flash Crowd, Normal+Attacker, Flash Crowd+Attacker, all three. Each
# phase only starts or stops the generators whose desired state actually
# changed from the previous phase, so a generator already running into a
# mixed phase keeps running without a restart.
#
# The gateway's Stage 1 sensor and Stage 2 service restart once per run, and
# the two ipsets are emptied each time. Do not run this while the gateway
# protects live traffic.
#
# Usage:
#   bash scripts/benchmark_live.sh <config-file>
#
# See scripts/benchmark_live.example.env for every variable this reads and
# what it means. Copy it, fill in your own hosts, targets, and generator
# commands, and pass the copy as the one argument.
# =============================================================================
set -uo pipefail

CONFIG="${1:-}"
if [ -z "$CONFIG" ] || [ ! -f "$CONFIG" ]; then
    echo "Usage: bash scripts/benchmark_live.sh <config-file>" >&2
    echo "See scripts/benchmark_live.example.env for the format." >&2
    exit 1
fi
# The config is sourced as shell, so it must belong to this account or root and
# must not be writable by everyone.
config_owner=$(stat -c %u "$CONFIG")
if [ "$config_owner" != "$(id -u)" ] && [ "$config_owner" != 0 ]; then
    echo "Config error: $CONFIG belongs to another account" >&2
    exit 1
fi
if [ $(( 8#$(stat -c %a "$CONFIG") & 8#002 )) -ne 0 ]; then
    echo "Config error: $CONFIG is writable by everyone" >&2
    exit 1
fi
# shellcheck source=/dev/null
source "$CONFIG"

: "${GATEWAY_HOST:?set in config}"
: "${GATEWAY_SSH_KEY:?set in config}"
: "${TARGET_IPS:?set in config, comma separated}"
: "${STAGE1_UNIT:=ddos-stage1.service}"
: "${STAGE2_UNIT:=ddos-stage2.service}"
: "${BLOCKLIST_SET:=ddos_blocklist}"
: "${RATELIMIT_SET:=ddos_ratelimit}"
: "${WARMUP_TIMEOUT_SECS:=900}"
: "${NORMAL_SECS:=120}"
: "${FLASHCROWD_SECS:=120}"
: "${ATTACK_SECS:=180}"
: "${PAIR_SECS:=150}"
: "${ALL_THREE_SECS:=180}"
: "${OUTPUT_DIR:=./benchmark-live-results}"
: "${SYSTEM_SAMPLE_INTERVAL_SECS:=5}"
: "${CAPTURE_MODES:=kernel pcap}"
: "${RUNS_PER_MODE:=1}"
: "${INGRESS_IFACE:=}"
: "${EGRESS_IFACE:=}"
: "${BASELINE_DIR:=/var/lib/ddos_stage1}"
: "${REMOTE_DIR:=/root/.flod_benchmark}"
: "${ATTACK_SWEEP_SECS:=0}"
: "${TYPE_GAP_SECS:=30}"
: "${ATTACK_SOURCE_FILE:=}"
: "${ATTACK_SOURCES_MIN:=30}"
: "${ATTACK_SOURCES_MAX:=40}"
: "${CALIBRATE:=off}"
: "${CALIBRATE_WINDOWS:=1000}"
: "${CALIBRATE_TIMEOUT_MINS:=30}"
: "${NORMAL_SOURCE_FILE:=}"
: "${FLASHCROWD_SOURCE_FILE:=}"

# The generator start and stop commands are shell you wrote, run over SSH on
# the generator hosts, and this file is sourced as shell, so keep it out of
# reach of anyone you do not trust. Every other value below ends up in a
# command line on the gateway, which runs as root, so each one is checked
# against a strict pattern before anything runs.
config_error() { echo "Config error: $*" >&2; exit 1; }
check_value() { [[ "$2" =~ $3 ]] || config_error "$1 has an invalid value: '$2'"; }
validate_config() {
    local unit_re='^[A-Za-z0-9@:._-]{1,100}$' set_re='^[A-Za-z0-9_.-]{1,31}$'
    local iface_re='^[A-Za-z0-9_.:-]{1,15}$' path_re='^/[A-Za-z0-9_./-]{1,200}$'
    local host_re='^[A-Za-z0-9._@-]{1,100}$' key_re='^[A-Za-z0-9_./~-]{1,200}$'
    local name mode
    check_value GATEWAY_HOST "$GATEWAY_HOST" "$host_re"
    check_value GATEWAY_SSH_KEY "$GATEWAY_SSH_KEY" "$key_re"
    check_value STAGE1_UNIT "$STAGE1_UNIT" "$unit_re"
    check_value STAGE2_UNIT "$STAGE2_UNIT" "$unit_re"
    check_value BLOCKLIST_SET "$BLOCKLIST_SET" "$set_re"
    check_value RATELIMIT_SET "$RATELIMIT_SET" "$set_re"
    check_value TARGET_IPS "$TARGET_IPS" '^[0-9A-Fa-f:.,]+$'
    [ -z "$INGRESS_IFACE" ] || check_value INGRESS_IFACE "$INGRESS_IFACE" "$iface_re"
    [ -z "$EGRESS_IFACE" ] || check_value EGRESS_IFACE "$EGRESS_IFACE" "$iface_re"
    for name in BASELINE_DIR REMOTE_DIR; do
        check_value "$name" "${!name}" "$path_re"
        case "${!name}" in *..*|/) config_error "$name has an invalid value: '${!name}'" ;; esac
    done
    for name in WARMUP_TIMEOUT_SECS NORMAL_SECS FLASHCROWD_SECS ATTACK_SECS PAIR_SECS \
                ALL_THREE_SECS SYSTEM_SAMPLE_INTERVAL_SECS RUNS_PER_MODE; do
        check_value "$name" "${!name}" '^[0-9]{1,6}$'
    done
    [ "$RUNS_PER_MODE" -ge 1 ] || config_error "RUNS_PER_MODE must be at least 1"
    for mode in $CAPTURE_MODES; do
        [[ "$mode" =~ ^(pcap|kernel)$ ]] || config_error "CAPTURE_MODES holds '$mode', expected pcap or kernel"
    done
    [[ "$CALIBRATE" =~ ^(off|measure|apply)$ ]] || config_error "CALIBRATE is '$CALIBRATE', expected off, measure or apply"
    for name in CALIBRATE_WINDOWS CALIBRATE_TIMEOUT_MINS; do
        check_value "$name" "${!name}" '^[0-9]{1,6}$'
    done
    [ "$CALIBRATE_WINDOWS" -ge 2 ] || config_error "CALIBRATE_WINDOWS must be at least 2"
    for name in ATTACK_SWEEP_SECS TYPE_GAP_SECS ATTACK_SOURCES_MIN ATTACK_SOURCES_MAX; do
        check_value "$name" "${!name}" '^[0-9]{1,6}$'
    done
    for name in ATTACK_SOURCE_FILE NORMAL_SOURCE_FILE FLASHCROWD_SOURCE_FILE; do
        [ -z "${!name}" ] || check_value "$name" "${!name}" "$path_re"
    done
    for name in NORMAL_VARIANTS FLASHCROWD_VARIANTS ATTACK_VARIANTS; do
        for mode in ${!name:-}; do
            [[ "$mode" =~ ^[a-z0-9_]{1,20}$ ]] || config_error "$name holds '$mode', names use lowercase letters, digits and underscores"
        done
    done
    for name in NORMAL_HOST NORMAL_HOST_2 FLASHCROWD_HOST FLASHCROWD_HOST_2 ATTACK_HOST; do
        [ -z "${!name:-}" ] || check_value "$name" "${!name}" "$host_re"
    done
    for name in NORMAL_SSH_KEY NORMAL_SSH_KEY_2 FLASHCROWD_SSH_KEY FLASHCROWD_SSH_KEY_2 ATTACK_SSH_KEY; do
        [ -z "${!name:-}" ] || check_value "$name" "${!name}" "$key_re"
    done
}
validate_config

GW_SSH="ssh -i $GATEWAY_SSH_KEY -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=8 $GATEWAY_HOST"
GW_SCP="scp -i $GATEWAY_SSH_KEY -o BatchMode=yes -o ConnectTimeout=10"
SESSION_DIR="$OUTPUT_DIR/session_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$SESSION_DIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# Set per run by run_session.
PHASES_FILE=""
FIREWALL_TSV=""

HELPER_LOCAL="$(dirname "$0")/benchmark_mode_switch.sh"
HELPER_REMOTE="$REMOTE_DIR/mode_switch.sh"

mark_phase() {
    local name="$1" out ts
    out=$($GW_SSH "$HELPER_REMOTE snapshot")
    ts=$(printf '%s\n' "$out" | head -1)
    echo -e "${name}\t${ts}" >> "$PHASES_FILE"
    printf '%s\n' "$out" | tail -n +2 | while IFS= read -r row; do
        printf '%s\t%s\t%s\n' "$name" "$ts" "$row" >> "$FIREWALL_TSV"
    done
    log "phase '$name' begins at $ts UTC"
}

ssh_retry() {
    local desc="$1"; shift
    local tries=0 rc
    while true; do
        "$@"
        rc=$?
        if [ "$rc" -ne 255 ]; then return "$rc"; fi
        tries=$((tries + 1))
        if [ "$tries" -ge 4 ]; then
            log "WARNING: ssh connection failed $tries times ($desc), giving up"
            return 255
        fi
        log "ssh connection failed (rc=255), retrying in 5s ($desc, attempt $((tries+1))/4)"
        sleep 5
    done
}

run_remote() {
    # run_remote <host> <key> <command...>
    local host="$1" key="$2"; shift 2
    ssh_retry "$host: $*" ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=10 "$host" "$@"
}

# --- Traffic classes and their variants. Each class (NORMAL, FLASHCROWD,
# ATTACK) has a list of named variants, for example two Normal request
# patterns or five attack types, so the traffic does not repeat the same
# pattern in every phase and run. A class without a variant list uses its
# plain START_CMD and STOP_CMD as one variant called "default". A variant
# "bursty" of NORMAL reads NORMAL_V_bursty_START_CMD, NORMAL_V_bursty_STOP_CMD
# (falling back to NORMAL_STOP_CMD), the _2 forms for a second generator host,
# and NORMAL_V_bursty_DESC for the report.
#
# Every time a class is started, the next variant in its list is chosen,
# offset by the run number, so run 2 begins where run 1's rotation left the
# list. Both backends see the same sequence for the same run number, which
# keeps the comparison fair. A generator that stays active across a phase
# transition is left alone and keeps running. ---
get_var() { local n="$1"; printf '%s' "${!n:-${2:-}}"; }
variant_var() {
    if [ "$2" = default ]; then echo "${1}_${3}"; else echo "${1}_V_${2}_${3}"; fi
}
RUN_INDEX=1
FORCE_ATTACK_VARIANT=""
NORMAL_STARTS=0; FLASHCROWD_STARTS=0; ATTACK_STARTS=0
RUNNING_NORMAL=""; RUNNING_FLASHCROWD=""; RUNNING_ATTACK=""

next_variant() {
    # next_variant <CLASS> <starts so far>
    local class="$1" starts="$2" list
    if [ "$class" = ATTACK ] && [ -n "$FORCE_ATTACK_VARIANT" ]; then echo "$FORCE_ATTACK_VARIANT"; return; fi
    read -ra list <<< "$(get_var "${class}_VARIANTS" default)"
    echo "${list[$(( (starts + RUN_INDEX - 1) % ${#list[@]} ))]}"
}

start_class() {
    # start_class <CLASS> <variant>
    local class="$1" v="$2" cmd cmd2
    cmd=$(get_var "$(variant_var "$class" "$v" START_CMD)")
    cmd2=$(get_var "$(variant_var "$class" "$v" START_CMD_2)")
    if [ -n "$cmd" ]; then run_remote "$(get_var "${class}_HOST")" "$(get_var "${class}_SSH_KEY")" "$cmd"; fi
    if [ -n "$cmd2" ]; then run_remote "$(get_var "${class}_HOST_2")" "$(get_var "${class}_SSH_KEY_2")" "$cmd2"; fi
}

stop_class() {
    # stop_class <CLASS> <variant>
    local class="$1" v="${2:-default}" cmd cmd2
    cmd=$(get_var "$(variant_var "$class" "$v" STOP_CMD)" "$(get_var "${class}_STOP_CMD")")
    cmd2=$(get_var "$(variant_var "$class" "$v" STOP_CMD_2)" "$(get_var "${class}_STOP_CMD_2")")
    if [ -n "$cmd" ]; then run_remote "$(get_var "${class}_HOST")" "$(get_var "${class}_SSH_KEY")" "$cmd"; fi
    if [ -n "$cmd2" ]; then run_remote "$(get_var "${class}_HOST_2")" "$(get_var "${class}_SSH_KEY_2")" "$cmd2"; fi
}

stop_normal() { stop_class NORMAL "${RUNNING_NORMAL:-default}"; }
stop_flashcrowd() { stop_class FLASHCROWD "${RUNNING_FLASHCROWD:-default}"; }
stop_attack() { stop_class ATTACK "${RUNNING_ATTACK:-default}"; }

variant_description() {
    # variant_description <CLASS> <variant>
    local d
    d=$(get_var "$(variant_var "$1" "$2" DESC)")
    printf '%s' "${d//[$'\t\n']/ }"
}

# count_sources <host> <key> <file>: number of non-empty lines in a source
# address file on a generator host, empty if it cannot be read.
count_sources() {
    run_remote "$1" "$2" "grep -c . '$3'" 2>/dev/null | tr -d '[:space:]'
}

# The gateway forwards traffic to the targets out of the egress interface. If
# that interface has no IPv4 address the gateway cannot forward, the targets
# receive nothing, and every phase of the session would measure that failure
# and not the system. Seen on 2026-09-19, when a NetworkManager profile kept
# taking the interface down.
check_egress_interface() {
    [ -n "$EGRESS_IFACE" ] || return 0
    if ! $GW_SSH "ip -4 -br addr show dev '$EGRESS_IFACE' | grep -q ' [0-9]'" >/dev/null 2>&1; then
        log "ERROR: $EGRESS_IFACE has no IPv4 address on the gateway, so it cannot forward to the targets. Fix that before running."
        exit 1
    fi
    log "Egress interface $EGRESS_IFACE has an address"
}

# The attack's spread of source addresses decides how much entropy separates
# it from Normal and Flash Crowd traffic, so the count is checked against the
# configured range before anything runs, and recorded with each run.
ATTACK_SOURCES=""
check_attack_sources() {
    if [ -n "$ATTACK_SOURCE_FILE" ]; then
        ATTACK_SOURCES=$(count_sources "$ATTACK_HOST" "$ATTACK_SSH_KEY" "$ATTACK_SOURCE_FILE")
        if ! [[ "$ATTACK_SOURCES" =~ ^[0-9]+$ ]]; then
            log "ERROR: could not count the attack source addresses in $ATTACK_SOURCE_FILE on $ATTACK_HOST"
            exit 1
        fi
        if [ "$ATTACK_SOURCES" -lt "$ATTACK_SOURCES_MIN" ] || [ "$ATTACK_SOURCES" -gt "$ATTACK_SOURCES_MAX" ]; then
            log "ERROR: $ATTACK_SOURCE_FILE holds $ATTACK_SOURCES addresses, outside the allowed $ATTACK_SOURCES_MIN to $ATTACK_SOURCES_MAX"
            exit 1
        fi
        log "Attack source addresses: $ATTACK_SOURCES"
    fi
    NORMAL_SOURCES=""; FLASHCROWD_SOURCES=""
    if [ -n "$NORMAL_SOURCE_FILE" ]; then NORMAL_SOURCES=$(count_sources "$NORMAL_HOST" "$NORMAL_SSH_KEY" "$NORMAL_SOURCE_FILE"); fi
    if [ -n "$FLASHCROWD_SOURCE_FILE" ]; then FLASHCROWD_SOURCES=$(count_sources "$FLASHCROWD_HOST" "$FLASHCROWD_SSH_KEY" "$FLASHCROWD_SOURCE_FILE"); fi
}

# --- System-health sampling on the gateway itself: CPU time, context
# switches, and memory for both services, system wide CPU, and network
# interface counters, polled independently of the traffic phases so a
# session shows whether the pipeline stayed healthy under load as well as
# what it classified. Runs the whole run, started before Phase 1 and stopped
# only once all phases are done. ---
SAMPLER_LOCAL="$(dirname "$0")/benchmark_system_sampler.sh"
SAMPLER_REMOTE="$REMOTE_DIR/system_sampler.sh"
SAMPLER_PIDFILE="$REMOTE_DIR/system_sampler.pid"
SAMPLER_OUT_REMOTE="$REMOTE_DIR/system_samples.csv"
SAMPLER_LOG_REMOTE="$REMOTE_DIR/system_sampler.log"
start_system_sampling() {
    if ! $GW_SCP "$SAMPLER_LOCAL" "$GATEWAY_HOST:$SAMPLER_REMOTE" >/dev/null 2>&1; then
        log "WARNING: could not copy $SAMPLER_LOCAL to the gateway, system-health sampling will be skipped"
        return
    fi
    $GW_SSH "chmod +x $SAMPLER_REMOTE; nohup $SAMPLER_REMOTE $SYSTEM_SAMPLE_INTERVAL_SECS $STAGE1_UNIT $STAGE2_UNIT $SAMPLER_OUT_REMOTE '$INGRESS_IFACE' '$EGRESS_IFACE' >$SAMPLER_LOG_REMOTE 2>&1 & echo \$! > $SAMPLER_PIDFILE" >/dev/null 2>&1
    log "system-health sampler started (interval ${SYSTEM_SAMPLE_INTERVAL_SECS}s)"
}
stop_system_sampling() {
    $GW_SSH "kill \$(cat $SAMPLER_PIDFILE 2>/dev/null) 2>/dev/null; pkill -f '[s]ystem_sampler.sh' 2>/dev/null" >/dev/null 2>&1
    log "system-health sampler stopped"
}

# --- Capture mode switching and rollback. The gateway side of this is
# benchmark_mode_switch.sh; every timestamp it records comes from the
# gateway's own clock. ---
SWITCHED=0
ORIGINAL_MODE=""

# The helper, the sampler, and their output files live in a directory only
# root can enter, and never in /tmp, where another account on the gateway could
# swap a file between the copy and the run. The directory is checked each time.
ensure_remote_dir() {
    if ! $GW_SSH "umask 077; mkdir -p -m 700 '$REMOTE_DIR' && [ -d '$REMOTE_DIR' ] && [ ! -L '$REMOTE_DIR' ] && [ \"\$(stat -c %u '$REMOTE_DIR')\" = 0 ] && [ \"\$(stat -c %a '$REMOTE_DIR')\" = 700 ]" >/dev/null 2>&1; then
        log "ERROR: $REMOTE_DIR on the gateway is missing, not a real directory, or not a root owned 700 directory"
        exit 1
    fi
}

install_helper() {
    ensure_remote_dir
    if ! $GW_SCP "$HELPER_LOCAL" "$GATEWAY_HOST:$HELPER_REMOTE" >/dev/null 2>&1; then
        log "ERROR: could not copy $HELPER_LOCAL to the gateway"
        exit 1
    fi
    $GW_SSH "chmod +x $HELPER_REMOTE" >/dev/null 2>&1
}

verify_gateway() {
    # verify_gateway <expected-mode-or-empty> <out-file>
    $GW_SSH "$HELPER_REMOTE verify $STAGE1_UNIT $STAGE2_UNIT '$INGRESS_IFACE' '$1' $BLOCKLIST_SET $RATELIMIT_SET" > "$2" 2>&1
    if grep -q "result=fail" "$2"; then
        log "WARNING: gateway verification reported a failure, see $2"
    fi
}

switch_mode() {
    # switch_mode <mode> <run-number> <run-dir>
    local mode="$1" run="$2" dir="$3"
    local baseline="$BASELINE_DIR/flod_benchmark_${mode}_run${run}.json"
    log "Switching Stage 1 to the $mode backend (fresh baseline file $baseline)..."
    SWITCHED=1
    $GW_SSH "$HELPER_REMOTE switch $mode $baseline $STAGE1_UNIT $REMOTE_DIR/mode_switch.txt $STAGE2_UNIT $BLOCKLIST_SET $RATELIMIT_SET"
    $GW_SCP "$GATEWAY_HOST:$REMOTE_DIR/mode_switch.txt" "$dir/mode_switch.txt" >/dev/null 2>&1
    verify_gateway "$mode" "$dir/mode_verify.txt"
    log "Switch to $mode: $(grep -E '^downtime_to_first_status_secs=' "$dir/mode_switch.txt" | tr '\n' ' ')"
}

do_rollback() {
    # do_rollback <out-prefix>
    local prefix="$1"
    log "Rolling Stage 1 back to the original configuration (mode: ${ORIGINAL_MODE:-unknown})..."
    $GW_SSH "$HELPER_REMOTE rollback $STAGE1_UNIT $REMOTE_DIR/rollback.txt '$ORIGINAL_MODE' '$BASELINE_DIR' $STAGE2_UNIT $BLOCKLIST_SET $RATELIMIT_SET"
    $GW_SCP "$GATEWAY_HOST:$REMOTE_DIR/rollback.txt" "${prefix}_switch.txt" >/dev/null 2>&1
    verify_gateway "$ORIGINAL_MODE" "${prefix}_verify.txt"
    SWITCHED=0
    log "Rollback: $(grep -E '^(tuning_restore|downtime_to_first_status_secs)=' "${prefix}_switch.txt" | tr '\n' ' ')"
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [ "$SWITCHED" -eq 1 ]; then
        log "Interrupted: stopping generators and restoring the original capture mode"
        stop_normal >/dev/null 2>&1
        stop_flashcrowd >/dev/null 2>&1
        stop_attack >/dev/null 2>&1
        stop_system_sampling >/dev/null 2>&1
        do_rollback "$SESSION_DIR/rollback_emergency"
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# goto_phase <name> <normal 0|1> <flashcrowd 0|1> <attack 0|1>
# Starts or stops only what changed from the previous phase's active set,
# choosing a variant for every class that starts, then marks the phase
# boundary and records which variant of each active class the phase ran.
normal_on=0
flashcrowd_on=0
attack_on=0
VARIANTS_TSV=""
goto_phase() {
    local name="$1" want_normal="$2" want_flashcrowd="$3" want_attack="$4" v

    if [ "$want_normal" -eq 0 ] && [ "$normal_on" -eq 1 ]; then stop_normal; RUNNING_NORMAL=""; fi
    if [ "$want_flashcrowd" -eq 0 ] && [ "$flashcrowd_on" -eq 1 ]; then stop_flashcrowd; RUNNING_FLASHCROWD=""; fi
    if [ "$want_attack" -eq 0 ] && [ "$attack_on" -eq 1 ]; then stop_attack; RUNNING_ATTACK=""; fi

    if [ "$want_normal" -eq 1 ] && [ "$normal_on" -eq 0 ]; then
        v=$(next_variant NORMAL "$NORMAL_STARTS"); NORMAL_STARTS=$((NORMAL_STARTS + 1)); RUNNING_NORMAL="$v"
        log "Starting Normal traffic, variant '$v'"; start_class NORMAL "$v"
    fi
    if [ "$want_flashcrowd" -eq 1 ] && [ "$flashcrowd_on" -eq 0 ]; then
        v=$(next_variant FLASHCROWD "$FLASHCROWD_STARTS"); FLASHCROWD_STARTS=$((FLASHCROWD_STARTS + 1)); RUNNING_FLASHCROWD="$v"
        log "Starting Flash Crowd traffic, variant '$v'"; start_class FLASHCROWD "$v"
    fi
    if [ "$want_attack" -eq 1 ] && [ "$attack_on" -eq 0 ]; then
        v=$(next_variant ATTACK "$ATTACK_STARTS"); ATTACK_STARTS=$((ATTACK_STARTS + 1)); RUNNING_ATTACK="$v"
        log "Starting attack traffic, type '$v'"; start_class ATTACK "$v"
    fi

    normal_on="$want_normal"; flashcrowd_on="$want_flashcrowd"; attack_on="$want_attack"
    mark_phase "$name"
    if [ "$normal_on" -eq 1 ]; then printf '%s\tnormal\t%s\t%s\n' "$name" "$RUNNING_NORMAL" "$(variant_description NORMAL "$RUNNING_NORMAL")" >> "$VARIANTS_TSV"; fi
    if [ "$flashcrowd_on" -eq 1 ]; then printf '%s\tflashcrowd\t%s\t%s\n' "$name" "$RUNNING_FLASHCROWD" "$(variant_description FLASHCROWD "$RUNNING_FLASHCROWD")" >> "$VARIANTS_TSV"; fi
    if [ "$attack_on" -eq 1 ]; then printf '%s\tattack\t%s\t%s\n' "$name" "$RUNNING_ATTACK" "$(variant_description ATTACK "$RUNNING_ATTACK")" >> "$VARIANTS_TSV"; fi
}

stop_all_generators() {
    if [ "$normal_on" -eq 1 ]; then stop_normal; fi
    if [ "$flashcrowd_on" -eq 1 ]; then stop_flashcrowd; fi
    if [ "$attack_on" -eq 1 ]; then stop_attack; fi
    normal_on=0; flashcrowd_on=0; attack_on=0
    RUNNING_NORMAL=""; RUNNING_FLASHCROWD=""; RUNNING_ATTACK=""
}

# One pair of phases per attack type, so every type is measured on every run
# regardless of where the rotation above happens to land: the attack alone,
# then with Normal traffic (where the spread of source addresses shows up in
# entropy). Between types all traffic stops, both ipsets are emptied and
# Stage 2 restarts, so a block from one type cannot shorten the next.
run_attack_sweep() {
    local t
    for t in $(get_var ATTACK_VARIANTS); do
        log "--- Attack type sweep: $t ---"
        stop_all_generators
        mark_phase "gap_$t"
        $GW_SSH "$HELPER_REMOTE reset-enforcement $STAGE2_UNIT $BLOCKLIST_SET $RATELIMIT_SET" >/dev/null 2>&1
        sleep "$TYPE_GAP_SECS"
        FORCE_ATTACK_VARIANT="$t"
        goto_phase "attacker_$t" 0 0 1
        log "Observing attack type $t alone for ${ATTACK_SWEEP_SECS}s..."
        sleep "$ATTACK_SWEEP_SECS"
        goto_phase "normal_attacker_$t" 1 0 1
        log "Observing attack type $t with Normal traffic for ${ATTACK_SWEEP_SECS}s..."
        sleep "$ATTACK_SWEEP_SECS"
        FORCE_ATTACK_VARIANT=""
    done
}

# wait_for_warmup <journal since>: waits until Stage 1 reports a finished
# warm-up or a restored baseline since the given time. Sets WARM_OK and
# WARM_SECS.
WARM_OK=0
WARM_SECS=0
wait_for_warmup() {
    local since="$1" elapsed=0
    WARM_OK=0
    while [ "$elapsed" -lt "$WARMUP_TIMEOUT_SECS" ]; do
        sleep 10
        elapsed=$((elapsed + 10))
        if $GW_SSH "journalctl -u $STAGE1_UNIT --no-pager --since '$since' 2>/dev/null | grep -qE 'warm-up complete|restored baseline'"; then
            WARM_OK=1
            break
        fi
    done
    WARM_SECS="$elapsed"
}

# run_calibration <mode> <run-dir>: runs scripts/calibrate.py on the gateway
# under this run's Normal traffic, as part of the warm-up stage and before any
# measured phase. calibrate.py only measures here. It is never allowed to write
# tuning.env itself, because it would replace the whole file and drop the
# capture mode and baseline path this run depends on, so with CALIBRATE=apply
# the helper adds the derived floors to the existing tuning line, restarts the
# sensor under timing, and the run waits for the baseline again. Everything is
# written to calibration.txt, calibration.log and calibration_apply.txt.
CALIBRATE_LOCAL="$(dirname "$0")/calibrate.py"
CALIBRATE_REMOTE="$REMOTE_DIR/calibrate.py"
FLOORS_LINE_RE='^--rate-sigma-floor [0-9]+(\.[0-9]+)?( --entropy-sigma-floor [0-9]+(\.[0-9]+)?)?( --entropy-sigma-ceiling [0-9]+(\.[0-9]+)?)?$'
run_calibration() {
    local mode="$1" dir="$2" status="failed" rc=0 started ended flags="" apply_since rewarm_ok=0 rewarm_secs=0
    log "Calibrating the sigma floors under this run's Normal traffic ($CALIBRATE, $CALIBRATE_WINDOWS windows per target, up to $CALIBRATE_TIMEOUT_MINS minutes)..."
    if ! $GW_SCP "$CALIBRATE_LOCAL" "$GATEWAY_HOST:$CALIBRATE_REMOTE" >/dev/null 2>&1; then
        log "WARNING: could not copy calibrate.py to the gateway, skipping calibration"
        printf 'mode=%s\nstatus=skipped\nreason=copy failed\n' "$CALIBRATE" > "$dir/calibration.txt"
        return
    fi
    started=$(date +%s)
    $GW_SSH "python3 $CALIBRATE_REMOTE --windows $CALIBRATE_WINDOWS --timeout $CALIBRATE_TIMEOUT_MINS --partial --auto-debug" > "$dir/calibration.log" 2>&1
    rc=$?
    ended=$(date +%s)
    flags=$(tr '\r' '\n' < "$dir/calibration.log" | sed -n '/^Recommended, covering every target:/{n;s/^ *//;p;q}')
    if [ "$rc" -eq 0 ] && [[ "$flags" =~ $FLOORS_LINE_RE ]]; then
        status="measured"
        if [ "$CALIBRATE" = apply ]; then
            $GW_SSH "$HELPER_REMOTE apply-floors '$flags' $STAGE1_UNIT $REMOTE_DIR/calibration_apply.txt $mode" >/dev/null 2>&1
            $GW_SCP "$GATEWAY_HOST:$REMOTE_DIR/calibration_apply.txt" "$dir/calibration_apply.txt" >/dev/null 2>&1
            apply_since=$(sed -n 's/^t_started=//p' "$dir/calibration_apply.txt")
            if [ -n "$apply_since" ]; then
                log "Floors applied ($flags). Waiting for the baseline after the restart..."
                wait_for_warmup "@${apply_since%.*}"
                rewarm_ok="$WARM_OK"; rewarm_secs="$WARM_SECS"
                status="applied"
            else
                log "WARNING: the helper did not report the floors restart, treating calibration as failed"
                status="failed"
            fi
        fi
    else
        log "WARNING: calibration did not produce usable floors (exit $rc), the run continues with the floors already in force"
        flags=""
    fi
    {
        echo "mode=$CALIBRATE"
        echo "status=$status"
        echo "exit_code=$rc"
        echo "windows_requested=$CALIBRATE_WINDOWS"
        echo "timeout_mins=$CALIBRATE_TIMEOUT_MINS"
        echo "duration_secs=$((ended - started))"
        echo "recommended_flags=$flags"
        echo "rewarm_ok=$rewarm_ok"
        echo "rewarm_secs=$rewarm_secs"
    } > "$dir/calibration.txt"
    log "Calibration $status in $((ended - started))s"
}

# run_session <mode> <run-number> <run-dir>: the seven phase set against
# whichever backend Stage 1 is currently running.
run_session() {
    local mode="$1" run="$2" dir="$3"
    PHASES_FILE="$dir/phase_boundaries.tsv"
    FIREWALL_TSV="$dir/firewall_counters.tsv"
    : > "$PHASES_FILE"
    : > "$FIREWALL_TSV"
    VARIANTS_TSV="$dir/traffic_variants.tsv"
    : > "$VARIANTS_TSV"
    normal_on=0; flashcrowd_on=0; attack_on=0
    NORMAL_STARTS=0; FLASHCROWD_STARTS=0; ATTACK_STARTS=0
    RUNNING_NORMAL=""; RUNNING_FLASHCROWD=""; RUNNING_ATTACK=""
    FORCE_ATTACK_VARIANT=""
    RUN_INDEX="$run"

    log "=== FLOD live benchmark: $mode backend, run $run ==="
    log "Targets: $TARGET_IPS"
    mark_phase "session_start"
    start_system_sampling

    log "--- Warm-up stage: Normal traffic, warm-up, and calibration ---"
    goto_phase "warmup" 1 0 0

    log "Waiting for warm-up (up to ${WARMUP_TIMEOUT_SECS}s)..."
    local warmup_start warmed elapsed
    warmup_start=$(awk -F'\t' '$1=="warmup"{print $2}' "$PHASES_FILE")
    warmup_start="${warmup_start%.*}"
    wait_for_warmup "$warmup_start"
    warmed="$WARM_OK"; elapsed="$WARM_SECS"
    if [ "$warmed" -eq 1 ]; then
        log "warm-up complete after ~${elapsed}s"
    else
        log "WARNING: no warm-up completion seen after ${WARMUP_TIMEOUT_SECS}s, proceeding anyway"
    fi
    if [ "$CALIBRATE" != off ]; then
        run_calibration "$mode" "$dir"
    fi
    {
        echo "mode=$mode"
        echo "run=$run"
        echo "warmed=$warmed"
        echo "warmup_secs=$elapsed"
        echo "targets=$TARGET_IPS"
        echo "ingress_iface=$INGRESS_IFACE"
        echo "egress_iface=$EGRESS_IFACE"
        echo "original_mode=$ORIGINAL_MODE"
        echo "attack_sources=$ATTACK_SOURCES"
        echo "normal_sources=$NORMAL_SOURCES"
        echo "flashcrowd_sources=$FLASHCROWD_SOURCES"
        echo "normal_variants=$(get_var NORMAL_VARIANTS default)"
        echo "flashcrowd_variants=$(get_var FLASHCROWD_VARIANTS default)"
        echo "attack_variants=$(get_var ATTACK_VARIANTS default)"
        echo "attack_sweep_secs=$ATTACK_SWEEP_SECS"
        echo "calibrate=$CALIBRATE"
    } > "$dir/run_info.txt"

    log "--- Phase 1: Normal ---"
    goto_phase "normal" 1 0 0
    log "Observing Normal for ${NORMAL_SECS}s..."
    sleep "$NORMAL_SECS"

    log "--- Phase 2: Flash Crowd ---"
    goto_phase "flash_crowd" 0 1 0
    log "Observing Flash Crowd for ${FLASHCROWD_SECS}s..."
    sleep "$FLASHCROWD_SECS"

    log "--- Phase 3: Attacker ---"
    goto_phase "attacker" 0 0 1
    log "Observing Attacker for ${ATTACK_SECS}s..."
    sleep "$ATTACK_SECS"

    log "--- Phase 4: Normal + Flash Crowd ---"
    goto_phase "normal_flashcrowd" 1 1 0
    log "Observing Normal + Flash Crowd for ${PAIR_SECS}s..."
    sleep "$PAIR_SECS"

    log "--- Phase 5: Normal + Attacker ---"
    goto_phase "normal_attacker" 1 0 1
    log "Observing Normal + Attacker for ${PAIR_SECS}s..."
    sleep "$PAIR_SECS"

    log "--- Phase 6: Flash Crowd + Attacker ---"
    goto_phase "flashcrowd_attacker" 0 1 1
    log "Observing Flash Crowd + Attacker for ${PAIR_SECS}s..."
    sleep "$PAIR_SECS"

    log "--- Phase 7: All three ---"
    goto_phase "all_three" 1 1 1
    log "Observing all three for ${ALL_THREE_SECS}s..."
    sleep "$ALL_THREE_SECS"

    if [ "$ATTACK_SWEEP_SECS" -gt 0 ] && [ -n "$(get_var ATTACK_VARIANTS)" ]; then
        run_attack_sweep
    fi

    log "--- Stopping all traffic ---"
    stop_all_generators
    stop_system_sampling
    mark_phase "session_end"

    local session_start
    session_start=$(awk -F'\t' '$1=="session_start"{print $2}' "$PHASES_FILE")
    session_start="${session_start%.*}"

    log "--- Capturing logs and firewall state ---"
    $GW_SSH "journalctl -u $STAGE1_UNIT --no-pager -o short-precise --since '$session_start'" > "$dir/stage1.log" 2>&1
    $GW_SSH "journalctl -u $STAGE2_UNIT --no-pager -o short-precise --since '$session_start'" > "$dir/stage2.log" 2>&1
    $GW_SSH "ipset list $BLOCKLIST_SET; echo; ipset list $RATELIMIT_SET" > "$dir/firewall.log" 2>&1
    $GW_SSH "cat $SAMPLER_OUT_REMOTE 2>/dev/null" > "$dir/system_samples.csv" 2>&1
    $GW_SSH "getconf CLK_TCK" > "$dir/clk_tck.txt" 2>&1
    $GW_SSH "rm -f $SAMPLER_REMOTE $SAMPLER_OUT_REMOTE $SAMPLER_PIDFILE $SAMPLER_LOG_REMOTE $CALIBRATE_REMOTE $REMOTE_DIR/calibration_apply.txt" >/dev/null 2>&1
    log "=== $mode run $run complete. Logs in $dir ==="
}

# --- Main ---
log "=== FLOD live benchmark starting: backends '$CAPTURE_MODES', $RUNS_PER_MODE run(s) each ==="
install_helper
check_egress_interface
check_attack_sources
verify_gateway "" "$SESSION_DIR/original_state.txt"
ORIGINAL_MODE=$(sed -n 's/^check=capture_mode result=info detail=//p' "$SESSION_DIR/original_state.txt")
[ "$ORIGINAL_MODE" = "unknown" ] && ORIGINAL_MODE=""
log "Gateway is running the '${ORIGINAL_MODE:-unknown}' backend before the benchmark"

for mode in $CAPTURE_MODES; do
    run=1
    while [ "$run" -le "$RUNS_PER_MODE" ]; do
        run_dir="$SESSION_DIR/${mode}_run${run}"
        mkdir -p "$run_dir"
        switch_mode "$mode" "$run" "$run_dir"
        run_session "$mode" "$run" "$run_dir"
        run=$((run + 1))
    done
done

do_rollback "$SESSION_DIR/rollback"

log "=== Session complete. Results in $SESSION_DIR ==="
log "Running analysis..."
python3 "$(dirname "$0")/analyze_live_benchmark.py" "$SESSION_DIR" | tee "$SESSION_DIR/report.txt"
