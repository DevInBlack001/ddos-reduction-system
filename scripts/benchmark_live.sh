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

GW_SSH="ssh -i $GATEWAY_SSH_KEY -o BatchMode=yes -o ConnectTimeout=10 $GATEWAY_HOST"
GW_SCP="scp -i $GATEWAY_SSH_KEY -o BatchMode=yes -o ConnectTimeout=10"
SESSION_DIR="$OUTPUT_DIR/session_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$SESSION_DIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# Set per run by run_session.
PHASES_FILE=""
FIREWALL_TSV=""

HELPER_LOCAL="$(dirname "$0")/benchmark_mode_switch.sh"
HELPER_REMOTE="/tmp/flod_benchmark_mode_switch.sh"

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

# --- Per traffic type start/stop, one command pair reused across every
# phase that wants it active. A generator that stays active across a phase
# transition (for example Normal running through Normal, then Normal+Flash
# Crowd) is left alone and keeps running. ---
start_normal() {
    if [ -n "${NORMAL_START_CMD:-}" ]; then run_remote "$NORMAL_HOST" "$NORMAL_SSH_KEY" "$NORMAL_START_CMD"; fi
    if [ -n "${NORMAL_START_CMD_2:-}" ]; then run_remote "$NORMAL_HOST_2" "$NORMAL_SSH_KEY_2" "$NORMAL_START_CMD_2"; fi
}
stop_normal() {
    if [ -n "${NORMAL_STOP_CMD:-}" ]; then run_remote "$NORMAL_HOST" "$NORMAL_SSH_KEY" "$NORMAL_STOP_CMD"; fi
    if [ -n "${NORMAL_STOP_CMD_2:-}" ]; then run_remote "$NORMAL_HOST_2" "$NORMAL_SSH_KEY_2" "$NORMAL_STOP_CMD_2"; fi
}
start_flashcrowd() {
    if [ -n "${FLASHCROWD_START_CMD:-}" ]; then run_remote "$FLASHCROWD_HOST" "$FLASHCROWD_SSH_KEY" "$FLASHCROWD_START_CMD"; fi
    if [ -n "${FLASHCROWD_START_CMD_2:-}" ]; then run_remote "$FLASHCROWD_HOST_2" "$FLASHCROWD_SSH_KEY_2" "$FLASHCROWD_START_CMD_2"; fi
}
stop_flashcrowd() {
    if [ -n "${FLASHCROWD_STOP_CMD:-}" ]; then run_remote "$FLASHCROWD_HOST" "$FLASHCROWD_SSH_KEY" "$FLASHCROWD_STOP_CMD"; fi
    if [ -n "${FLASHCROWD_STOP_CMD_2:-}" ]; then run_remote "$FLASHCROWD_HOST_2" "$FLASHCROWD_SSH_KEY_2" "$FLASHCROWD_STOP_CMD_2"; fi
}
start_attack() {
    if [ -n "${ATTACK_START_CMD:-}" ]; then run_remote "$ATTACK_HOST" "$ATTACK_SSH_KEY" "$ATTACK_START_CMD"; fi
}
stop_attack() {
    if [ -n "${ATTACK_STOP_CMD:-}" ]; then run_remote "$ATTACK_HOST" "$ATTACK_SSH_KEY" "$ATTACK_STOP_CMD"; fi
}

# --- System-health sampling on the gateway itself: CPU time, context
# switches, and memory for both services, system wide CPU, and network
# interface counters, polled independently of the traffic phases so a
# session shows whether the pipeline stayed healthy under load as well as
# what it classified. Runs the whole run, started before Phase 1 and stopped
# only once all phases are done. ---
SAMPLER_LOCAL="$(dirname "$0")/benchmark_system_sampler.sh"
SAMPLER_REMOTE="/tmp/flod_benchmark_system_sampler.sh"
SAMPLER_PIDFILE="/tmp/flod_benchmark_system_sampler.pid"
SAMPLER_OUT_REMOTE="/tmp/flod_benchmark_system_samples.csv"
start_system_sampling() {
    if ! $GW_SCP "$SAMPLER_LOCAL" "$GATEWAY_HOST:$SAMPLER_REMOTE" >/dev/null 2>&1; then
        log "WARNING: could not copy $SAMPLER_LOCAL to the gateway, system-health sampling will be skipped"
        return
    fi
    $GW_SSH "chmod +x $SAMPLER_REMOTE; nohup $SAMPLER_REMOTE $SYSTEM_SAMPLE_INTERVAL_SECS $STAGE1_UNIT $STAGE2_UNIT $SAMPLER_OUT_REMOTE '$INGRESS_IFACE' '$EGRESS_IFACE' >/tmp/flod_benchmark_sampler.log 2>&1 & echo \$! > $SAMPLER_PIDFILE" >/dev/null 2>&1
    log "system-health sampler started (interval ${SYSTEM_SAMPLE_INTERVAL_SECS}s)"
}
stop_system_sampling() {
    $GW_SSH "kill \$(cat $SAMPLER_PIDFILE 2>/dev/null) 2>/dev/null; pkill -f '$SAMPLER_REMOTE' 2>/dev/null" >/dev/null 2>&1
    log "system-health sampler stopped"
}

# --- Capture mode switching and rollback. The gateway side of this is
# benchmark_mode_switch.sh; every timestamp it records comes from the
# gateway's own clock. ---
SWITCHED=0
ORIGINAL_MODE=""

install_helper() {
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
    $GW_SSH "$HELPER_REMOTE switch $mode $baseline $STAGE1_UNIT /tmp/flod_mode_switch.txt $STAGE2_UNIT $BLOCKLIST_SET $RATELIMIT_SET"
    $GW_SCP "$GATEWAY_HOST:/tmp/flod_mode_switch.txt" "$dir/mode_switch.txt" >/dev/null 2>&1
    verify_gateway "$mode" "$dir/mode_verify.txt"
    log "Switch to $mode: $(grep -E '^downtime_to_first_status_secs=' "$dir/mode_switch.txt" | tr '\n' ' ')"
}

do_rollback() {
    # do_rollback <out-prefix>
    local prefix="$1"
    log "Rolling Stage 1 back to the original configuration (mode: ${ORIGINAL_MODE:-unknown})..."
    $GW_SSH "$HELPER_REMOTE rollback $STAGE1_UNIT /tmp/flod_rollback.txt '$ORIGINAL_MODE' '$BASELINE_DIR/flod_benchmark_*.json' $STAGE2_UNIT $BLOCKLIST_SET $RATELIMIT_SET"
    $GW_SCP "$GATEWAY_HOST:/tmp/flod_rollback.txt" "${prefix}_switch.txt" >/dev/null 2>&1
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
# then marks the phase boundary.
normal_on=0
flashcrowd_on=0
attack_on=0
goto_phase() {
    local name="$1" want_normal="$2" want_flashcrowd="$3" want_attack="$4"

    if [ "$want_normal" -eq 0 ] && [ "$normal_on" -eq 1 ]; then stop_normal; fi
    if [ "$want_flashcrowd" -eq 0 ] && [ "$flashcrowd_on" -eq 1 ]; then stop_flashcrowd; fi
    if [ "$want_attack" -eq 0 ] && [ "$attack_on" -eq 1 ]; then stop_attack; fi

    if [ "$want_normal" -eq 1 ] && [ "$normal_on" -eq 0 ]; then start_normal; fi
    if [ "$want_flashcrowd" -eq 1 ] && [ "$flashcrowd_on" -eq 0 ]; then start_flashcrowd; fi
    if [ "$want_attack" -eq 1 ] && [ "$attack_on" -eq 0 ]; then start_attack; fi

    normal_on="$want_normal"; flashcrowd_on="$want_flashcrowd"; attack_on="$want_attack"
    mark_phase "$name"
}

# run_session <mode> <run-number> <run-dir>: the seven phase set against
# whichever backend Stage 1 is currently running.
run_session() {
    local mode="$1" run="$2" dir="$3"
    PHASES_FILE="$dir/phase_boundaries.tsv"
    FIREWALL_TSV="$dir/firewall_counters.tsv"
    : > "$PHASES_FILE"
    : > "$FIREWALL_TSV"
    normal_on=0; flashcrowd_on=0; attack_on=0

    log "=== FLOD live benchmark: $mode backend, run $run ==="
    log "Targets: $TARGET_IPS"
    mark_phase "session_start"
    start_system_sampling

    log "--- Phase 1: Normal ---"
    goto_phase "normal" 1 0 0

    log "Waiting for warm-up (up to ${WARMUP_TIMEOUT_SECS}s)..."
    local normal_start warmed=0 elapsed=0
    normal_start=$(awk -F'\t' '$1=="normal"{print $2}' "$PHASES_FILE")
    normal_start="${normal_start%.*}"
    while [ "$elapsed" -lt "$WARMUP_TIMEOUT_SECS" ]; do
        sleep 10
        elapsed=$((elapsed + 10))
        if $GW_SSH "journalctl -u $STAGE1_UNIT --no-pager --since '$normal_start' 2>/dev/null | grep -qE 'warm-up complete|restored baseline'"; then
            log "warm-up complete after ~${elapsed}s"
            warmed=1
            break
        fi
    done
    if [ "$warmed" -eq 0 ]; then
        log "WARNING: no warm-up completion seen after ${WARMUP_TIMEOUT_SECS}s, proceeding anyway"
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
    } > "$dir/run_info.txt"

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

    log "--- Stopping all traffic ---"
    stop_normal
    stop_flashcrowd
    stop_attack
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
    $GW_SSH "rm -f $SAMPLER_REMOTE $SAMPLER_OUT_REMOTE $SAMPLER_PIDFILE /tmp/flod_benchmark_sampler.log" >/dev/null 2>&1
    log "=== $mode run $run complete. Logs in $dir ==="
}

# --- Main ---
log "=== FLOD live benchmark starting: backends '$CAPTURE_MODES', $RUNS_PER_MODE run(s) each ==="
install_helper
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
