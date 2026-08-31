#!/usr/bin/env bash
# =============================================================================
# benchmark_live.sh: the live-traffic counterpart to
# scripts/benchmark_fixed_threshold.py.
# =============================================================================
#
# That script replays an already-captured CSV offline; this one drives real
# traffic at a real, running deployment and reports what the deployed system
# actually did: detection counts, misclassifications, enforcement actions,
# and the resulting firewall state. Where the offline benchmark answers "does
# the trained model generalize," this answers "does the deployed pipeline,
# warm-up, hysteresis, block tiers and all, behave the way that implies."
#
# Traffic generation is deliberately not prescribed here either, matching
# docs/training.md's own stance: this script orchestrates phase timing,
# warm-up detection, log capture, and reporting, but the actual Normal /
# Flash Crowd / Attacker traffic comes from whatever start/stop commands you
# configure, run over SSH on your own generator hosts.
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
: "${MIXED_SECS:=120}"
: "${OUTPUT_DIR:=./benchmark-live-results}"

GW_SSH="ssh -i $GATEWAY_SSH_KEY -o BatchMode=yes -o ConnectTimeout=10 $GATEWAY_HOST"
mkdir -p "$OUTPUT_DIR"
PHASES_FILE="$OUTPUT_DIR/phase_boundaries.tsv"
: > "$PHASES_FILE"

log() { echo "[$(date +%H:%M:%S)] $*"; }
mark_phase() {
    local name="$1"
    local ts
    ts=$($GW_SSH 'date -u +"%Y-%m-%d %H:%M:%S"')
    echo -e "${name}\t${ts}" >> "$PHASES_FILE"
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

log "=== FLOD live benchmark starting ==="
log "Targets: $TARGET_IPS"
mark_phase "session_start"

log "--- Phase 1: Normal ---"
if [ -n "${NORMAL_START_CMD:-}" ]; then
    run_remote "$NORMAL_HOST" "$NORMAL_SSH_KEY" "$NORMAL_START_CMD"
fi
if [ -n "${NORMAL_START_CMD_2:-}" ]; then
    run_remote "$NORMAL_HOST_2" "$NORMAL_SSH_KEY_2" "$NORMAL_START_CMD_2"
fi
mark_phase "normal"

log "Waiting for warm-up (up to ${WARMUP_TIMEOUT_SECS}s)..."
NORMAL_PHASE_START=$(awk -F'\t' '$1=="normal"{print $2}' "$PHASES_FILE")
warmed=0
elapsed=0
while [ "$elapsed" -lt "$WARMUP_TIMEOUT_SECS" ]; do
    sleep 10
    elapsed=$((elapsed + 10))
    if $GW_SSH "journalctl -u $STAGE1_UNIT --no-pager --since '$NORMAL_PHASE_START' 2>/dev/null | grep -q 'warm-up complete'"; then
        log "warm-up complete after ~${elapsed}s"
        warmed=1
        break
    fi
done
if [ "$warmed" -eq 0 ]; then
    log "WARNING: no warm-up completion seen after ${WARMUP_TIMEOUT_SECS}s, proceeding anyway"
fi

log "Observing Normal for ${NORMAL_SECS}s..."
sleep "$NORMAL_SECS"

log "--- Phase 2: Flash Crowd ---"
if [ -n "${NORMAL_STOP_CMD:-}" ]; then run_remote "$NORMAL_HOST" "$NORMAL_SSH_KEY" "$NORMAL_STOP_CMD"; fi
if [ -n "${NORMAL_STOP_CMD_2:-}" ]; then run_remote "$NORMAL_HOST_2" "$NORMAL_SSH_KEY_2" "$NORMAL_STOP_CMD_2"; fi
if [ -n "${FLASHCROWD_START_CMD:-}" ]; then run_remote "$FLASHCROWD_HOST" "$FLASHCROWD_SSH_KEY" "$FLASHCROWD_START_CMD"; fi
if [ -n "${FLASHCROWD_START_CMD_2:-}" ]; then run_remote "$FLASHCROWD_HOST_2" "$FLASHCROWD_SSH_KEY_2" "$FLASHCROWD_START_CMD_2"; fi
mark_phase "flash_crowd"
log "Observing Flash Crowd for ${FLASHCROWD_SECS}s..."
sleep "$FLASHCROWD_SECS"

log "--- Phase 3: Attacker ---"
if [ -n "${FLASHCROWD_STOP_CMD:-}" ]; then run_remote "$FLASHCROWD_HOST" "$FLASHCROWD_SSH_KEY" "$FLASHCROWD_STOP_CMD"; fi
if [ -n "${FLASHCROWD_STOP_CMD_2:-}" ]; then run_remote "$FLASHCROWD_HOST_2" "$FLASHCROWD_SSH_KEY_2" "$FLASHCROWD_STOP_CMD_2"; fi
if [ -n "${ATTACK_START_CMD:-}" ]; then run_remote "$ATTACK_HOST" "$ATTACK_SSH_KEY" "$ATTACK_START_CMD"; fi
mark_phase "attacker"
log "Observing Attacker for ${ATTACK_SECS}s..."
sleep "$ATTACK_SECS"

log "--- Phase 4: Mixed ---"
if [ -n "${ATTACK_STOP_CMD:-}" ]; then run_remote "$ATTACK_HOST" "$ATTACK_SSH_KEY" "$ATTACK_STOP_CMD"; fi
if [ -n "${MIXED_NORMAL_START_CMD:-}" ]; then run_remote "$NORMAL_HOST" "$NORMAL_SSH_KEY" "$MIXED_NORMAL_START_CMD"; fi
if [ -n "${MIXED_NORMAL_START_CMD_2:-}" ]; then run_remote "$NORMAL_HOST_2" "$NORMAL_SSH_KEY_2" "$MIXED_NORMAL_START_CMD_2"; fi
sleep 5
if [ -n "${MIXED_FLASHCROWD_START_CMD:-}" ]; then run_remote "$FLASHCROWD_HOST" "$FLASHCROWD_SSH_KEY" "$MIXED_FLASHCROWD_START_CMD"; fi
if [ -n "${MIXED_ATTACK_START_CMD:-}" ]; then run_remote "$ATTACK_HOST" "$ATTACK_SSH_KEY" "$MIXED_ATTACK_START_CMD"; fi
mark_phase "mixed"
log "Observing Mixed for ${MIXED_SECS}s..."
sleep "$MIXED_SECS"

log "--- Stopping all traffic ---"
if [ -n "${MIXED_NORMAL_STOP_CMD:-}" ]; then run_remote "$NORMAL_HOST" "$NORMAL_SSH_KEY" "$MIXED_NORMAL_STOP_CMD"; fi
if [ -n "${MIXED_NORMAL_STOP_CMD_2:-}" ]; then run_remote "$NORMAL_HOST_2" "$NORMAL_SSH_KEY_2" "$MIXED_NORMAL_STOP_CMD_2"; fi
if [ -n "${MIXED_FLASHCROWD_STOP_CMD:-}" ]; then run_remote "$FLASHCROWD_HOST" "$FLASHCROWD_SSH_KEY" "$MIXED_FLASHCROWD_STOP_CMD"; fi
if [ -n "${MIXED_ATTACK_STOP_CMD:-}" ]; then run_remote "$ATTACK_HOST" "$ATTACK_SSH_KEY" "$MIXED_ATTACK_STOP_CMD"; fi
mark_phase "session_end"

SESSION_START=$(awk -F'\t' '$1=="session_start"{print $2}' "$PHASES_FILE")

log "--- Capturing logs and firewall state ---"
$GW_SSH "journalctl -u $STAGE1_UNIT --no-pager --since '$SESSION_START'" > "$OUTPUT_DIR/stage1.log" 2>&1
$GW_SSH "journalctl -u $STAGE2_UNIT --no-pager --since '$SESSION_START'" > "$OUTPUT_DIR/stage2.log" 2>&1
$GW_SSH "ipset list $BLOCKLIST_SET; echo; ipset list $RATELIMIT_SET" > "$OUTPUT_DIR/firewall.log" 2>&1

log "=== Session complete. Logs in $OUTPUT_DIR ==="
log "Running analysis..."
python3 "$(dirname "$0")/analyze_live_benchmark.py" "$OUTPUT_DIR"
