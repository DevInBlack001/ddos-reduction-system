#!/usr/bin/env bash
# =============================================================================
# run.sh: manual runner for Stage 1 and Stage 2
# =============================================================================
#
# For running the system by hand, out of a working copy, without installing it
# as a service. Prompts for every value it needs, so nothing has to be typed on
# the command line, and offers a default for each one.
#
# Every prompt can also be supplied as a flag, in which case that value becomes
# the default the prompt offers. With --defaults it asks nothing at all.
#
# The installed path is scripts/install.sh followed by systemd. This script is
# for development and for demonstrations.
#
# Usage:
#   sudo bash scripts/run.sh                 prompt for everything
#   sudo bash scripts/run.sh --defaults      accept every default, no prompts
#   sudo bash scripts/run.sh -i eth0 -m kernel
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

RUN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$RUN_DIR")"

# ── Defaults ──────────────────────────────────────────────────────────────────
# The interface carrying the default route is a better guess than any fixed
# name, and is usually right on a single homed development box.
detect_interface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

INTERFACE="$(detect_interface)"
INTERFACE="${INTERFACE:-eth0}"
EGRESS_INTERFACE=""
TARGETS=""
CAPTURE_MODE="pcap"
K_MULTIPLIER="2.0"
LOG_LEVEL="info"
MAX_SOURCES=""
MAX_FLOWS=""
MAX_PROTECTED_HOSTS=""
RUN_STAGE2="yes"
SOCKET_PATH="/run/ddos_stage1/stage1.sock"
ASSUME_DEFAULTS=false

usage() {
    cat <<EOF

Usage: sudo bash scripts/run.sh [options]

Runs Stage 1, and optionally Stage 2, from this working copy. With no options
it asks for each value and offers a default. Any value given as a flag becomes
that prompt's default.

Options:
  -i, --interface <IFACE>       Ingress interface            [default: $INTERFACE]
  -e, --egress-interface <IFACE>  Egress interface, enables drop measurement
  -t, --targets <IPs|CIDR>      Protected hosts. A comma separated list, or a
                                subnet such as 192.0.2.0/24
  -m, --capture-mode <MODE>     pcap or kernel               [default: $CAPTURE_MODE]
  -k, --multiplier <VAL>        Anomaly multiplier k         [default: $K_MULTIPLIER]
  -l, --log-level <LEVEL>       RUST_LOG value               [default: $LOG_LEVEL]
      --max-sources <N>         Kernel source table size
      --max-flows <N>           Flow table size, both backends
      --max-protected-hosts <N> Kernel protected host table size
      --stage2 <yes|no>         Also run Stage 2             [default: $RUN_STAGE2]
  -y, --defaults                Accept every default, ask nothing
  -h, --help                    Show this message

EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--interface)          INTERFACE="$2"; shift 2 ;;
        -e|--egress-interface)   EGRESS_INTERFACE="$2"; shift 2 ;;
        -t|--targets)            TARGETS="$2"; shift 2 ;;
        -m|--capture-mode)       CAPTURE_MODE="$2"; shift 2 ;;
        -k|--multiplier)         K_MULTIPLIER="$2"; shift 2 ;;
        -l|--log-level)          LOG_LEVEL="$2"; shift 2 ;;
        --max-sources)           MAX_SOURCES="$2"; shift 2 ;;
        --max-flows)             MAX_FLOWS="$2"; shift 2 ;;
        --max-protected-hosts)   MAX_PROTECTED_HOSTS="$2"; shift 2 ;;
        --stage2)                RUN_STAGE2="$2"; shift 2 ;;
        -y|--defaults)           ASSUME_DEFAULTS=true; shift ;;
        -h|--help)               usage; exit 0 ;;
        *) usage; error "Unknown argument: $1" ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    error "Raw capture and ipset updates both need root. Re-run with sudo."
fi

# ── Prompting ─────────────────────────────────────────────────────────────────
# Reading from the terminal rather than stdin, so the script still works when
# piped. An empty answer keeps the default; that is what makes it possible to
# hold Enter through the whole thing.
ask() {
    local prompt="$1" default="$2" reply
    if $ASSUME_DEFAULTS || [[ ! -t 0 ]]; then
        echo "$default"
        return
    fi
    if [[ -n "$default" ]]; then
        read -r -p "$(echo -e "  ${BOLD}${prompt}${NC} [${default}]: ")" reply </dev/tty || reply=""
        echo "${reply:-$default}"
    else
        read -r -p "$(echo -e "  ${BOLD}${prompt}${NC}: ")" reply </dev/tty || reply=""
        echo "$reply"
    fi
}

ask_yes_no() {
    local prompt="$1" default="$2" reply
    if $ASSUME_DEFAULTS || [[ ! -t 0 ]]; then
        echo "$default"
        return
    fi
    while true; do
        read -r -p "$(echo -e "  ${BOLD}${prompt}${NC} [${default}]: ")" reply </dev/tty || reply=""
        reply="${reply:-$default}"
        case "${reply,,}" in
            y|yes) echo "yes"; return ;;
            n|no)  echo "no";  return ;;
            *) echo "    Answer yes or no." >&2 ;;
        esac
    done
}

echo ""
echo -e "${BOLD}FLOD System manual runner${NC}"
if $ASSUME_DEFAULTS; then
    info "Using defaults for everything (--defaults)."
else
    info "Press Enter to accept the value in brackets."
fi
echo ""

INTERFACE=$(ask "Ingress interface" "$INTERFACE")
[[ -d "/sys/class/net/$INTERFACE" ]] || error "No interface named '$INTERFACE'. Available: $(ls /sys/class/net | tr '\n' ' ')"

EGRESS_INTERFACE=$(ask "Egress interface (blank for none)" "$EGRESS_INTERFACE")
if [[ -n "$EGRESS_INTERFACE" && ! -d "/sys/class/net/$EGRESS_INTERFACE" ]]; then
    error "No interface named '$EGRESS_INTERFACE'."
fi

TARGETS=$(ask "Protected hosts, comma separated or a subnet" "$TARGETS")
[[ -n "$TARGETS" ]] || error "Protected hosts are required. Without them the sensor has nothing to watch."

CAPTURE_MODE=$(ask "Capture mode (pcap or kernel)" "$CAPTURE_MODE")
case "$CAPTURE_MODE" in
    pcap|kernel) ;;
    *) error "Capture mode must be 'pcap' or 'kernel', got '$CAPTURE_MODE'." ;;
esac

K_MULTIPLIER=$(ask "Anomaly multiplier k" "$K_MULTIPLIER")
LOG_LEVEL=$(ask "Log level (info, debug, or a filter)" "$LOG_LEVEL")

# The table sizes are asked for only when they can take effect and only when
# wanted, so the common path stays short.
if [[ "$CAPTURE_MODE" == "kernel" ]]; then
    if [[ "$(ask_yes_no "Change the kernel table sizes?" "no")" == "yes" ]]; then
        MAX_SOURCES=$(ask "  Source table entries" "${MAX_SOURCES:-65536}")
        MAX_FLOWS=$(ask "  Flow table entries" "${MAX_FLOWS:-8192}")
        MAX_PROTECTED_HOSTS=$(ask "  Protected host entries" "${MAX_PROTECTED_HOSTS:-256}")
    fi
fi

RUN_STAGE2=$(ask_yes_no "Also run Stage 2 (classifier, enforcement, dashboard)?" "$RUN_STAGE2")

# ── Resolve what we are going to run ──────────────────────────────────────────
STAGE1_BIN=""
if [[ -x "$PROJECT_ROOT/stage1/target/release/ddos_stage1" ]]; then
    STAGE1_BIN="$PROJECT_ROOT/stage1/target/release/ddos_stage1"
elif [[ -x "$PROJECT_ROOT/stage1/target/debug/ddos_stage1" ]]; then
    STAGE1_BIN="$PROJECT_ROOT/stage1/target/debug/ddos_stage1"
    warn "Using the debug build. Build with 'cargo build --release' for a realistic rate."
elif command -v ddos_stage1 &>/dev/null; then
    STAGE1_BIN="$(command -v ddos_stage1)"
else
    error "No ddos_stage1 binary. Build one with 'cd stage1 && cargo build --release'."
fi

STAGE2_VENV_PYTHON="$PROJECT_ROOT/stage2/venv/bin/python3"
STAGE2_SCRIPT="$PROJECT_ROOT/stage2/stage2.py"
STAGE2_MODEL="$PROJECT_ROOT/stage2/ddos_rf_model.joblib"

if [[ "$RUN_STAGE2" == "yes" ]]; then
    [[ -x "$STAGE2_VENV_PYTHON" ]] || error "No Stage 2 virtual environment at $STAGE2_VENV_PYTHON. Run scripts/install.sh first."
    [[ -f "$STAGE2_SCRIPT" ]]     || error "No Stage 2 entry point at $STAGE2_SCRIPT."
    [[ -f "$STAGE2_MODEL" ]]      || error "No model at $STAGE2_MODEL. Train one with '$STAGE2_VENV_PYTHON $PROJECT_ROOT/stage2/train.py'."
fi

# Targets carrying a prefix are a subnet, anything else is a list. Deciding
# here rather than asking spares one prompt.
if [[ "$TARGETS" == */* ]]; then
    TARGET_FLAG=(--victim-subnet "$TARGETS")
else
    TARGET_FLAG=(--victim-ips "$TARGETS")
fi

STAGE1_ARGS=(
    --interface "$INTERFACE"
    "${TARGET_FLAG[@]}"
    --capture-mode "$CAPTURE_MODE"
    --k "$K_MULTIPLIER"
    --socket "$SOCKET_PATH"
)
[[ -n "$EGRESS_INTERFACE" ]]    && STAGE1_ARGS+=(--egress-interface "$EGRESS_INTERFACE")
[[ -n "$MAX_SOURCES" ]]         && STAGE1_ARGS+=(--max-sources "$MAX_SOURCES")
[[ -n "$MAX_FLOWS" ]]           && STAGE1_ARGS+=(--max-flows "$MAX_FLOWS")
[[ -n "$MAX_PROTECTED_HOSTS" ]] && STAGE1_ARGS+=(--max-protected-hosts "$MAX_PROTECTED_HOSTS")

echo ""
info "Interface     $INTERFACE${EGRESS_INTERFACE:+ (egress $EGRESS_INTERFACE)}"
info "Protected     $TARGETS"
info "Backend       $CAPTURE_MODE"
info "k             $K_MULTIPLIER"
info "Log level     $LOG_LEVEL"
info "Stage 2       $RUN_STAGE2"
echo ""

# ── Teardown ──────────────────────────────────────────────────────────────────
STAGE1_PID=""
STAGE2_PID=""

cleanup() {
    trap - EXIT SIGINT SIGTERM SIGHUP
    echo ""
    info "Stopping."
    [[ -n "$STAGE1_PID" ]] && kill "$STAGE1_PID" 2>/dev/null || true
    [[ -n "$STAGE2_PID" ]] && kill "$STAGE2_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    [[ -S "$SOCKET_PATH" || -f "$SOCKET_PATH" ]] && rm -f "$SOCKET_PATH" || true
    success "Stopped."
}
trap cleanup EXIT SIGINT SIGTERM SIGHUP

# A socket left by a crashed run would be connected to nothing.
if [[ -S "$SOCKET_PATH" || -f "$SOCKET_PATH" ]]; then
    info "Removing a leftover socket at $SOCKET_PATH."
    rm -f "$SOCKET_PATH"
fi

# ── Stage 2 ───────────────────────────────────────────────────────────────────
if [[ "$RUN_STAGE2" == "yes" ]]; then
    info "Starting Stage 2..."
    cd "$PROJECT_ROOT/stage2"
    "$STAGE2_VENV_PYTHON" "$STAGE2_SCRIPT" &
    STAGE2_PID=$!

    info "Waiting for the IPC socket..."
    for _ in $(seq 1 50); do
        [[ -S "$SOCKET_PATH" ]] && break
        # A Stage 2 that died is a faster answer than the timeout.
        kill -0 "$STAGE2_PID" 2>/dev/null || error "Stage 2 exited during startup. Its output is above."
        sleep 0.2
    done
    [[ -S "$SOCKET_PATH" ]] || error "Stage 2 did not create $SOCKET_PATH within 10 seconds."
    success "Stage 2 is listening. Dashboard on port 8000."
else
    info "Stage 2 not started. Stage 1 will retry the socket and keep analysing without it,"
    info "so windows are logged but nothing is classified or enforced."
fi

# ── Stage 1 ───────────────────────────────────────────────────────────────────
info "Starting Stage 1..."
cd "$PROJECT_ROOT/stage1"

# Backgrounded and waited on rather than run in the foreground, so the trap
# above catches Ctrl+C immediately instead of after the binary yields.
RUST_LOG="$LOG_LEVEL" "$STAGE1_BIN" "${STAGE1_ARGS[@]}" &
STAGE1_PID=$!

wait "$STAGE1_PID"
