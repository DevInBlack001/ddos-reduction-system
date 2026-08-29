#!/usr/bin/env bash
# =============================================================================
# train.sh: model training selector for Stage 2
# =============================================================================
#
# Prompts for the training CSV and which model(s) to train, then dispatches
# to stage2/train.py (RandomForest) and/or stage2/train_isolation_forest.py
# (V7's Isolation Forest). Neither script gains model selection logic of its
# own: the choice lives here, in the wrapper, so each training script stays
# exactly what it already is.
#
# Usage:
#   bash scripts/train.sh                 prompt for everything
#   bash scripts/train.sh --defaults      accept every default, no prompts
#   bash scripts/train.sh -c stage1/training_data.csv -w both
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ── Defaults ──────────────────────────────────────────────────────────────────
CSV_PATH="$PROJECT_ROOT/stage1/training_data.csv"
WHICH="both"
ASSUME_DEFAULTS=false

usage() {
    cat <<EOF

Usage: bash scripts/train.sh [options]

Trains one or both of Stage 2's models against a training CSV. With no
options it asks for each value and offers a default.

Options:
  -c, --csv <PATH>          Training CSV                 [default: $CSV_PATH]
  -w, --which <rf|if|both>  Which model(s) to train       [default: $WHICH]
  -y, --defaults            Accept every default, ask nothing
  -h, --help                Show this message

EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--csv)       CSV_PATH="$2"; shift 2 ;;
        -w|--which)     WHICH="$2"; shift 2 ;;
        -y|--defaults)  ASSUME_DEFAULTS=true; shift ;;
        -h|--help)      usage; exit 0 ;;
        *) usage; error "Unknown argument: $1" ;;
    esac
done

# ── Prompting ─────────────────────────────────────────────────────────────────
ask() {
    local prompt="$1" default="$2" reply
    if $ASSUME_DEFAULTS || [[ ! -t 0 ]]; then
        echo "$default"
        return
    fi
    read -r -p "$(echo -e "  ${BOLD}${prompt}${NC} [${default}]: ")" reply </dev/tty || reply=""
    echo "${reply:-$default}"
}

echo ""
echo -e "${BOLD}FLOD System training selector${NC}"
if $ASSUME_DEFAULTS; then
    info "Using defaults for everything (--defaults)."
else
    info "Press Enter to accept the value in brackets."
fi
echo ""

CSV_PATH=$(ask "Training CSV" "$CSV_PATH")
[[ -f "$CSV_PATH" ]] || error "No file at '$CSV_PATH'. Capture training data first (see docs/training.md)."
# Resolved to an absolute path before the cd into stage2/ below, so a
# relative path given at the prompt (or on argv) still means what the user
# meant, not "relative to stage2/".
CSV_PATH="$(cd "$(dirname "$CSV_PATH")" && pwd)/$(basename "$CSV_PATH")"

while true; do
    WHICH=$(ask "Train which model(s)? (rf, if, or both)" "$WHICH")
    case "${WHICH,,}" in
        rf|if|both) WHICH="${WHICH,,}"; break ;;
        *) echo "    Answer rf, if, or both." >&2 ;;
    esac
done

# A production install (scripts/install.sh) copies Stage 2's code and venv
# into a root-owned /opt/flod/stage2, root-owned so the running root
# service never executes anything an operator's login account could still
# modify, and the running service loads its models from /var/lib/flod, not
# the checkout. Training against that install has to target the same
# locations, or a freshly trained model would silently sit in the checkout
# while the service keeps running the old one.
STAGE2_PROD_DIR="/opt/flod/stage2"
STAGE2_STATE_DIR="/var/lib/flod"
TRAIN_DIR="$PROJECT_ROOT/stage2"

if [[ -x "$STAGE2_PROD_DIR/venv/bin/python3" ]]; then
    if [[ $EUID -ne 0 ]]; then
        error "A production install exists at $STAGE2_PROD_DIR, whose state" \
              "directory ($STAGE2_STATE_DIR) is root owned. Re-run this" \
              "script with sudo to update its models, or run scripts/train.sh" \
              "from a plain checkout with no production install to train" \
              "into the checkout instead."
    fi
    VENV_PYTHON="$STAGE2_PROD_DIR/venv/bin/python3"
    TRAIN_DIR="$STAGE2_PROD_DIR"
    export MODEL_PATH="$STAGE2_STATE_DIR/ddos_rf_model.joblib"
    export IF_MODEL_PATH="$STAGE2_STATE_DIR/ddos_if_model.joblib"
    info "Production install detected: training into $STAGE2_STATE_DIR."
else
    VENV_PYTHON="$PROJECT_ROOT/stage2/venv/bin/python3"
    if [[ ! -x "$VENV_PYTHON" ]]; then
        warn "No Stage 2 virtual environment at $VENV_PYTHON."
        warn "Falling back to the system python3; run scripts/install.sh for a proper venv."
        VENV_PYTHON="python3"
    fi
fi

echo ""
info "CSV      $CSV_PATH"
info "Training $WHICH"
echo ""

cd "$TRAIN_DIR"

if [[ "$WHICH" == "rf" || "$WHICH" == "both" ]]; then
    info "Training the RandomForest (train.py)..."
    "$VENV_PYTHON" train.py "$CSV_PATH"
    success "RandomForest trained."
    echo ""
fi

if [[ "$WHICH" == "if" || "$WHICH" == "both" ]]; then
    info "Training the Isolation Forest (train_isolation_forest.py)..."
    "$VENV_PYTHON" train_isolation_forest.py "$CSV_PATH"
    success "Isolation Forest trained."
    echo ""
fi

success "Done."
