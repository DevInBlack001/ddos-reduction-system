#!/usr/bin/env bash
# =============================================================================
# update.sh: Stage 1 & 2 Update Script
# =============================================================================
#
# Updates an existing Stage 1 & 2 installation to the latest code in the project
# directory. Does NOT download anything from the internet (except optionally
# updating the Rust toolchain itself).
#
# What this script does:
#   1. Stops the running ddos-stage1 & ddos-stage2 systemd services (if active).
#   2. Optionally updates the Rust toolchain to the latest stable release.
#   3. Rebuilds Stage 1 in release mode.
#   4. Updates Stage 2 Python dependencies inside virtual environment.
#   5. Replaces the installed binary atomically (no downtime window on the fs).
#   6. Reapplies CAP_NET_RAW capability to the new binary.
#   7. Restarts the systemd services.
#
# Usage:
#   sudo bash scripts/update.sh [--no-toolchain-update] [--no-service-restart]
#
# Options:
#   --no-toolchain-update   Skip `rustup update` (use existing compiler)
#   --no-service-restart    Do not restart the systemd service after update
#   --auto-label-interval <DURATION> Systemd time span for confidence gated auto-labeling
#                            job (default: 1h, e.g. 30m, 2h, 1d)
#   --training-csv <PATH>    CSV to retrain the RandomForest and second model
#                            against periodically. No default: there is no safe
#                            universal path, so the retrain timer is only
#                            installed when this is given.
#   --retrain-interval <DURATION> Systemd time span between retraining runs
#                            (default: 7d, e.g. 1d, 3d, 2w). Only takes effect
#                            when --training-csv is given.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
UPDATE_TOOLCHAIN=true
RESTART_SERVICE=true
# Systemd time span for the confidence gated auto-labeling job timer.
AUTO_LABEL_INTERVAL="1h"
# CSV to retrain the RandomForest and second model against. No default: the
# right training data location varies per deployment, so the retrain timer is
# only generated when this is explicitly given, never guessed.
TRAINING_CSV=""
# Systemd time span for the periodic retrain job timer. Only used when
# TRAINING_CSV is given.
RETRAIN_INTERVAL="7d"
BINARY_NAME="ddos_stage1"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="ddos-stage1"
SERVICE2_NAME="ddos-stage2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")/stage1"
STAGE2_DIR="$(dirname "$SCRIPT_DIR")/stage2"
BPF_OBJECT_DIR="/usr/local/lib/ddos_stage1"
SERVICE_DIR="/etc/systemd/system"
# Same root-owned locations install.sh installs into, see its own comment
# on why: Stage 2 runs as root and must not execute code, or load a model,
# from a directory the operator's own login account can still write to.
STAGE2_INSTALL_DIR="/opt/flod/stage2"
STAGE2_STATE_DIR="/var/lib/flod"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-toolchain-update) UPDATE_TOOLCHAIN=false; shift ;;
        --no-service-restart)  RESTART_SERVICE=false; shift ;;
        --auto-label-interval) AUTO_LABEL_INTERVAL="$2"; shift 2 ;;
        --training-csv)        TRAINING_CSV="$2"; shift 2 ;;
        --retrain-interval)    RETRAIN_INTERVAL="$2"; shift 2 ;;
        --help|-h)
            grep '^#' "$0" | head -30 | sed 's/^# \?//'
            exit 0 ;;
        *) error "Unknown argument: $1" ;;
    esac
done

# ── Validate arguments ────────────────────────────────────────────────────────
if ! [[ "$AUTO_LABEL_INTERVAL" =~ ^[0-9]+(s|m|min|h|hr|d|w)$ ]]; then
    error "--auto-label-interval must look like a systemd time span, e.g. 30m, 1h, 6h. Got: '$AUTO_LABEL_INTERVAL'."
fi
if ! [[ "$RETRAIN_INTERVAL" =~ ^[0-9]+(s|m|min|h|hr|d|w)$ ]]; then
    error "--retrain-interval must look like a systemd time span, e.g. 1d, 3d, 2w. Got: '$RETRAIN_INTERVAL'."
fi
if [[ -n "$TRAINING_CSV" ]]; then
    [[ -f "$TRAINING_CSV" ]] || error "No file at '$TRAINING_CSV' (--training-csv)."
fi

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root. Try: sudo bash $0"
fi

echo ""
info "═══════════════════════════════════════════════════════"
info "  FLOD System | Stage 1 and 2 Updater       "
info "═══════════════════════════════════════════════════════"
echo ""

# =============================================================================
# Stop the running services (if systemd is available and services exist)
# =============================================================================
SERVICE1_WAS_ACTIVE=false
SERVICE2_WAS_ACTIVE=false

if command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Stopping $SERVICE_NAME service before update..."
        systemctl stop "$SERVICE_NAME"
        SERVICE1_WAS_ACTIVE=true
        success "$SERVICE_NAME stopped."
    fi
    if systemctl is-active --quiet "$SERVICE2_NAME" 2>/dev/null; then
        info "Stopping $SERVICE2_NAME service before update..."
        systemctl stop "$SERVICE2_NAME"
        SERVICE2_WAS_ACTIVE=true
        success "$SERVICE2_NAME stopped."
    fi
else
    warn "systemctl not found; skipping service stop."
fi

# =============================================================================
# Rebuild Stage 1 and, if the kernel backend is already deployed, its eBPF
# object
# =============================================================================
# Compiling means running cargo against this checkout: build.rs and proc
# macros in any dependency run arbitrary code as whoever invokes cargo, same
# as rustup and the eBPF build. Done as the account that ran git clone, never
# as root, matching install.sh; see scripts/build-stage1.sh for why. This
# script itself never sources lib-toolchain.sh or touches cargo directly.
info "Rebuilding Stage 1..."

if [[ ! -d "$PROJECT_DIR" ]]; then
    error "Stage 1 source directory not found at: $PROJECT_DIR"
fi

BUILD_ARGS=()
if $UPDATE_TOOLCHAIN; then
    BUILD_ARGS+=(--update-toolchain)
else
    info "Toolchain update skipped (--no-toolchain-update)."
fi
# Only rebuilding the eBPF object when one is already installed matches this
# script's original behaviour: a deployment on the libpcap backend has no
# toolchain and should not start needing one at update time.
if [[ -f "$BPF_OBJECT_DIR/ddos-stage1.o" ]]; then
    BUILD_ARGS+=(--with-ebpf)
else
    BUILD_ARGS+=(--no-ebpf)
fi

if [[ -n "${SUDO_USER:-}" ]] && id -u "$SUDO_USER" &>/dev/null; then
    # An install from before this script stopped building as root can have
    # left root-owned files inside the checkout, most visibly the compiled
    # eBPF object under stage1/src/bpf: the unprivileged build below cannot
    # even remove or overwrite those, since deleting a file needs write
    # access to its directory, not just the file. Reclaiming the checkout
    # for the invoking account first is a one-time fix on such a system; on
    # one that was always built this way, every path here is already that
    # account's own, so this is a fast no-op.
    chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" \
        "$PROJECT_DIR" "$(dirname "$SCRIPT_DIR")/stage1-ebpf" 2>/dev/null || true
    sudo -u "$SUDO_USER" -H bash "$SCRIPT_DIR/build-stage1.sh" "${BUILD_ARGS[@]}"
else
    warn "No non-root account to build as: this script was not invoked with"
    warn "sudo from a normal login. Building as root instead, which trusts"
    warn "this checkout's build scripts and every dependency's build code."
    warn "Prefer 'sudo bash scripts/update.sh' from a normal account."
    bash "$SCRIPT_DIR/build-stage1.sh" "${BUILD_ARGS[@]}"
fi

BINARY_PATH="$PROJECT_DIR/target/release/$BINARY_NAME"
[[ -f "$BINARY_PATH" ]] || error "Stage 1 build did not produce $BINARY_PATH."
success "Build complete: $BINARY_PATH"

# =============================================================================
# Update Stage 2: re-copy the code, rebuild the venv, all in the root-owned
# runtime location, never in place in the checkout. Mirrors the equivalent
# section of install.sh; an update has to move an existing checkout-rooted
# install (from before this split existed) onto the new layout too, not
# only refresh one that is already there.
# =============================================================================
if [[ -d "$STAGE2_DIR" ]]; then
    info "Updating Stage 2 in $STAGE2_INSTALL_DIR..."

    install -d -o root -g root -m 755 "$STAGE2_INSTALL_DIR"
    for f in "$STAGE2_DIR"/*.py "$STAGE2_DIR/requirements.txt"; do
        [[ -f "$f" && ! -L "$f" ]] || continue
        install -o root -g root -m 644 "$f" "$STAGE2_INSTALL_DIR/$(basename "$f")"
    done
    # version.json is the project's single source of truth for the release
    # version; config.py checks beside itself first, which is here.
    install -o root -g root -m 644 "$(dirname "$STAGE2_DIR")/version.json" "$STAGE2_INSTALL_DIR/version.json"
    if [[ -d "$STAGE2_DIR/static" ]]; then
        install -d -o root -g root -m 755 "$STAGE2_INSTALL_DIR/static"
        while IFS= read -r -d '' f; do
            rel="${f#"$STAGE2_DIR"/static/}"
            install -D -o root -g root -m 644 "$f" "$STAGE2_INSTALL_DIR/static/$rel"
        done < <(find "$STAGE2_DIR/static" -type f -print0)
    fi
    success "Stage 2 source refreshed in $STAGE2_INSTALL_DIR."

    if ! "$STAGE2_INSTALL_DIR/venv/bin/python" -c "import sys" &>/dev/null; then
        warn "Virtual environment is missing, broken, or moved. Re-creating..."
        python3 -m venv --clear "$STAGE2_INSTALL_DIR/venv"
        chown -R root:root "$STAGE2_INSTALL_DIR/venv"
    fi

    "$STAGE2_INSTALL_DIR/venv/bin/pip" install --upgrade pip
    "$STAGE2_INSTALL_DIR/venv/bin/pip" install -r "$STAGE2_INSTALL_DIR/requirements.txt"

    # WeasyPrint has no Python-level dependency for this, it dlopen()s
    # Pango at runtime, so pip install succeeding is not enough: an
    # existing install upgrading past the version that introduced the
    # PDF report needs this system package once, by hand. Caught here
    # rather than left to surface as a crash loop after this script exits.
    if ! "$STAGE2_INSTALL_DIR/venv/bin/python" -c "from weasyprint import HTML" &>/dev/null; then
        warn "WeasyPrint cannot load Pango. Install your distribution's"
        warn "'pango' (dnf/yum/apk) or 'libpango-1.0-0' (apt) package,"
        warn "then re-run this script or restart ddos-stage2 by hand."
    fi

    # State migration: a pre-existing checkout-rooted install (from before
    # this layout existed) still has its real data sitting in $STAGE2_DIR.
    # Only files present there and absent from the new location move, so
    # this is a no-op on a second run. Model files are deliberately not in
    # this list: joblib.load() deserialises via pickle and can execute
    # arbitrary code on load, so a .joblib sitting in the checkout,
    # writable by whichever account ran git clone, must never be
    # auto-promoted into the path root loads from. See below.
    install -d -o root -g root -m 700 "$STAGE2_STATE_DIR"
    for f in stage2.db whitelist.json shared_ips.json victims.json \
             enforcement_config.json alerts_config.json stage2.log \
             anomalous_capture.csv; do
        if [[ -f "$STAGE2_DIR/$f" && ! -f "$STAGE2_STATE_DIR/$f" ]]; then
            mv "$STAGE2_DIR/$f" "$STAGE2_STATE_DIR/$f"
            info "Migrated existing $f to $STAGE2_STATE_DIR."
        fi
    done
    chown -R root:root "$STAGE2_STATE_DIR"

    for f in ddos_rf_model.joblib ddos_if_model.joblib ddos_gb_model.joblib; do
        if [[ -f "$STAGE2_DIR/$f" && ! -f "$STAGE2_STATE_DIR/$f" ]]; then
            warn "Found $f in the checkout but did not migrate it:" \
                 "a model file is loaded with joblib.load(), which can run" \
                 "arbitrary code, so one sitting in a location the checkout" \
                 "account can write to is not trusted automatically. Train" \
                 "a fresh model with 'sudo scripts/train.sh', which writes" \
                 "directly to $STAGE2_STATE_DIR, or verify $f yourself and" \
                 "copy it to $STAGE2_STATE_DIR/$f as root."
        fi
    done

    info "Updating/migrating administrative database..."
    DB_PATH="$STAGE2_STATE_DIR/stage2.db" \
        "$STAGE2_INSTALL_DIR/venv/bin/python" "$STAGE2_INSTALL_DIR/setup_admin.py"

    # Rewrite the unit unconditionally so a pre-existing unit that still
    # points at the old checkout-rooted layout gets moved onto the new one,
    # not only a fresh install. Left disabled/stopped units alone otherwise;
    # only content is refreshed here, enablement state is not touched.
    if command -v systemctl &>/dev/null; then
        cat > "$SERVICE_DIR/ddos-stage2.service" << EOF
# =============================================================================
# ddos-stage2.service, systemd unit for the DDoS mitigation Stage 2 daemon
# Regenerated by update.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

[Unit]
Description=Adaptive DDoS Mitigation Stage 2 Classifier (Python)
Documentation=https://github.com/DevInBlack001/ddos-reduction-system/wiki
After=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$STAGE2_INSTALL_DIR
ExecStart=/bin/bash -c 'source "$STAGE2_INSTALL_DIR/venv/bin/activate" && exec python3 stage2.py'
Restart=on-failure
RestartSec=5s
Environment="PYTHONUNBUFFERED=1"
Environment="FLOD_STATE_DIR=$STAGE2_STATE_DIR"
Environment="DB_PATH=$STAGE2_STATE_DIR/stage2.db"

[Install]
WantedBy=multi-user.target
EOF

        cat > "$SERVICE_DIR/ddos-stage2-auto-label.service" << EOF
# =============================================================================
# ddos-stage2-auto-label.service, V8's confidence gated labeling job
# Regenerated by update.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

[Unit]
Description=Adaptive DDoS Mitigation Stage 2 Confidence Gated Labeling
Documentation=https://github.com/DevInBlack001/ddos-reduction-system/wiki

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=$STAGE2_INSTALL_DIR
ExecStart=/bin/bash -c 'source "$STAGE2_INSTALL_DIR/venv/bin/activate" && exec python3 auto_label.py'
Environment="FLOD_STATE_DIR=$STAGE2_STATE_DIR"
Nice=10
CPUWeight=20
IOSchedulingClass=idle
EOF

        cat > "$SERVICE_DIR/ddos-stage2-auto-label.timer" << EOF
# =============================================================================
# ddos-stage2-auto-label.timer, runs the labeling job periodically rather
# than as a background thread inside the long-running Stage 2 service.
# Regenerated by update.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

[Timer]
OnBootSec=$AUTO_LABEL_INTERVAL
OnUnitActiveSec=$AUTO_LABEL_INTERVAL
Persistent=true
RandomizedDelaySec=5m

[Install]
WantedBy=timers.target
EOF

        # The retrain timer needs training data to point at, and there is no
        # safe universal default for that path (see auto_label.py's freshness
        # safeguard: a model trained before a row was captured can never
        # auto-label that row, so the RF and second model must be periodically
        # retrained for the feature to keep producing output). Opt-in only,
        # rewritten unconditionally alongside the other units above when given,
        # so a re-run with an updated --training-csv also updates the unit.
        if [[ -n "$TRAINING_CSV" ]]; then
            cat > "$SERVICE_DIR/ddos-stage2-retrain.service" << EOF
# =============================================================================
# ddos-stage2-retrain.service, periodic RandomForest and second-model retrain
# Regenerated by update.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

[Unit]
Description=Adaptive DDoS Mitigation Stage 2 Periodic Model Retrain
Documentation=https://github.com/DevInBlack001/ddos-reduction-system/wiki

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=$STAGE2_INSTALL_DIR
Environment="FLOD_STATE_DIR=$STAGE2_STATE_DIR"
Environment="MODEL_PATH=$STAGE2_STATE_DIR/ddos_rf_model.joblib"
Environment="SECOND_MODEL_PATH=$STAGE2_STATE_DIR/ddos_gb_model.joblib"
ExecStart=/bin/bash -c 'source "$STAGE2_INSTALL_DIR/venv/bin/activate" && python3 train.py "$TRAINING_CSV" && exec python3 train_second_model.py "$TRAINING_CSV"'
Nice=10
CPUWeight=20
IOSchedulingClass=idle
EOF

            cat > "$SERVICE_DIR/ddos-stage2-retrain.timer" << EOF
# =============================================================================
# ddos-stage2-retrain.timer, runs the periodic model retrain job. The RF and
# second model must be retrained periodically or auto_label.py's freshness
# safeguard will permanently refuse to auto-label any newly captured traffic,
# since it always predates a model trained only once at initial setup.
# Regenerated by update.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

[Timer]
OnBootSec=$RETRAIN_INTERVAL
OnUnitActiveSec=$RETRAIN_INTERVAL
Persistent=true
RandomizedDelaySec=5m

[Install]
WantedBy=timers.target
EOF
            success "Systemd timer created for periodic RF/second-model retraining."
            RETRAIN_TIMER_INSTALLED=true
        else
            info "Skipping the retrain timer: no --training-csv given. Pass one to enable periodic RF/second-model retraining."
            RETRAIN_TIMER_INSTALLED=false
        fi

        systemctl daemon-reload
    fi

    success "Stage 2 updated: code and venv in $STAGE2_INSTALL_DIR, state in $STAGE2_STATE_DIR."
fi

# =============================================================================
# Atomic binary replacement
# =============================================================================
info "Replacing binary at $INSTALL_DIR/$BINARY_NAME..."

# Copy to a temp file first, then atomically move it over the old binary.
# This avoids a race window where the binary is partially written.
TMP_BINARY="$(mktemp --tmpdir="$INSTALL_DIR" "$BINARY_NAME.XXXXXX")"
install -m 755 "$BINARY_PATH" "$TMP_BINARY"
mv -f "$TMP_BINARY" "$INSTALL_DIR/$BINARY_NAME"
success "Binary updated: $INSTALL_DIR/$BINARY_NAME"

# =============================================================================
# Install the rebuilt eBPF object
# =============================================================================
# Already rebuilt above, as the unprivileged build account, only when one was
# already installed. Root's job here is just to place the result: a
# deployment on the libpcap backend has no toolchain and should not start
# needing one at update time.
EBPF_OBJ="$PROJECT_DIR/src/bpf/ddos-stage1.o"
if [[ -f "$BPF_OBJECT_DIR/ddos-stage1.o" ]]; then
    if [[ -f "$EBPF_OBJ" ]]; then
        install -o root -g root -m 644 "$EBPF_OBJ" "$BPF_OBJECT_DIR/ddos-stage1.o"
        success "eBPF object updated."
    else
        # Leaving the old object in place would silently run the previous
        # version against a new binary, so say so loudly.
        warn "eBPF rebuild FAILED. The installed object is now older than the"
        warn "binary. Run scripts/build-stage1.sh for the reason, or start"
        warn "with --capture-mode pcap until it is fixed."
    fi
fi

# =============================================================================
# Reapply CAP_NET_RAW capability
# =============================================================================
if command -v setcap &>/dev/null; then
    # The setcap capability is stored in the inode extended attributes.
    # Replacing the binary clears them, we must reapply after every update.
    # The kernel backend also needs to load programs and attach them. The
    # systemd unit grants these ambiently; setcap covers running by hand.
    setcap cap_net_raw,cap_bpf,cap_net_admin,cap_perfmon+ep "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null \
        || setcap cap_net_raw+ep "$INSTALL_DIR/$BINARY_NAME"
    success "Capabilities reapplied."
else
    warn "setcap not found. Run the binary as root."
fi

# =============================================================================
# Restart the services (optional)
# =============================================================================
if $RESTART_SERVICE; then
    if $SERVICE2_WAS_ACTIVE; then
        info "Restarting $SERVICE2_NAME..."
        systemctl start "$SERVICE2_NAME"
        sleep 0.5
    fi
    if $SERVICE1_WAS_ACTIVE; then
        info "Restarting $SERVICE_NAME..."
        systemctl start "$SERVICE_NAME"
        sleep 0.5
    fi

    # Verify status
    if command -v systemctl &>/dev/null; then
        if $SERVICE1_WAS_ACTIVE && ! systemctl is-active --quiet "$SERVICE_NAME"; then
            warn "$SERVICE_NAME failed to start. Check: journalctl -u $SERVICE_NAME -n 20"
        fi
        if $SERVICE2_WAS_ACTIVE && ! systemctl is-active --quiet "$SERVICE2_NAME"; then
            warn "$SERVICE2_NAME failed to start. Check: journalctl -u $SERVICE2_NAME -n 20"
        fi
    fi
fi

info ""
info "To enable the labeling job at boot and start now:"
info "    systemctl enable --now ddos-stage2-auto-label.timer"
if [[ "${RETRAIN_TIMER_INSTALLED:-false}" == true ]]; then
    info "    systemctl enable --now ddos-stage2-retrain.timer"
fi
info ""

echo ""
success "════════════════════════════════════════════"
success " Stage 1 & 2 update complete!              "
success "════════════════════════════════════════════"
echo ""
