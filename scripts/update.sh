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

# Toolchain discovery, used by the Rust and eBPF steps below.
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib-toolchain.sh"
load_cargo_env

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-toolchain-update) UPDATE_TOOLCHAIN=false; shift ;;
        --no-service-restart)  RESTART_SERVICE=false; shift ;;
        --help|-h)
            grep '^#' "$0" | head -30 | sed 's/^# \?//'
            exit 0 ;;
        *) error "Unknown argument: $1" ;;
    esac
done

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
# Update the Rust toolchain (optional)
# =============================================================================
if $UPDATE_TOOLCHAIN; then
    info "Updating Rust toolchain..."
    # Source the cargo env in case we're running in a minimal shell.
    # shellcheck source=/dev/null
    [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

    if command -v rustup &>/dev/null; then
        rustup update stable 2>&1
        success "Rust toolchain updated: $(rustc --version)"
    elif [[ -f "$BPF_OBJECT_DIR/ddos-stage1.o" ]]; then
        # This deployment uses the kernel backend, which needs a nightly
        # toolchain to rebuild. Without rustup that is impossible, so install
        # it rather than silently shipping a stale object.
        info "rustup not found but the kernel backend is installed. Installing rustup..."
        if ensure_rustup; then
            rustup update stable &>/dev/null || true
            success "rustup installed: $(rustc --version)"
        else
            warn "Could not install rustup. The eBPF object cannot be rebuilt."
        fi
    else
        warn "rustup not found. Skipping toolchain update (using existing compiler)."
    fi
else
    info "Toolchain update skipped (--no-toolchain-update)."
fi

# =============================================================================
# Rebuild Stage 1
# =============================================================================
info "Rebuilding Stage 1 in release mode..."

if [[ ! -d "$PROJECT_DIR" ]]; then
    error "Stage 1 source directory not found at: $PROJECT_DIR"
fi

# Source cargo env again in case we are in a fresh root shell.
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

cd "$PROJECT_DIR"
RUSTFLAGS="-C target-cpu=native" cargo build --release 2>&1
success "Build complete."

# This script runs as root, so everything it just wrote under target/ is root
# owned. Building from a working copy would then break every later non root
# cargo build with a permission error. Hand the tree back to whoever invoked
# sudo. Only applies when running from a checkout, not from an unpacked copy.
if [[ -n "${SUDO_USER:-}" ]] && id -u "$SUDO_USER" &>/dev/null; then
    for tree in "$PROJECT_DIR/target" "$(dirname "$SCRIPT_DIR")/stage1-ebpf/target"; do
        [[ -d "$tree" ]] || continue
        chown -R "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$tree" 2>/dev/null || true
    done
    info "Build artefacts returned to $SUDO_USER."
fi

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
        [[ -f "$f" ]] || continue
        install -o root -g root -m 644 "$f" "$STAGE2_INSTALL_DIR/$(basename "$f")"
    done
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
    # this is a no-op on a second run.
    install -d -o root -g root -m 700 "$STAGE2_STATE_DIR"
    for f in stage2.db whitelist.json shared_ips.json victims.json \
             enforcement_config.json alerts_config.json stage2.log \
             anomalous_capture.csv ddos_rf_model.joblib ddos_if_model.joblib; do
        if [[ -f "$STAGE2_DIR/$f" && ! -f "$STAGE2_STATE_DIR/$f" ]]; then
            mv "$STAGE2_DIR/$f" "$STAGE2_STATE_DIR/$f"
            info "Migrated existing $f to $STAGE2_STATE_DIR."
        fi
    done
    chown -R root:root "$STAGE2_STATE_DIR"

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
install -m 755 "target/release/$BINARY_NAME" "$TMP_BINARY"
mv -f "$TMP_BINARY" "$INSTALL_DIR/$BINARY_NAME"
success "Binary updated: $INSTALL_DIR/$BINARY_NAME"

# =============================================================================
# Rebuild the eBPF object
# =============================================================================
# Only when one is already installed. A deployment on the libpcap backend has
# no toolchain and should not start needing one at update time.
if [[ -f "$BPF_OBJECT_DIR/ddos-stage1.o" ]]; then
    info "Rebuilding the eBPF programs..."
    if bash "$SCRIPT_DIR/build-ebpf.sh" &>/dev/null; then
        install -o root -g root -m 644 \
            "$PROJECT_DIR/src/bpf/ddos-stage1.o" \
            "$BPF_OBJECT_DIR/ddos-stage1.o"
        success "eBPF object updated."
    else
        # Leaving the old object in place would silently run the previous
        # version against a new binary, so say so loudly.
        warn "eBPF rebuild FAILED. The installed object is now older than the"
        warn "binary. Run scripts/build-ebpf.sh for the reason, or start with"
        warn "--capture-mode pcap until it is fixed."
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

echo ""
success "════════════════════════════════════════════"
success " Stage 1 & 2 update complete!              "
success "════════════════════════════════════════════"
echo ""
