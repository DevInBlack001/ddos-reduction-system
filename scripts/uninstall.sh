#!/usr/bin/env bash
# =============================================================================
# uninstall.sh: Stage 1 & 2 Uninstall Script
# =============================================================================
#
# Completely removes Stage 1 & 2 from the system:
#   1. Stops and disables systemd service units for both stages.
#   2. Removes the service unit files.
#   3. Removes the installed Stage 1 binary.
#   4. Removes the Stage 2 Python virtual environment.
#   5. Optionally removes compiled build cache (target/ directory).
#   6. Optionally removes the Rust toolchain (rustup self uninstall).
#   7. Removes the IPC socket file if it exists.
#
# The project source files (stage1/src/ and stage2/) are NOT deleted.
#
# Usage:
#   sudo bash scripts/uninstall.sh [OPTIONS]
#
# Options:
#   --remove-build      Also delete the stage1/target/ build cache
#   --remove-rust       Also uninstall the Rust toolchain via rustup
#   --yes               Skip the confirmation prompt (non-interactive)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
REMOVE_BUILD=false
REMOVE_RUST=false
CONFIRM=true
BINARY_NAME="ddos_stage1"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="ddos-stage1"
SERVICE2_NAME="ddos-stage2"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SERVICE2_FILE="/etc/systemd/system/${SERVICE2_NAME}.service"
SOCKET_FILE="/run/ddos_stage1/stage1.sock"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(dirname "$SCRIPT_DIR")/stage1/target"
STAGE2_DIR="$(dirname "$SCRIPT_DIR")/stage2"
# Where install.sh/update.sh put things from this version onward.
STAGE2_INSTALL_DIR="/opt/flod/stage2"
STAGE2_STATE_DIR="/var/lib/flod"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --remove-build) REMOVE_BUILD=true; shift ;;
        --remove-rust)  REMOVE_RUST=true; shift ;;
        --yes)          CONFIRM=false; shift ;;
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
info "  FLOD System | Stage 1 and 2 Uninstaller   "
info "═══════════════════════════════════════════════════════"
echo ""

# ── Confirmation prompt ───────────────────────────────────────────────────────
if $CONFIRM; then
    warn "This will remove Stage 1 & 2 from your system."
    warn "The following will be deleted:"
    warn "  • $INSTALL_DIR/$BINARY_NAME"
    warn "  • $SERVICE_FILE (if present)"
    warn "  • $SERVICE2_FILE (if present)"
    warn "  • $SOCKET_FILE (if present)"
    warn "  • $STAGE2_INSTALL_DIR (Stage 2 code and virtual environment)"
    warn "  • $STAGE2_STATE_DIR (database, config, trained models)"
    $REMOVE_BUILD && warn "  • $BUILD_DIR (build cache)"
    $REMOVE_RUST  && warn "  • Rust toolchain (~/.cargo and ~/.rustup)"
    echo ""
    read -r -p "Are you sure? (yes/no): " ANSWER
    [[ "$ANSWER" != "yes" ]] && { info "Uninstall cancelled."; exit 0; }
fi

# =============================================================================
# Stop and disable systemd services
# =============================================================================
if command -v systemctl &>/dev/null; then
    for svc in "$SERVICE_NAME" "$SERVICE2_NAME"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            info "Stopping $svc..."
            systemctl stop "$svc"
            success "$svc stopped."
        fi
        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            info "Disabling $svc..."
            systemctl disable "$svc"
            success "$svc disabled."
        fi
    done
else
    info "systemctl not found; skipping service stop."
fi

# =============================================================================
# Clean up Netfilter ipset / iptables rules
# =============================================================================
info "Cleaning up Netfilter rules and ipset list..."
if command -v iptables &>/dev/null; then
    iptables -D INPUT -m set --match-set ddos_blocklist src -j DROP 2>/dev/null || true
    iptables -D FORWARD -m set --match-set ddos_blocklist src -j DROP 2>/dev/null || true
fi
if command -v ipset &>/dev/null; then
    ipset destroy ddos_blocklist 2>/dev/null || true
fi
success "Firewall rules and ipsets cleaned."

# =============================================================================
# Clean up databases and configuration policies
# =============================================================================
info "Cleaning up SQLite database and policy files..."
rm -rf "$STAGE2_STATE_DIR"
# Older installs, from before Stage 2's state moved out of the checkout,
# may still have these sitting beside the source. Cleaned up too so an
# uninstall on one of those hosts is still complete.
rm -f "$STAGE2_DIR/stage2.db" "$STAGE2_DIR/whitelist.json" "$STAGE2_DIR/victims.json" \
      "$STAGE2_DIR/shared_ips.json" "$STAGE2_DIR/enforcement_config.json" \
      "$STAGE2_DIR/alerts_config.json" "$STAGE2_DIR/stage2.log" \
      "$STAGE2_DIR/anomalous_capture.csv" "$STAGE2_DIR/ddos_rf_model.joblib" \
      "$STAGE2_DIR/ddos_if_model.joblib"
rm -rf "/run/ddos_stage1"
success "Database and configurations removed."

# =============================================================================
# Remove systemd unit files
# =============================================================================
RELOAD_NEEDED=false
for svc_file in "$SERVICE_FILE" "$SERVICE2_FILE"; do
    if [[ -f "$svc_file" ]]; then
        info "Removing systemd unit file: $svc_file"
        rm -f "$svc_file"
        RELOAD_NEEDED=true
        success "Unit file $(basename "$svc_file") removed."
    fi
done

if $RELOAD_NEEDED && command -v systemctl &>/dev/null; then
    systemctl daemon-reload
fi

# =============================================================================
# Remove the binary
# =============================================================================
if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
    info "Removing binary: $INSTALL_DIR/$BINARY_NAME"
    # Clear the setcap capability before deleting, to be clean.
    command -v setcap &>/dev/null && setcap -r "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
    rm -f "$INSTALL_DIR/$BINARY_NAME"
    success "Binary removed."
else
    warn "Binary not found at $INSTALL_DIR/$BINARY_NAME (already removed?)."
fi

# =============================================================================
# Detach the eBPF programs and remove the object
# =============================================================================
# Attachments outlive the process. Stopping the service leaves XDP on the
# interface and a clsact qdisc behind, so both are cleared explicitly rather
# than left for the next reboot.
BPF_OBJECT_DIR="/usr/local/lib/ddos_stage1"

if command -v ip &>/dev/null; then
    for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
        if ip link show "$iface" 2>/dev/null | grep -q xdp; then
            info "Detaching XDP from $iface..."
            ip link set dev "$iface" xdp off 2>/dev/null || true
        fi
    done
fi

if command -v tc &>/dev/null; then
    for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
        if tc qdisc show dev "$iface" 2>/dev/null | grep -q clsact; then
            info "Removing the clsact qdisc from $iface..."
            tc qdisc del dev "$iface" clsact 2>/dev/null || true
        fi
    done
fi

if [[ -d "$BPF_OBJECT_DIR" ]]; then
    info "Removing eBPF object directory: $BPF_OBJECT_DIR"
    rm -rf "$BPF_OBJECT_DIR"
    success "eBPF object removed."
fi

# =============================================================================
# Remove the IPC socket file (if a previous run left it behind)
# =============================================================================
if [[ -S "$SOCKET_FILE" ]] || [[ -f "$SOCKET_FILE" ]]; then
    info "Removing IPC socket: $SOCKET_FILE"
    rm -f "$SOCKET_FILE"
    success "Socket file removed."
fi

# =============================================================================
# Remove runtime/state directories and the Stage 1 service account
# =============================================================================
info "Removing runtime and persisted-state directories..."
rm -rf "/run/ddos_stage1"
rm -rf "/var/lib/ddos_stage1"
rm -rf "/etc/ddos_stage1"
rm -rf "/etc/ddos_stage2"
success "Runtime and state directories removed."

if id -u ddos-stage1 &>/dev/null; then
    userdel ddos-stage1 2>/dev/null || warn "Could not remove user ddos-stage1 (may still own other files)."
fi
if getent group ddos-ipc &>/dev/null; then
    groupdel ddos-ipc 2>/dev/null || warn "Could not remove group ddos-ipc (still in use by another account?)."
fi

# =============================================================================
# Remove Stage 2's installed code and virtual environment
# =============================================================================
if [[ -d "$STAGE2_INSTALL_DIR" ]]; then
    info "Removing $STAGE2_INSTALL_DIR..."
    rm -rf "$STAGE2_INSTALL_DIR"
    success "Stage 2 install directory removed."
fi
# Older installs built the venv inside the checkout directly; remove that
# too if present, so an uninstall on one of those hosts is still complete.
# This was already this script's behaviour before the venv moved to
# $STAGE2_INSTALL_DIR, kept as is rather than trying to guess whether a
# given checkout venv came from install.sh or a developer's own setup.
if [[ -d "$STAGE2_DIR/venv" ]]; then
    info "Removing legacy Stage 2 virtual environment in the checkout..."
    rm -rf "$STAGE2_DIR/venv"
    success "Legacy virtual environment removed."
fi

# =============================================================================
# Remove build artefacts (optional)
# =============================================================================
if $REMOVE_BUILD; then
    if [[ -d "$BUILD_DIR" ]]; then
        info "Removing build cache: $BUILD_DIR"
        rm -rf "$BUILD_DIR"
        success "Build cache removed."
    else
        info "No build cache found at $BUILD_DIR."
    fi
else
    info "Build cache kept (use --remove-build to delete $BUILD_DIR)."
fi

# =============================================================================
# Remove Rust toolchain (optional, DESTRUCTIVE)
# =============================================================================
if $REMOVE_RUST; then
    warn "Removing Rust toolchain (rustup self uninstall)..."
    if command -v rustup &>/dev/null; then
        [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
        rustup self uninstall -y
        success "Rust toolchain removed."
    else
        warn "rustup not found; toolchain may have already been removed."
    fi
else
    info "Rust toolchain kept (use --remove-rust to also uninstall rustup)."
fi

echo ""
success "═══════════════════════════════════════════════"
success " Stage 1 & 2 have been uninstalled successfully "
success "═══════════════════════════════════════════════"
echo ""
info "Source files in stage1/src/ and stage2/ have NOT been deleted."
info "Re-install at any time with: sudo bash scripts/install.sh"
echo ""
