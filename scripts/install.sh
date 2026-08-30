#!/usr/bin/env bash
# =============================================================================
# install.sh: Stage 1 & 2 Installation Script (Linux/macOS)
# =============================================================================
#
# Supports:
#   • Debian / Ubuntu (apt)
#   • RHEL / Fedora / Rocky / AlmaLinux (dnf / yum)
#   • Alpine Linux (apk)
#
# What this script does:
#   1. Detects the host OS/package manager.
#   2. Installs system dependencies (libpcap, build tools).
#   3. Installs the Rust toolchain via rustup (if not already present).
#   4. Compiles Stage 1 in release mode.
#   5. Installs the binary to /usr/local/bin/ddos_stage1.
#   6. Writes a systemd service unit (Linux only) to allow boot-time autostart.
#
# Usage:
#   sudo bash scripts/install.sh [--interface ens19] [--victim-ips 10.0.0.3,10.0.0.4] [--victim-subnet 10.0.0.0/24]
#
# Options:
#   --interface  <IFACE>     Default capture interface written into the service unit
#   --victim-ips <IPs>       Default list of victim IPs (comma-separated, alias: --victim-ip)
#   --victim-subnet <SUBNET> Default victim subnet CIDR (e.g. 10.0.0.0/24)
#   --exclude-ips <IPs>      Addresses carved out of the above, comma-separated (alias: --exclude-ip)
#   --capture-mode <MODE>    pcap (default) or kernel. 'kernel' uses XDP and TC
#                            and is written into the service unit
#   --no-service             Skip systemd unit installation
#
# Detection tuning, all optional. Anything not given is left out of the unit so
# the sensor's own default applies, which lets a later release improve it:
#   --k <FLOAT>                  Sensitivity multiplier
#   --entropy-sigma-floor <F>    Smallest entropy deviation for the boundary
#   --rate-sigma-floor <F>       Same floor for the rate, in pps
#   --entropy-min-packets <N>    Packets needed before entropy may flag
#   --no-tuning-prompt           Skip the interactive tuning questions
#
# Notes:
#   • Must be run as root (or with sudo) because pcap and systemd require it.
#   • Building Stage 1 is not: it runs as the account sudo was invoked from
#     (via 'sudo -u'), never as root, so cargo, rustup, and every
#     dependency's build code run with that account's privileges. The Rust
#     toolchain is installed into that account's own ~/.cargo, not root's.
#     Only the resulting binary and eBPF object are then installed as root.
#   • Use `sudo setcap cap_net_raw+ep /usr/local/bin/ddos_stage1` after install
#     to run the binary WITHOUT root in production.
#
# Full instructions, including network placement and first login, are in
# the wiki: https://github.com/DevInBlack001/ddos-reduction-system/wiki
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
INTERFACE="br0"
VICTIM_IP=""
VICTIM_IPS=""
VICTIM_SUBNET=""
EXCLUDE_IPS=""
# Which backend the generated unit starts with. pcap by default because it
# works on any interface; the kernel backend additionally needs the compiled
# object and a driver the verifier will attach to.
CAPTURE_MODE="pcap"
INSTALL_SERVICE=true
# Detection tuning. Empty means "not set", and an unset value is left out of
# the unit entirely so the sensor's own default applies. Writing every default
# into ExecStart would freeze today's values, so a later release that improves
# a default would have no effect on an existing install.
TUNE_K=""
TUNE_ENTROPY_SIGMA_FLOOR=""
TUNE_RATE_SIGMA_FLOOR=""
TUNE_ENTROPY_MIN_PACKETS=""
SKIP_TUNING_PROMPT=false
BINARY_NAME="ddos_stage1"
INSTALL_DIR="/usr/local/bin"
SERVICE_DIR="/etc/systemd/system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")/stage1"
# Stage 2 runs as root, so its code and venv must not live somewhere the
# operator's own login account can still write to: anyone who can modify
# the checkout would otherwise get root the next time the service
# restarts, updates, or training reruns. The checkout is a source from
# here on, copied into these root-owned locations, never executed from
# directly by the systemd unit. scripts/run.sh and a developer's own venv
# (see CONTRIBUTING.md) still run straight from the checkout, deliberately:
# that path never crosses a privilege boundary, the operator only ever
# runs it as themselves.
STAGE2_INSTALL_DIR="/opt/flod/stage2"
STAGE2_STATE_DIR="/var/lib/flod"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface)               INTERFACE="$2"; shift 2 ;;
        --victim-ip|--victim-ips)  VICTIM_IPS="$2"; shift 2 ;;
        --victim-subnet)           VICTIM_SUBNET="$2"; shift 2 ;;
        --exclude-ip|--exclude-ips) EXCLUDE_IPS="$2"; shift 2 ;;
        --capture-mode)
            case "$2" in
                pcap|kernel) CAPTURE_MODE="$2" ;;
                *) error "--capture-mode takes 'pcap' or 'kernel', got '$2'." ;;
            esac
            shift 2 ;;
        --k)                       TUNE_K="$2"; shift 2 ;;
        --entropy-sigma-floor)     TUNE_ENTROPY_SIGMA_FLOOR="$2"; shift 2 ;;
        --rate-sigma-floor)        TUNE_RATE_SIGMA_FLOOR="$2"; shift 2 ;;
        --entropy-min-packets)     TUNE_ENTROPY_MIN_PACKETS="$2"; shift 2 ;;
        --no-tuning-prompt)        SKIP_TUNING_PROMPT=true; shift ;;
        --no-service)              INSTALL_SERVICE=false; shift ;;
        --help|-h)
            grep '^#' "$0" | head -40 | sed 's/^# \?//'
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
info "  FLOD System | Stage 1 and 2 Installer     "
info "═══════════════════════════════════════════════════════"
echo ""

# ── Interactive prompts ───────────────────────────────────────────────────────
if [[ -t 0 ]]; then
    # Resolve current target default for the prompt
    CURRENT_TARGET=""
    if [[ -n "$VICTIM_IPS" ]]; then
        CURRENT_TARGET="$VICTIM_IPS"
    elif [[ -n "$VICTIM_SUBNET" ]]; then
        CURRENT_TARGET="$VICTIM_SUBNET"
    fi

    echo -ne "${YELLOW}[INPUT]${NC} Enter the network interface to monitor [default: ${INTERFACE}]: "
    read -r input_iface
    if [[ -n "$input_iface" ]]; then
        INTERFACE="$input_iface"
    fi

    echo -ne "${YELLOW}[INPUT]${NC} Enter the victim IP(s) or subnet (e.g. 10.0.0.3 or 10.0.0.0/24) [default: ${CURRENT_TARGET:-none}]: "
    read -r input_target
    if [[ -n "$input_target" ]]; then
        if [[ "$input_target" == "none" ]]; then
            VICTIM_IPS=""
            VICTIM_SUBNET=""
        elif [[ "$input_target" == *"/"* ]]; then
            VICTIM_SUBNET="$input_target"
            VICTIM_IPS=""
        else
            VICTIM_IPS="$input_target"
            VICTIM_SUBNET=""
        fi
    fi

    echo -ne "${YELLOW}[INPUT]${NC} Enter any IP(s) to exclude from monitoring, comma-separated (e.g. the gateway's own address, if it falls inside a subnet above) [default: ${EXCLUDE_IPS:-none}]: "
    read -r input_exclude
    if [[ -n "$input_exclude" ]]; then
        if [[ "$input_exclude" == "none" ]]; then
            EXCLUDE_IPS=""
        else
            EXCLUDE_IPS="$input_exclude"
        fi
    fi
    echo ""
fi

# =============================================================================
# Detect OS and package manager
# =============================================================================
info "Detecting operating system..."

PKG_MANAGER=""
OS_NAME=""

if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
    OS_NAME="Debian/Ubuntu"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    OS_NAME="RHEL/Fedora"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    OS_NAME="RHEL/CentOS (legacy)"
elif command -v apk &>/dev/null; then
    PKG_MANAGER="apk"
    OS_NAME="Alpine Linux"
else
    error "Unsupported OS: could not find apt, dnf, yum, or apk."
fi

success "Detected OS: $OS_NAME (package manager: $PKG_MANAGER)"

# =============================================================================
# Install system dependencies
# =============================================================================
info "Installing system dependencies..."

install_deps_apt() {
    apt-get update -qq
    # libpcap-dev  : headers and static lib for pcap crate
    # build-essential : gcc, make, linker
    # pkg-config   : lets Cargo find libpcap via pkg-config
    # python3, python3-pip, python3-venv, ipset : for Stage 2
    # libpango-1.0-0 : WeasyPrint has no Python-level rendering dependency,
    # but it dlopen()s Pango at runtime for text shaping in the PDF report
    apt-get install -y --no-install-recommends \
        libpcap-dev \
        build-essential \
        pkg-config \
        curl \
        llvm \
        clang \
        python3 \
        python3-pip \
        python3-venv \
        ipset \
        libpango-1.0-0
}

install_deps_dnf() {
    # libpcap-devel provides the headers and .so needed to compile the pcap crate
    # pango : WeasyPrint dlopen()s it at runtime for PDF report text shaping,
    # it is not something pip install can provide
    dnf install -y \
        libpcap-devel \
        gcc \
        pkg-config \
        curl \
        llvm \
        llvm-devel \
        clang \
        python3 \
        python3-pip \
        ipset \
        pango
}

install_deps_yum() {
    yum install -y \
        libpcap-devel \
        gcc \
        pkgconfig \
        curl \
        llvm \
        llvm-devel \
        clang \
        python3 \
        python3-pip \
        ipset \
        pango
}

install_deps_apk() {
    # Alpine uses musl libc; libpcap-dev provides headers
    # py3-* packages avoid compilation of heavy libraries
    apk add --no-cache \
        libpcap-dev \
        build-base \
        pkgconfig \
        curl \
        bash \
        llvm-dev \
        clang \
        python3 \
        py3-pip \
        ipset \
        py3-pandas \
        py3-numpy \
        py3-scikit-learn \
        py3-joblib \
        pango
}

case "$PKG_MANAGER" in
    apt) install_deps_apt ;;
    dnf) install_deps_dnf ;;
    yum) install_deps_yum ;;
    apk) install_deps_apk ;;
esac

success "System dependencies installed."

# =============================================================================
# Build Stage 1 and its eBPF backend
# =============================================================================
# Compiling means running cargo against this checkout: build.rs and proc
# macros in any dependency run arbitrary code as whoever invokes cargo, and
# rustup, cargo install, and the eBPF build all touch the checkout the same
# way. Done as the account that ran git clone, never as root, so a checkout
# that account can write to cannot use a poisoned dependency or a modified
# build script to run code as root. This script itself never sources
# lib-toolchain.sh or touches cargo directly; scripts/build-stage1.sh does,
# entirely as that unprivileged account. Root's job starts only once real
# files exist on disk to install.
info "Building Stage 1..."

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
    sudo -u "$SUDO_USER" -H bash "$SCRIPT_DIR/build-stage1.sh"
else
    warn "No non-root account to build as: this script was not invoked with"
    warn "sudo from a normal login. Building as root instead, which trusts"
    warn "this checkout's build scripts and every dependency's build code."
    warn "Prefer 'sudo bash scripts/install.sh' from a normal account."
    bash "$SCRIPT_DIR/build-stage1.sh"
fi

BINARY_PATH="$PROJECT_DIR/target/release/$BINARY_NAME"
[[ -f "$BINARY_PATH" ]] || error "Stage 1 build did not produce $BINARY_PATH."
success "Build complete: $BINARY_PATH"

BPF_OBJECT_DIR="/usr/local/lib/ddos_stage1"
EBPF_OBJ="$PROJECT_DIR/src/bpf/ddos-stage1.o"
EBPF_READY=false

if [[ -f "$EBPF_OBJ" ]]; then
    # The sensor loads this into the kernel as a privileged process, so a
    # non root account able to replace it would be running its own kernel
    # code. Root owned directory, not writable by anyone else.
    install -d -o root -g root -m 755 "$BPF_OBJECT_DIR"
    install -o root -g root -m 644 "$EBPF_OBJ" "$BPF_OBJECT_DIR/ddos-stage1.o"
    success "eBPF object installed to $BPF_OBJECT_DIR/ddos-stage1.o"
    EBPF_READY=true
else
    warn "No eBPF object was built. Stage 1 will run on the libpcap backend."
fi

# The kernel backend cannot start without the object, so a unit asking for it
# would fail on every boot. Falling back keeps the install working and says so.
if [[ "$CAPTURE_MODE" == "kernel" ]] && ! $EBPF_READY; then
    warn "--capture-mode kernel was requested but the eBPF object is not available."
    warn "The service will start on the libpcap backend instead. Fix the build,"
    warn "then edit $SERVICE_DIR/ddos-stage1.service to add --capture-mode kernel."
    CAPTURE_MODE="pcap"
fi

# =============================================================================
# Install the binary
# =============================================================================
info "Installing binary to $INSTALL_DIR/$BINARY_NAME..."
install -m 755 "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
success "Binary installed: $INSTALL_DIR/$BINARY_NAME"

# =============================================================================
# Detection tuning (optional)
# =============================================================================
# Asked after the binary exists so the real defaults can be read from --help
# rather than duplicated here, where they would drift.
sensor_default() {
    "$INSTALL_DIR/$BINARY_NAME" --help 2>&1 \
        | grep -A 1 -- "  $1 " \
        | grep -o 'default: [^]]*' \
        | head -1 | cut -d' ' -f2
}

# Ask for one value, keeping the sensor's default when the answer is empty.
prompt_tuning() {
    local flag="$1" description="$2" current="$3"
    local shown="${current:-$(sensor_default "$flag")}"
    echo -ne "${YELLOW}[INPUT]${NC} ${description}\n         ${flag} [default: ${shown:-built in}]: "
    read -r reply
    echo "${reply:-$current}"
}

if [[ -t 0 ]] && ! $SKIP_TUNING_PROMPT; then
    echo ""
    info "Detection tuning is optional. The defaults are what the system was"
    info "tested against, and the sensor relearns your traffic baseline on its"
    info "own, so most installs should keep them."
    info "They can be changed later by editing the service unit."
    echo ""
    echo -ne "${YELLOW}[INPUT]${NC} Set detection tuning values now? [y/N]: "
    read -r want_tuning

    if [[ "$want_tuning" =~ ^[Yy] ]]; then
        echo ""
        info "Press Enter on any prompt to keep that default."
        echo ""
        TUNE_K=$(prompt_tuning "--k" \
            "Sensitivity. Lower fires more readily, higher demands a bigger deviation." \
            "$TUNE_K")
        TUNE_ENTROPY_SIGMA_FLOOR=$(prompt_tuning "--entropy-sigma-floor" \
            "Smallest entropy deviation used for the boundary. Raise if ordinary traffic gets flagged." \
            "$TUNE_ENTROPY_SIGMA_FLOOR")
        TUNE_RATE_SIGMA_FLOOR=$(prompt_tuning "--rate-sigma-floor" \
            "Same floor for the rate, in packets per second." \
            "$TUNE_RATE_SIGMA_FLOOR")
        TUNE_ENTROPY_MIN_PACKETS=$(prompt_tuning "--entropy-min-packets" \
            "Packets a window needs before its entropy may raise an anomaly." \
            "$TUNE_ENTROPY_MIN_PACKETS")
        echo ""
    fi
fi

# Grant capabilities so the binary can run without root. CAP_NET_RAW covers
# libpcap; CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON cover the kernel backend loading
# and attaching programs. Falls back to CAP_NET_RAW alone on a kernel too old
# to recognise the others, since pcap capture must still work either way.
if command -v setcap &>/dev/null; then
    if setcap cap_net_raw,cap_bpf,cap_net_admin,cap_perfmon+ep "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null; then
        success "Capabilities granted (CAP_NET_RAW, CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON), binary can run without sudo."
    else
        setcap cap_net_raw+ep "$INSTALL_DIR/$BINARY_NAME"
        success "CAP_NET_RAW capability granted, binary can run without sudo."
        warn "Could not grant CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON; the kernel backend needs root or --capture-mode pcap when run by hand."
    fi
else
    warn "setcap not found. You will need to run $BINARY_NAME as root."
fi

# Dedicated, unprivileged service account for Stage 1. It only needs the
# capabilities granted above via setcap (and again below via the systemd
# unit's AmbientCapabilities), not full root, running the packet-capture
# daemon as root means any bug in it has root's blast radius for no reason.
# ddos-ipc is a shared group so this account can reach the Stage 1 <-> Stage
# 2 IPC socket that Stage 2 (still root, for ipset/iptables) creates.
if ! getent group ddos-ipc &>/dev/null; then
    groupadd --system ddos-ipc
    success "Created group: ddos-ipc"
fi
if ! id -u ddos-stage1 &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --gid ddos-ipc ddos-stage1
    success "Created service account: ddos-stage1"
fi

# V4: create the baseline-persistence directory. Deliberately NOT /tmp, the
# entire point of this file is surviving a reboot. Stage 1 degrades
# gracefully (logs a warning, skips persistence) if this is missing, but the
# feature does nothing useful without it existing up front. Owned by the
# Stage 1 service account alone, Stage 2 never reads or writes baselines.
install -d -m 700 -o ddos-stage1 -g ddos-stage1 /var/lib/ddos_stage1
success "Baseline persistence directory ready: /var/lib/ddos_stage1"

# =============================================================================
# Install Stage 2 into a root-owned runtime location
# =============================================================================
info "Installing Stage 2 into $STAGE2_INSTALL_DIR (root owned)..."
STAGE2_DIR="$(dirname "$PROJECT_DIR")/stage2"
if [[ -d "$STAGE2_DIR" ]]; then
    if ! command -v python3 &>/dev/null; then
        error "python3 is not installed."
    fi

    # Code only: *.py at the top level, static/, requirements.txt. An
    # explicit allowlist rather than "copy everything except", so a stray
    # capture CSV or leftover state file sitting in the checkout never
    # rides along into the runtime copy.
    install -d -o root -g root -m 755 "$STAGE2_INSTALL_DIR"
    for f in "$STAGE2_DIR"/*.py "$STAGE2_DIR/requirements.txt"; do
        [[ -f "$f" && ! -L "$f" ]] || continue
        install -o root -g root -m 644 "$f" "$STAGE2_INSTALL_DIR/$(basename "$f")"
    done
    if [[ -d "$STAGE2_DIR/static" ]]; then
        install -d -o root -g root -m 755 "$STAGE2_INSTALL_DIR/static"
        while IFS= read -r -d '' f; do
            rel="${f#"$STAGE2_DIR"/static/}"
            install -D -o root -g root -m 644 "$f" "$STAGE2_INSTALL_DIR/static/$rel"
        done < <(find "$STAGE2_DIR/static" -type f -print0)
    fi
    success "Stage 2 source copied to $STAGE2_INSTALL_DIR."

    info "Creating the Stage 2 virtual environment..."
    if [[ "$PKG_MANAGER" == "apk" ]]; then
        python3 -m venv --clear --system-site-packages "$STAGE2_INSTALL_DIR/venv"
    else
        python3 -m venv --clear "$STAGE2_INSTALL_DIR/venv"
    fi
    chown -R root:root "$STAGE2_INSTALL_DIR/venv"

    info "Installing dependencies from requirements.txt..."
    "$STAGE2_INSTALL_DIR/venv/bin/pip" install --upgrade pip
    "$STAGE2_INSTALL_DIR/venv/bin/pip" install -r "$STAGE2_INSTALL_DIR/requirements.txt"

    # Mutable state: database, JSON config, models, logs, the anomalous
    # traffic review CSV. Never under $STAGE2_INSTALL_DIR: everything
    # there should be safely re-derivable from a fresh install, this
    # directory is not. Root owned since Stage 2 itself runs as root.
    install -d -o root -g root -m 700 "$STAGE2_STATE_DIR"

    # Upgrading a pre-existing checkout-rooted install: carry real state
    # forward instead of silently starting over. Only files present in the
    # old location and absent from the new one move, so re-running this
    # after the state directory exists is a no-op here. Model files are
    # deliberately not in this list: joblib.load() deserialises via
    # pickle and can execute arbitrary code on load, so a .joblib sitting
    # in the checkout, writable by whichever account ran git clone, must
    # never be auto-promoted into the path root loads from. See below.
    for f in stage2.db whitelist.json shared_ips.json victims.json \
             enforcement_config.json alerts_config.json stage2.log \
             anomalous_capture.csv; do
        if [[ -f "$STAGE2_DIR/$f" && ! -f "$STAGE2_STATE_DIR/$f" ]]; then
            mv "$STAGE2_DIR/$f" "$STAGE2_STATE_DIR/$f"
            info "Migrated existing $f to $STAGE2_STATE_DIR."
        fi
    done
    chown -R root:root "$STAGE2_STATE_DIR"

    for f in ddos_rf_model.joblib ddos_if_model.joblib; do
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

    info "Setting up administrative database and user..."
    # setup_admin.py resolves its own DB_PATH independently of config.py's
    # FLOD_STATE_DIR, it predates that mechanism, so it needs the specific
    # file path, not the directory.
    DB_PATH="$STAGE2_STATE_DIR/stage2.db" \
        "$STAGE2_INSTALL_DIR/venv/bin/python" "$STAGE2_INSTALL_DIR/setup_admin.py"

    success "Stage 2 installed: code and venv in $STAGE2_INSTALL_DIR, state in $STAGE2_STATE_DIR."
else
    warn "Stage 2 directory not found at $STAGE2_DIR. Skipping."
fi

# =============================================================================
# Generate a self-signed TLS certificate for the management console
# =============================================================================
# Without this, the admin login form, session cookie, and every block/unblock
# API call travel in plaintext over whatever network the box is on. A
# self-signed cert at least gets the channel encrypted; browsers will warn on
# first connect (expected, click through, or replace these files with a
# CA-signed cert/key pair for that host/IP).
TLS_DIR="/etc/ddos_stage2/tls"
if command -v openssl &>/dev/null; then
    install -d -m 750 "$TLS_DIR"
    if [[ -f "$TLS_DIR/cert.pem" && -f "$TLS_DIR/key.pem" ]]; then
        info "TLS certificate already present at $TLS_DIR, leaving it in place."
    else
        info "Generating self-signed TLS certificate for the management console..."
        openssl req -x509 -nodes -newkey rsa:2048 \
            -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
            -days 825 -subj "/CN=ddos-mitigation-gateway" \
            >/dev/null 2>&1
        chmod 600 "$TLS_DIR/key.pem"
        chmod 644 "$TLS_DIR/cert.pem"
        success "Self-signed TLS certificate generated at $TLS_DIR."
    fi
else
    warn "openssl not found, skipping TLS certificate generation. The" \
         "management console will fall back to plain HTTP until" \
         "$TLS_DIR/cert.pem and $TLS_DIR/key.pem exist."
fi

# =============================================================================
# Install systemd service units (optional, Linux only)
# =============================================================================
if $INSTALL_SERVICE && command -v systemctl &>/dev/null; then
    info "Installing systemd service units..."

    # Build the ExecStart command line.
    EXEC_START="\"$INSTALL_DIR/$BINARY_NAME\" --interface $INTERFACE"
    if [[ -n "$VICTIM_IPS" ]]; then
        EXEC_START+=" --victim-ips $VICTIM_IPS"
    elif [[ -n "$VICTIM_SUBNET" ]]; then
        EXEC_START+=" --victim-subnet $VICTIM_SUBNET"
    else
        warn "No --victim-ips or --victim-subnet specified. Service will run without a BPF filter (dev mode)."
        EXEC_START+=" --no-filter"
    fi
    if [[ -n "$EXCLUDE_IPS" ]]; then
        EXEC_START+=" --exclude-ips $EXCLUDE_IPS"
    fi

    if [[ "$CAPTURE_MODE" == "kernel" ]]; then
        EXEC_START+=" --capture-mode kernel"
    fi

    # Only values the operator actually chose. Anything left unset stays out,
    # so the sensor's own default applies and a later release can improve it.
    [[ -n "$TUNE_K" ]]                    && EXEC_START+=" --k $TUNE_K"
    [[ -n "$TUNE_ENTROPY_SIGMA_FLOOR" ]]  && EXEC_START+=" --entropy-sigma-floor $TUNE_ENTROPY_SIGMA_FLOOR"
    [[ -n "$TUNE_RATE_SIGMA_FLOOR" ]]     && EXEC_START+=" --rate-sigma-floor $TUNE_RATE_SIGMA_FLOOR"
    [[ -n "$TUNE_ENTROPY_MIN_PACKETS" ]]  && EXEC_START+=" --entropy-min-packets $TUNE_ENTROPY_MIN_PACKETS"

    # Measured tuning from scripts/calibrate.py, expanded from the optional
    # environment file below. Last, because the sensor's parser takes the final
    # value given for a flag, so a calibration overrides what was chosen here
    # without this script needing to know what it found.
    EXEC_START+=" \$FLOD_TUNING"

    cat > "$SERVICE_DIR/ddos-stage1.service" << EOF
# =============================================================================
# ddos-stage1.service, systemd unit for the DDoS mitigation Stage 1 daemon
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

[Unit]
Description=Adaptive DDoS Pre-Filter Stage 1 (Rust)
Documentation=https://github.com/DevInBlack001/ddos-reduction-system/wiki
# Start after network is up and Stage 2 classification engine is running
After=network-online.target ddos-stage2.service
Wants=network-online.target

[Service]
Type=simple
User=ddos-stage1
Group=ddos-stage1
SupplementaryGroups=ddos-ipc
# Raw packet capture needs CAP_NET_RAW; nothing else in this process needs
# root. AmbientCapabilities grants it at exec time regardless of the
# binary's file capabilities (setcap above still matters for anyone running
# the binary directly outside systemd).
# CAP_NET_RAW covers libpcap. The kernel backend also needs CAP_BPF to load
# programs and create maps, and CAP_NET_ADMIN to attach XDP and TC. Granting
# them unconditionally keeps one unit working for both backends; without them
# --capture-mode kernel fails under systemd while working by hand as root,
# which is a confusing way to find out.
AmbientCapabilities=CAP_NET_RAW CAP_BPF CAP_NET_ADMIN CAP_PERFMON
CapabilityBoundingSet=CAP_NET_RAW CAP_BPF CAP_NET_ADMIN CAP_PERFMON
# Loading eBPF programs needs locked memory on kernels before 5.11.
LimitMEMLOCK=infinity
NoNewPrivileges=true
# Optional, written by scripts/calibrate.py. Absent until a calibration runs,
# and removing it returns the sensor to the values chosen at install time.
EnvironmentFile=-/etc/ddos_stage1/tuning.env
ExecStart=$EXEC_START
Restart=on-failure
RestartSec=5s
Environment="RUST_LOG=info"
MemoryMax=256M
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    if [[ -d "$STAGE2_DIR" ]]; then
        cat > "$SERVICE_DIR/ddos-stage2.service" << EOF
# =============================================================================
# ddos-stage2.service, systemd unit for the DDoS mitigation Stage 2 daemon
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
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
# Everything mutable (database, JSON config, models, logs, the anomalous
# traffic review CSV) lives outside $STAGE2_INSTALL_DIR on purpose: see
# config.py's FLOD_STATE_DIR comment. DB_PATH is set explicitly alongside
# it because setup_admin.py and config.py resolve it independently.
Environment="FLOD_STATE_DIR=$STAGE2_STATE_DIR"
Environment="DB_PATH=$STAGE2_STATE_DIR/stage2.db"

[Install]
WantedBy=multi-user.target
EOF
        success "Systemd service file created for Stage 2."
    fi

    systemctl daemon-reload
    success "Systemd services installed: ddos-stage1.service, ddos-stage2.service"
    if [[ "$CAPTURE_MODE" == "kernel" ]]; then
        success "Capture backend: kernel (XDP and TC)"
    else
        info "Capture backend: pcap. Re-run with --capture-mode kernel to use XDP and TC."
    fi
    info ""
    info "To enable at boot and start now:"
    info "    systemctl enable --now ddos-stage2"
    info "    systemctl enable --now ddos-stage1"
    info ""
    info "To check logs:"
    info "    journalctl -u ddos-stage2 -f"
    info "    journalctl -u ddos-stage1 -f"
else
    if $INSTALL_SERVICE; then
        warn "systemctl not found; skipping service installation (Alpine OpenRC or non-systemd system)."
    fi
fi

# =============================================================================
# Done
# =============================================================================
info "========================================================================"
info "   CRITICAL ACTION REQUIRED: MACHINE LEARNING MODEL TRAINING"
info "========================================================================"
info "Both the Random Forest classifier and the Isolation Forest anomaly"
info "detector must be trained on network traffic baselines before starting"
info "the detection services. Both models run in production together."
info ""
info "Step 1: Generate Training Data (Capture on your gateway interface):"
info ""
info "  a) Capture NORMAL peacetime baseline traffic (Label 0) for ~5 minutes (until warm-up completes):"
info "     sudo ddos_stage1 --interface \$INTERFACE --victim-ips <VICTIM_IPS> --train-csv stage1/training_data.csv --train-label 0"
info ""
info "  b) Capture FLASH CROWD (legitimate high-volume) traffic (Label 1) for ~5 minutes (until warm-up completes):"
info "     sudo ddos_stage1 --interface \$INTERFACE --victim-ips <VICTIM_IPS> --train-csv stage1/training_data.csv --train-label 1"
info ""
info "  c) Capture DDoS attack traffic (Label 2) for ~5 minutes (until warm-up completes):"
info "     sudo ddos_stage1 --interface \$INTERFACE --victim-ips <VICTIM_IPS> --train-csv stage1/training_data.csv --train-label 2"
info ""
info "Step 2: Train Both Classifier Models:"
info "  Run the interactive training selector, which trains the Random Forest,"
info "  the Isolation Forest, or both against a chosen CSV:"
info "     scripts/train.sh"
info "  This install's running service loads models from $STAGE2_STATE_DIR,"
info "  not the checkout, so scripts/train.sh saves there when it detects"
info "  this install (see the script's own output for where it wrote them)."
info ""
info "Step 3: Launch System Daemons:"
info "  Once trained, start and enable the systemd services:"
info "     sudo systemctl enable --now ddos-stage2"
info "     sudo systemctl enable --now ddos-stage1"
info "========================================================================"
echo ""
