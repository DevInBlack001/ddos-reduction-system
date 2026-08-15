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
#   • The Rust toolchain is installed into ~/.cargo for the current user.
#     If running as root via sudo, the toolchain lands in /root/.cargo.
#   • Use `sudo setcap cap_net_raw+ep /usr/local/bin/ddos_stage1` after install
#     to run the binary WITHOUT root in production.
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

# Toolchain discovery, used by both the Rust and eBPF steps below.
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib-toolchain.sh"
load_cargo_env

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --interface)               INTERFACE="$2"; shift 2 ;;
        --victim-ip|--victim-ips)  VICTIM_IPS="$2"; shift 2 ;;
        --victim-subnet)           VICTIM_SUBNET="$2"; shift 2 ;;
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
        ipset
}

install_deps_dnf() {
    # libpcap-devel provides the headers and .so needed to compile the pcap crate
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
        ipset
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
        ipset
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
        py3-joblib
}

case "$PKG_MANAGER" in
    apt) install_deps_apt ;;
    dnf) install_deps_dnf ;;
    yum) install_deps_yum ;;
    apk) install_deps_apk ;;
esac

success "System dependencies installed."

# =============================================================================
# Install Rust toolchain via rustup
# =============================================================================
info "Checking for Rust toolchain..."

if command -v cargo &>/dev/null && command -v rustc &>/dev/null; then
    success "Rust already installed: $(rustc --version)"
else
    info "Rust not found. Installing via rustup..."
    if ! ensure_rustup; then
        error "Could not install the Rust toolchain. Install cargo and rustc"
        error "from your distribution, or rustup from https://rustup.rs, then"
        error "re-run this script."
        exit 1
    fi
    success "Rust toolchain installed: $(rustc --version)"
fi

# Only meaningful when rustup is managing the toolchain. A distribution
# install has no notion of a default and the call is a harmless no-op.
if command -v rustup &>/dev/null; then
    rustup default stable &>/dev/null || true
fi

# =============================================================================
# eBPF build toolchain (optional)
# =============================================================================
# The XDP capture backend is compiled separately: it targets BPF bytecode on
# nightly, while the sensor targets the host on stable. This is best effort.
# A machine without it still builds and runs Stage 1 on the libpcap backend.
info "Setting up the eBPF build toolchain..."

EBPF_READY=false

# cargo can come from a distribution package with no rustup alongside it. That
# builds the sensor fine but cannot add nightly or rust-src, so rustup is
# installed here rather than assumed.
if ! command -v rustup &>/dev/null; then
    info "rustup not found. Installing it so a nightly toolchain can be added..."
    if ensure_rustup; then
        success "rustup installed: $(rustup --version 2>/dev/null | head -1)"
    else
        warn "Could not install rustup. Skipping the kernel capture backend."
        warn "Stage 1 will still build and run on the libpcap backend."
    fi
fi

if command -v rustup &>/dev/null && ! nightly_ready; then
    info "Installing the nightly toolchain and rust-src (needed to build core)..."
    rustup toolchain install nightly --component rust-src --profile minimal &>/dev/null || true
fi

if nightly_ready; then
    if command -v bpf-linker &>/dev/null; then
        success "bpf-linker already present: $(bpf-linker --version 2>/dev/null || echo unknown)"
        EBPF_READY=true
    elif detect_llvm; then
        info "Found LLVM $LLVM_MAJOR at $LLVM_PREFIX. Installing a matching bpf-linker..."
        # Version is chosen from the LLVM actually installed, not pinned here:
        # bpf-linker links against LLVM, and which LLVM a machine has is its
        # distribution's decision. Candidates are tried until one builds.
        if CHOSEN=$(install_bpf_linker "$LLVM_MAJOR" "$LLVM_PREFIX"); then
            success "bpf-linker installed ($CHOSEN, built against LLVM $LLVM_MAJOR)."
            EBPF_READY=true
        else
            warn "Could not build bpf-linker against LLVM $LLVM_MAJOR."
            warn "Stage 1 will still build and run on the libpcap backend."
        fi
    else
        warn "No LLVM installation found, so bpf-linker cannot be built."
        warn "Install your distribution's llvm and clang packages, then re-run."
    fi
else
    warn "Nightly toolchain unavailable. Skipping the eBPF backend."
fi

BPF_OBJECT_DIR="/usr/local/lib/ddos_stage1"

if $EBPF_READY; then
    info "Building the eBPF programs..."
    EBPF_LOG="$(mktemp)"
    if bash "$SCRIPT_DIR/build-ebpf.sh" >"$EBPF_LOG" 2>&1; then
        # The sensor loads this into the kernel as a privileged process, so a
        # non root account able to replace it would be running its own kernel
        # code. Root owned directory, not writable by anyone else.
        install -d -o root -g root -m 755 "$BPF_OBJECT_DIR"
        install -o root -g root -m 644 \
            "$PROJECT_DIR/src/bpf/ddos-stage1.o" \
            "$BPF_OBJECT_DIR/ddos-stage1.o"
        success "eBPF object installed to $BPF_OBJECT_DIR/ddos-stage1.o"
        rm -f "$EBPF_LOG"
    else
        EBPF_READY=false
        warn "eBPF build failed. The reason follows; the installation continues"
        warn "and Stage 1 will run on the libpcap backend."
        echo
        # Showing the reason here saves a second run just to find out what
        # went wrong.
        sed 's/^/    /' "$EBPF_LOG" | tail -n 25
        echo
        warn "Full output kept at $EBPF_LOG"
    fi
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
# Compile Stage 1 in release mode
# =============================================================================
info "Building Stage 1 (release mode, this may take a few minutes on first build)..."

if [[ ! -d "$PROJECT_DIR" ]]; then
    error "Stage 1 source directory not found at: $PROJECT_DIR"
fi

cd "$PROJECT_DIR"

# RUSTFLAGS: target-cpu=native enables CPU-specific optimisations (AVX2, etc.)
# on the gateway host. Remove this flag if building for distribution to other
# machines (use target-cpu=x86-64-v2 or omit entirely).
RUSTFLAGS="-C target-cpu=native" cargo build --release 2>&1

success "Build complete: target/release/$BINARY_NAME"

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
# Install the binary
# =============================================================================
info "Installing binary to $INSTALL_DIR/$BINARY_NAME..."
install -m 755 "target/release/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
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
# Setup Stage 2 Python Virtual Environment
# =============================================================================
info "Setting up Stage 2 Python virtual environment..."
STAGE2_DIR="$(dirname "$PROJECT_DIR")/stage2"
if [[ -d "$STAGE2_DIR" ]]; then
    if ! command -v python3 &>/dev/null; then
        error "python3 is not installed."
    fi
    info "Creating virtual environment at $STAGE2_DIR/venv..."
    if [[ "$PKG_MANAGER" == "apk" ]]; then
        python3 -m venv --clear --system-site-packages "$STAGE2_DIR/venv"
    else
        python3 -m venv --clear "$STAGE2_DIR/venv"
    fi
    
    info "Installing dependencies from requirements.txt..."
    "$STAGE2_DIR/venv/bin/pip" install --upgrade pip
    "$STAGE2_DIR/venv/bin/pip" install -r "$STAGE2_DIR/requirements.txt"
    
    info "Setting up administrative database and user..."
    "$STAGE2_DIR/venv/bin/python" "$STAGE2_DIR/setup_admin.py"
    
    success "Stage 2 Python environment setup complete."
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
Documentation=https://github.com/your-repo/ddos-reduction
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
After=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$STAGE2_DIR
ExecStart=/bin/bash -c 'source "$STAGE2_DIR/venv/bin/activate" && exec python3 stage2.py'
Restart=on-failure
RestartSec=5s
Environment="PYTHONUNBUFFERED=1"

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
info "The Random Forest classifier must be trained on network traffic baselines"
info "before starting the detection services."
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
info "Step 2: Train the Random Forest Classifier Model:"
info "  Run the training script (this cleans transient rows, balances classes,"
info "  and saves the model inside the stage2 directory):"
info "     stage2/venv/bin/python stage2/train.py"
info ""
info "Step 3: Launch System Daemons:"
info "  Once trained, start and enable the systemd services:"
info "     sudo systemctl enable --now ddos-stage2"
info "     sudo systemctl enable --now ddos-stage1"
info "========================================================================"
echo ""
