#!/usr/bin/env bash
# build-stage1.sh: build Stage 1 and, best effort, its eBPF backend.
#
# Deliberately unprivileged. install.sh and update.sh run this as the
# account that ran git clone, via 'sudo -u', never as root: cargo, rustup,
# and build.rs/proc-macro code in any dependency then execute with that
# account's privileges, not root's, however the checkout was modified.
# Root's own job starts only once this script has exited and left real
# files behind for it to install; root itself never sources
# lib-toolchain.sh or runs cargo directly.
#
# Usage: build-stage1.sh [--with-ebpf|--no-ebpf] [--update-toolchain]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")/stage1"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib-toolchain.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# Best effort by default, matching install.sh's original behaviour: a
# machine without the eBPF toolchain still builds and runs on libpcap.
WITH_EBPF=true
UPDATE_TOOLCHAIN=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-ebpf)        WITH_EBPF=true; shift ;;
        --no-ebpf)           WITH_EBPF=false; shift ;;
        --update-toolchain)  UPDATE_TOOLCHAIN=true; shift ;;
        *) error "Unknown argument: $1" ;;
    esac
done

if [[ ! -d "$PROJECT_DIR" ]]; then
    error "Stage 1 source directory not found at: $PROJECT_DIR"
fi

load_cargo_env

# =============================================================================
# Rust toolchain
# =============================================================================
info "Checking for Rust toolchain..."

if command -v cargo &>/dev/null && command -v rustc &>/dev/null; then
    success "Rust already installed: $(rustc --version)"
    if $UPDATE_TOOLCHAIN && command -v rustup &>/dev/null; then
        info "Updating Rust toolchain..."
        rustup update stable 2>&1
        success "Rust toolchain updated: $(rustc --version)"
    fi
else
    info "Rust not found. Installing via rustup..."
    if ! ensure_rustup; then
        error "Could not install the Rust toolchain. Install cargo and rustc" \
              "from your distribution, or rustup from https://rustup.rs, then" \
              "re-run this script."
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
EBPF_READY=false

if $WITH_EBPF; then
    # The caller decides whether this run produced a fresh object purely by
    # whether this path exists afterward. Clearing it first means a failed
    # build, or a toolchain that turns out not to be ready below, is never
    # mistaken for success by leaving a previous run's object sitting here.
    rm -f "$PROJECT_DIR/src/bpf/ddos-stage1.o"

    info "Setting up the eBPF build toolchain..."

    # cargo can come from a distribution package with no rustup alongside it.
    # That builds the sensor fine but cannot add nightly or rust-src, so
    # rustup is installed here rather than assumed.
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
            # Version is chosen from the LLVM actually installed, not pinned
            # here: bpf-linker links against LLVM, and which LLVM a machine
            # has is its distribution's decision. Candidates are tried until
            # one builds.
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

    if $EBPF_READY; then
        info "Building the eBPF programs..."
        EBPF_LOG="$(mktemp)"
        if bash "$SCRIPT_DIR/build-ebpf.sh" >"$EBPF_LOG" 2>&1; then
            success "eBPF object built: $PROJECT_DIR/src/bpf/ddos-stage1.o"
            rm -f "$EBPF_LOG"
        else
            EBPF_READY=false
            warn "eBPF build failed. The reason follows; Stage 1 will still"
            warn "build and run on the libpcap backend."
            echo
            # Showing the reason here saves a second run just to find out
            # what went wrong.
            sed 's/^/    /' "$EBPF_LOG" | tail -n 25
            echo
            warn "Full output kept at $EBPF_LOG"
        fi
    fi
fi

# =============================================================================
# Compile Stage 1 in release mode
# =============================================================================
info "Building Stage 1 (release mode, this may take a few minutes on first build)..."

cd "$PROJECT_DIR"

# RUSTFLAGS: target-cpu=native enables CPU-specific optimisations (AVX2, etc.)
# on the gateway host. Remove this flag if building for distribution to other
# machines (use target-cpu=x86-64-v2 or omit entirely).
RUSTFLAGS="-C target-cpu=native" cargo build --release

success "Build complete: $PROJECT_DIR/target/release/ddos_stage1"
