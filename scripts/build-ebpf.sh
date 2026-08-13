#!/usr/bin/env bash
# build-ebpf.sh: compile the Stage 1 eBPF programs to BPF bytecode.
#
# Separate from the normal cargo build because this half targets
# bpfel-unknown-none on nightly, while the sensor itself builds for the host on
# stable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EBPF_DIR="$PROJECT_DIR/stage1-ebpf"
OUT_DIR="$PROJECT_DIR/stage1/src/bpf"
TARGET="bpfel-unknown-none"
PROFILE="${1:-release}"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib-toolchain.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

load_cargo_env

if ! nightly_ready; then
    error "The eBPF programs need a nightly toolchain with rust-src."
    error "aya-ebpf builds core from source, which stable cannot do."
    error ""
    if command -v rustup &>/dev/null; then
        error "  rustup toolchain install nightly --component rust-src"
    else
        error "rustup was not found in any of: \$HOME, /root, or \$SUDO_USER's home."
        error "Install it, then re-run this script:"
        error "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        error ""
        error "If you installed it with 'sudo scripts/install.sh', it went to"
        error "root's home. Run this script with sudo so it is found."
    fi
    exit 1
fi

if ! command -v bpf-linker &>/dev/null; then
    error "bpf-linker not found. Run scripts/install.sh, which picks a version"
    error "matching the LLVM on this machine."
    exit 1
fi

if detect_llvm; then
    info "Using LLVM $LLVM_MAJOR at $LLVM_PREFIX"
    export LLVM_PREFIX
    export PATH="$LLVM_PREFIX/bin:$PATH"
else
    warn "No llvm-config found. bpf-linker will use whatever it was built"
    warn "against, which is usually fine but will not be checked here."
fi

info "Building the eBPF programs ($PROFILE)..."
cd "$EBPF_DIR"

BUILD_ARGS=(+nightly build --target "$TARGET" -Z build-std=core)
[[ "$PROFILE" == "release" ]] && BUILD_ARGS+=(--release)

cargo "${BUILD_ARGS[@]}"

OBJ="$EBPF_DIR/target/$TARGET/$PROFILE/ddos-stage1"
if [[ ! -f "$OBJ" ]]; then
    error "Build reported success but produced no object at $OBJ"
    exit 1
fi

# Compiling is not the same as being loadable. Confirm both programs and every
# map actually made it into the object before installing it.
MISSING=""
for sym in ingress egress PROTECTED COUNTERS SOURCES FLOWS; do
    if ! readelf -s "$OBJ" 2>/dev/null | grep -qw "$sym"; then
        MISSING="$MISSING $sym"
    fi
done
if [[ -n "$MISSING" ]]; then
    error "Object is missing:$MISSING"
    exit 1
fi

mkdir -p "$OUT_DIR"
install -m 644 "$OBJ" "$OUT_DIR/ddos-stage1.o"

success "eBPF object built: $OUT_DIR/ddos-stage1.o ($(stat -c%s "$OBJ") bytes)"

# The sensor loads from the installed path, not the build tree. Without this a
# rebuild looks successful while the running system keeps the old object, or
# none at all.
RUNTIME_DIR="/usr/local/lib/ddos_stage1"
if [[ $EUID -eq 0 ]]; then
    install -d -o root -g root -m 755 "$RUNTIME_DIR"
    install -o root -g root -m 644 "$OBJ" "$RUNTIME_DIR/ddos-stage1.o"
    success "Installed for the sensor: $RUNTIME_DIR/ddos-stage1.o"
elif [[ -d "$RUNTIME_DIR" ]]; then
    warn "Not running as root, so $RUNTIME_DIR was not updated."
    warn "The sensor loads from there, so re-run with sudo or pass"
    warn "--bpf-object $OUT_DIR/ddos-stage1.o to use this build directly."
fi

warn "Compiling only. The kernel verifier checks this at load time, on a host"
warn "with a real interface, and can still reject it."
