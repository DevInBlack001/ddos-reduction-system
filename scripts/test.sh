#!/usr/bin/env bash
# test.sh: run every test suite in the project.
#
# What a contributor runs before opening a pull request. Each component is
# reported separately so a failure says which one, and a missing toolchain is
# skipped rather than failed: not every contributor can build eBPF.
#
#   scripts/test.sh           everything available
#   scripts/test.sh stage1    the Rust sensor only
#   scripts/test.sh stage2    the Python service only
#   scripts/test.sh ebpf      the eBPF build check only

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
WHICH="${1:-all}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[SKIP]${NC}  $*"; }
error()   { echo -e "${RED}[FAIL]${NC} $*" >&2; }

FAILED=0
SKIPPED=0
RAN=0

run_stage1() {
    info "Stage 1: Rust sensor"
    if ! command -v cargo &>/dev/null; then
        warn "cargo not found, skipping the Rust suite."
        SKIPPED=$((SKIPPED + 1)); return
    fi
    # Needs libpcap headers to link. The pure maths modules can be tested
    # without them; see docs/testing.md.
    if ! (cd "$PROJECT_DIR/stage1" && cargo test); then
        error "Stage 1 tests failed."
        FAILED=$((FAILED + 1)); return
    fi
    success "Stage 1 tests passed."
    RAN=$((RAN + 1))
}

run_stage2() {
    info "Stage 2: Python service"
    PY="$PROJECT_DIR/stage2/venv/bin/python3"
    [[ -x "$PY" ]] || PY="$(command -v python3 || true)"
    if [[ -z "$PY" ]]; then
        warn "python3 not found, skipping the Python suite."
        SKIPPED=$((SKIPPED + 1)); return
    fi
    if ! (cd "$PROJECT_DIR/stage2" && "$PY" -m unittest discover -s tests -t tests -q); then
        error "Stage 2 tests failed."
        FAILED=$((FAILED + 1)); return
    fi
    success "Stage 2 tests passed."
    RAN=$((RAN + 1))
}

run_ebpf() {
    info "eBPF: build check"
    # There is no unit test framework for BPF bytecode. Building it and
    # confirming every program and map is present is the check that can run
    # without a kernel to load into.
    if ! command -v bpf-linker &>/dev/null; then
        warn "bpf-linker not found, skipping the eBPF build."
        warn "  cargo install bpf-linker --version '^0.9'"
        SKIPPED=$((SKIPPED + 1)); return
    fi
    if ! "$SCRIPT_DIR/build-ebpf.sh" >/dev/null 2>&1; then
        error "eBPF build failed. Run scripts/build-ebpf.sh for the reason."
        FAILED=$((FAILED + 1)); return
    fi
    success "eBPF object built and every program and map is present."
    RAN=$((RAN + 1))
}

case "$WHICH" in
    stage1) run_stage1 ;;
    stage2) run_stage2 ;;
    ebpf)   run_ebpf ;;
    all)    run_stage1; echo; run_stage2; echo; run_ebpf ;;
    *)      error "Unknown target '$WHICH'. Use stage1, stage2, ebpf, or all."; exit 2 ;;
esac

echo
if [[ $FAILED -gt 0 ]]; then
    error "$FAILED suite(s) failed, $RAN passed, $SKIPPED skipped."
    exit 1
fi
if [[ $RAN -eq 0 ]]; then
    error "Nothing ran. Every suite was skipped for a missing tool."
    exit 1
fi
success "$RAN suite(s) passed, $SKIPPED skipped."
