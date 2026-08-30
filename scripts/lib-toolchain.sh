# lib-toolchain.sh: shared toolchain discovery. Sourced, not executed.
#
# Nothing here pins a version. The eBPF build depends on LLVM, and which LLVM a
# machine has is decided by its distribution, so the setup reads what is
# installed and picks parts that work with it rather than demanding a specific
# release.

# Highest LLVM installation on this machine, or empty if there is none.
# Sets LLVM_PREFIX, LLVM_CONFIG, and LLVM_MAJOR.
detect_llvm() {
    LLVM_PREFIX=""; LLVM_CONFIG=""; LLVM_MAJOR=""

    local candidates=()
    # A versioned llvm-config is preferred over a bare one: distributions that
    # ship several keep the unversioned name pointing at an arbitrary choice.
    local c
    for c in /usr/lib/llvm-*/bin/llvm-config /usr/local/opt/llvm*/bin/llvm-config; do
        [[ -x "$c" ]] && candidates+=("$c")
    done
    command -v llvm-config &>/dev/null && candidates+=("$(command -v llvm-config)")

    local best="" best_major=0 major
    for c in "${candidates[@]}"; do
        major="$("$c" --version 2>/dev/null | cut -d. -f1)"
        [[ "$major" =~ ^[0-9]+$ ]] || continue
        if (( major > best_major )); then
            best_major=$major
            best="$c"
        fi
    done

    [[ -n "$best" ]] || return 1

    LLVM_CONFIG="$best"
    LLVM_MAJOR="$best_major"
    LLVM_PREFIX="$("$best" --prefix 2>/dev/null)"
    return 0
}

# The bpf-linker version constraints worth trying against LLVM $1, best first.
#
# bpf-linker links against whatever LLVM it finds, and the two move together.
# Releases from 0.11 call an interface introduced in LLVM 20, so on an older
# LLVM they fail at link time with an undefined symbol. Rather than asserting a
# compatibility table that will age badly, this returns an ordered list and the
# caller tries each until one installs.
bpf_linker_candidates() {
    local major="${1:-0}"
    if (( major >= 20 )); then
        echo "latest ^0.9"
    else
        echo "^0.9 latest"
    fi
}

# Install bpf-linker, trying each candidate until one succeeds.
install_bpf_linker() {
    local major="${1:-0}"
    local prefix="${2:-}"
    local spec

    for spec in $(bpf_linker_candidates "$major"); do
        local args=(install bpf-linker --locked)
        [[ "$spec" != "latest" ]] && args+=(--version "$spec")

        # bpf-linker reads LLVM_PREFIX and wants llvm-config on PATH. It does
        # not use the LLVM_SYS_*_PREFIX variable that llvm-sys documents.
        if LLVM_PREFIX="$prefix" PATH="${prefix:+$prefix/bin:}$PATH" \
                cargo "${args[@]}" >/dev/null 2>&1; then
            echo "$spec"
            return 0
        fi
    done
    return 1
}

# The package names for LLVM and clang differ per distribution, and pinning a
# major version breaks the moment the distribution moves on. These install
# whatever the package manager considers current.
llvm_packages_for() {
    case "$1" in
        apt)  echo "llvm clang" ;;
        dnf|yum) echo "llvm llvm-devel clang" ;;
        apk)  echo "llvm-dev clang" ;;
        pacman) echo "llvm clang" ;;
        *)    echo "" ;;
    esac
}

# Put cargo and rustup on PATH, wherever they were installed.
#
# sudo resets PATH from secure_path, so a toolchain in a home directory is
# invisible to a script run with plain sudo even though it is installed.
# install.sh and update.sh avoid this themselves by building as the invoking
# account via 'sudo -u', never as root, but a script run directly with plain
# sudo (bypassing them) still needs the fallback: the toolchain lives in
# whichever account originally ran rustup, root's home included, so every
# home this process might plausibly mean is checked.
load_cargo_env() {
    local home_dir
    for home_dir in "$HOME" "/root" "$(getent passwd "${SUDO_USER:-}" 2>/dev/null | cut -d: -f6)"; do
        [[ -n "$home_dir" && -d "$home_dir/.cargo/bin" ]] || continue
        case ":$PATH:" in
            *":$home_dir/.cargo/bin:"*) ;;
            *) PATH="$home_dir/.cargo/bin:$PATH" ;;
        esac
    done
    export PATH
}

# Make sure rustup is available, installing it if it is not.
#
# A distribution package can provide cargo and rustc, which is enough to build
# the sensor but not the eBPF programs: those need a nightly toolchain and the
# rust-src component, and only rustup can add either. rustup coexists with a
# distribution install rather than replacing it, since its shims live under
# ~/.cargo/bin.
#
# Returns non zero if rustup is still unavailable afterwards, which callers
# treat as "skip the eBPF backend", not as a fatal error.
ensure_rustup() {
    load_cargo_env
    if command -v rustup &>/dev/null; then
        return 0
    fi

    command -v curl &>/dev/null || return 1

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --default-toolchain stable >/dev/null 2>&1 || return 1

    # Puts ~/.cargo/bin on PATH for the rest of this script, in whichever
    # home rustup just installed into.
    # shellcheck source=/dev/null
    [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

    command -v rustup &>/dev/null
}

# True when the nightly toolchain and rust-src are both present. aya-ebpf
# builds core from source, which needs both, and neither is on stable.
nightly_ready() {
    load_cargo_env
    command -v rustup &>/dev/null || return 1
    rustup toolchain list 2>/dev/null | grep -q '^nightly' || return 1
    rustup component list --toolchain nightly 2>/dev/null \
        | grep -q '^rust-src.*(installed)' || return 1
    return 0
}
