# Testing

Everything runs in seconds and none of it needs a live network.

## Everything At Once

```bash
scripts/test.sh
```

Runs the Rust suite, the Python suite, and the eBPF build check, reporting each
separately so a failure says which one. A suite whose toolchain is missing is
skipped rather than failed, since not every contributor can build eBPF. It
exits non zero if anything fails, or if everything was skipped.

Individual components:

```bash
scripts/test.sh stage1
scripts/test.sh stage2
scripts/test.sh ebpf
```

## Stage 1

```bash
cd stage1
cargo test
```

51 tests across the online variance accumulator, the smoothed rate, entropy,
IPC serialisation, baseline persistence, the kernel backend's address
handling, and the analysis loop.

Building needs libpcap headers, `libpcap-dev` on Debian and Ubuntu or
`libpcap-devel` on Fedora and RHEL. Running the tests does not need capture
rights.

The pure maths modules can be tested with no libpcap present at all:

```bash
rustc --edition 2021 --test src/welford.rs -o /tmp/t && /tmp/t
rustc --edition 2021 --test src/ewma.rs    -o /tmp/t && /tmp/t
rustc --edition 2021 --test src/entropy.rs -o /tmp/t && /tmp/t
```

The golden vector `[4, 7, 13, 16]` giving mean 10.0 and variance 30.0 is
verified on every run.

## Stage 2

```bash
cd stage2
python3 -m unittest discover -s tests -t tests -q
```

196 tests across storage, configuration, request models, the database schema,
the audit writers, enforcement, and authentication.

Written against the standard library's `unittest`. Keep it that way: the suite
runs anywhere the service runs, with no extra dependency to install.

`httpx` is absent, so `fastapi.testclient` is unavailable. The auth routes are
plain functions and are called directly with a stand in request object, and the
async middleware is driven through a small helper.

## eBPF

```bash
scripts/build-ebpf.sh
```

There is no unit test framework for BPF bytecode. What can be checked without a
kernel to load into is that the object builds and that every program and map
made it in, which is what the script verifies before installing the object.

Building needs three things, and the script names whichever is missing:

| Requirement | Why |
|-|-|
| nightly toolchain | aya-ebpf needs `build-std`, which is nightly only |
| `rust-src` on nightly | `build-std` compiles core from source |
| `bpf-linker` | Links the BPF object |
| LLVM | What bpf-linker links against |

`scripts/install.sh` sets all of this up. No version is pinned anywhere: it
finds the newest LLVM on the machine and picks a bpf-linker that builds against
it, because which LLVM you have is your distribution's decision, not this
project's.

That matters because the two move together. bpf-linker releases from 0.11 call
an interface introduced in LLVM 20, so on a distribution still shipping LLVM 19
they fail at link time with an undefined symbol. The installer tries candidates
in an order chosen from the detected LLVM and keeps the first that builds,
rather than asserting a compatibility table that would age badly.

Doing it by hand, if you prefer:

```bash
rustup toolchain install nightly --component rust-src
LLVM_PREFIX=$(llvm-config --prefix) PATH="$(llvm-config --bindir):$PATH" \
    cargo install bpf-linker
```

If that fails on an undefined LLVM symbol, add `--version "^0.9"`. Note that
bpf-linker reads `LLVM_PREFIX` and wants `llvm-config` on `PATH`; it does not
use the `LLVM_SYS_*_PREFIX` variable that llvm-sys documents.

The eBPF backend is optional. A machine without any of this still builds and
runs Stage 1 on the libpcap backend, and `install.sh` treats it as best effort
for that reason.

**Compiling is not the same as loading.** The kernel verifier checks the
program when it is attached, on a host with a real interface, and can reject
something that built cleanly. Bounds proofs, map access patterns, and
instruction limits are all verifier concerns that the compiler does not catch.
Treat a successful build as necessary, not sufficient.

## Conventions

Described in `stage2/tests/_support.py`, and enforced by review.

**Never touch the host.** Enforcement tests replace `subprocess.run` with a
recorder and assert on the `ipset` and `iptables` arguments that would have
been executed. A test that edits the real firewall is a bug in the test.

**Redirect every path.** Stage 2 modules read paths from module level
attributes on `config`. Tests point those at temporary files and restore them
afterwards, so tests stay order independent.

**Build databases from the real schema.** The helper applies the same
definition the running system uses. It once carried its own copy, which is how
a constraint mismatch between two modules reached production without a test
failing.

**Use documentation addresses.** No address belonging to a real network appears
in a test.

| Range | Role |
|-|-|
| `192.0.2.x` | Protected hosts |
| `198.51.100.x` | Traffic sources |
| `203.0.113.x` | Dashboard clients |
| `2001:db8::/32` | IPv6 |

Interfaces are `eth0`, `eth1`, and `br0`.

**Name tests as sentences** describing the behaviour, not the function under
test. `test_a_whitelisted_ip_is_never_blocked`, not `test_block_ip_2`.

## Running It By Hand

Some things only show up on a live interface: the verifier accepting the eBPF
programs, XDP attaching in driver mode rather than the generic fallback,
whether the maps fill under a flood, and how the two backends compare on the
same traffic. None of that is reachable from a test suite.

```bash
sudo bash scripts/run.sh
```

It prompts for the interface, the protected hosts, the capture backend, `k`,
the log level, and whether to start Stage 2, offering a default for each.
`--defaults` accepts all of them without asking, and every prompt has a
matching flag if you would rather pass it.

Stage 2 is optional because Stage 1 retries the IPC socket and keeps analysing
without it. A sensor only run is what you want when comparing backends or
collecting calibration samples, since nothing is classified or enforced and
the windows are still logged.

Two things to set up for a backend comparison. Raise the log level to
`info,ddos_stage1::analysis=debug` so the per window lines are recorded, and
give each run its own `--baseline-path` so neither inherits the other's
baseline. Without the second, both backends restore the same figures and agree
for a reason that has nothing to do with either.

## What Tests Cannot Cover

Some things need a real deployment. A change touching any of them should say in
the pull request what was verified and how:

- Packet capture against a live interface
- ipset and iptables rules actually taking effect
- The dashboard rendering real traffic
- Alert delivery to Discord or email
- Classification accuracy against real traffic
