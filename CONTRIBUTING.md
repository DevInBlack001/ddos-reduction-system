# Contributing to FLOD System

Thanks for taking an interest. This document covers how to get the project
running, what the code expects of a change, and how to submit one.

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating, and
[SECURITY.md](SECURITY.md) before reporting anything that looks like a
vulnerability. Security issues do not go in the public issue tracker.

## Before You Start

This is a capstone project with a defined roadmap, not an open-ended platform.
The versions listed in the README describe what is planned and roughly in what
order. A change that fits somewhere on that roadmap is far more likely to be
merged than one that adds a new direction.

If you are unsure whether something fits, open an issue and ask before writing
the code. That costs you a day of waiting and saves you a week of work that
gets declined.

## What Is Most Useful

In rough order of value:

1. **Bug reports with reproduction steps.** Especially anything involving real
   traffic, since the test environment is a small virtual lab and cannot cover
   every network shape.
2. **Fixes for the known gaps.** The README roadmap and the open issues list
   what is already known to be missing. Detection tuning under real traffic is
   the area with the most room.
3. **Portability.** The project is developed on Linux with systemd, iptables,
   and ipset. Reports from other distributions, kernels, or init systems are
   welcome.
4. **Documentation.** If something in the README or wiki was wrong or unclear
   when you followed it, that is worth fixing.

## Development Environment

You need a Linux host. Stage 1 uses libpcap and needs raw capture rights;
Stage 2 shells out to iptables and ipset. Neither works meaningfully on macOS
or Windows.

### Stage 1 (Rust)

```bash
cd stage1
cargo build
cargo test
```

Building requires libpcap headers (`libpcap-dev` on Debian and Ubuntu,
`libpcap-devel` on Fedora and RHEL). Running the binary against a real
interface requires root or `CAP_NET_RAW`:

```bash
sudo setcap cap_net_raw+ep target/debug/ddos_stage1
```

`cargo test` does not need capture rights. The three pure math modules can also
be tested without libpcap present at all:

```bash
rustc --edition 2021 --test src/welford.rs -o /tmp/t && /tmp/t
```

### Stage 2 (Python)

```bash
cd stage2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m unittest discover -s tests -t tests -q
```

The test suite uses the standard library's `unittest`. Do not add pytest or
another runner without discussing it first; the suite is deliberately
dependency free so it runs anywhere the service does.

### eBPF Programs (optional)

The XDP capture backend is compiled separately, because it targets BPF bytecode
on nightly while the sensor targets the host on stable.

```bash
scripts/build-ebpf.sh
```

It needs a nightly toolchain with `rust-src`, plus `bpf-linker` and the LLVM it
links against. `scripts/install.sh` sets that up, choosing a bpf-linker that
matches whatever LLVM your distribution ships rather than requiring a specific
version. Do not add a pinned version back: bpf-linker and LLVM move together,
and the right pairing differs per machine.

This is optional. Without it, Stage 1 still builds and runs on libpcap, and
`scripts/test.sh` skips the eBPF check rather than failing.

### Full Install

`scripts/install.sh` builds Stage 1, installs the binary, copies Stage 2's
code and a fresh virtual environment into a root owned `/opt/flod/stage2`
(never the checkout, see [Security](docs/security.md)), generates a TLS
certificate, and writes systemd units. Use it on a disposable virtual
machine, not your workstation. It is documented in the wiki.

## Testing Expectations

**Every behavioural change needs a test.** Everything runs fast enough that
there is no excuse for skipping it.

```bash
scripts/test.sh
```

That runs the Rust suite, the Python suite, and the eBPF build check, and
reports each separately. Anything whose toolchain is missing is skipped rather
than failed. Pass `stage1`, `stage2`, or `ebpf` to run one.

- Stage 1 tests live beside the code in a `mod tests` block.
- Stage 2 tests live in `stage2/tests/`, one file per module.

A few conventions the Stage 2 suite relies on, described in
`stage2/tests/_support.py`:

- **Never touch the host.** Enforcement tests replace `subprocess.run` with
  `RecordingRun` and assert on the `ipset` and `iptables` arguments that would
  have been executed. A test that actually edits the firewall will be rejected.
- **Redirect every path.** Stage 2 modules read paths from module level
  attributes on `config`. Tests point those at temporary files and restore them
  in `tearDown`, so tests stay order independent.
- **Use documentation addresses.** `192.0.2.x` for protected hosts,
  `198.51.100.x` for traffic sources, `203.0.113.x` for dashboard clients,
  `2001:db8::/32` for IPv6, and `eth0`, `eth1`, `br0` for interfaces. No
  address belonging to a real network belongs in a test.

Test names are full sentences describing the behaviour, not the function under
test. `test_a_whitelisted_ip_is_never_blocked` rather than `test_block_ip_2`.

## Code Style

### Comments

Comments explain what the code does and, where it is not obvious, why it does
it that way. They are short. They do not:

- restate the line below them
- narrate the history of the file
- name a design pattern or a visual style
- carry decorative separator lines

If a comment is longer than the code it describes, the comment is probably
wrong or the code needs a better name.

The same applies to anything a user sees. Dashboard copy, log messages, and
report text describe what happened, not how the code is arranged internally.

### Rust

Standard `rustfmt` layout. Prefer returning errors over panicking anywhere in
the capture or analysis path; a malformed packet must never take down the
sensor. Anything keyed by data an attacker controls needs an explicit bound,
in the way `MAX_TRACKED_FLOWS` bounds the flow map.

### Python

Follow the surrounding code. Type hints where the existing module uses them.
Anything reachable from a request needs a Pydantic model that validates it, and
any value that reaches `ipset` or `iptables` must pass through the IP
validator in `models.py` first.

### Commits

Write a subject line that says what changed, then a body explaining why if the
reason is not obvious. Reference an issue number when one exists.

Do not use em dashes or double hyphens as punctuation anywhere in commits,
comments, or documentation.

## Submitting a Change

1. Fork the repository and branch from `master`.
2. Make the change, with tests.
3. Run both suites and confirm they pass.
4. Open a pull request describing what changed and why. Include the output of
   any manual verification you did, especially for anything touching packet
   capture or enforcement, since those cannot be fully covered by tests.

Expect review comments. This is a learning project and the review is part of
the point.

## What Cannot Be Verified by CI

Some things need a real deployment and a human. If your change touches any of
them, say in the pull request what you tested and how:

- Packet capture against a live interface
- ipset and iptables rules actually taking effect
- The dashboard rendering real traffic
- Alert delivery to Discord or email
- Model training and classification accuracy

## Project Layout

```
stage1/src/          Rust sensor
  capture.rs         pcap capture and header parsing
  analysis.rs        windowing, the three layer pipeline, IPC send
  entropy.rs         Shannon source IP entropy
  ewma.rs            exponentially weighted rate
  welford.rs         online mean and variance
  persistence.rs     baseline save and restore
  ipc.rs             feature vector wire format
  main.rs            argument parsing and thread startup

stage2/              Python classifier, enforcement, and dashboard
  ipc_receiver.py    reads feature vectors, runs the tiered enforcement
  enforcement.py     ipset and iptables control
  api.py             dashboard REST endpoints
  auth.py            sessions, login, request gating
  db.py              SQLite audit writers
  reports.py         PDF incident reports
  models.py          request validation
  static/            dashboard pages
  tests/             test suite

scripts/             install, update, uninstall, run, calibrate
```

To run the system out of a working copy without installing it, use
`scripts/run.sh`. It prompts for the interface, the protected hosts, the
capture backend and the rest, offering a default for each, and asks whether to
start Stage 2 as well. `--defaults` accepts everything without asking.

Stage 1 on its own is a supported mode. It retries the IPC socket and keeps
analysing without Stage 2, so windows are still logged while nothing is
classified or enforced.

The wire format between the two stages is defined in `stage1/src/ipc.rs` and
`stage2/config.py`. Field order matters as much as field size. Changing it
means changing both sides in the same commit.

## Licence

Contributions are made under the project's [LICENSE](LICENSE).
