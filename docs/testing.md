# Testing

Both suites run in seconds and neither needs a live network.

## Stage 1

```bash
cd stage1
cargo test
```

31 tests across the online variance accumulator, the smoothed rate, entropy,
IPC serialisation, baseline persistence, and the analysis loop.

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

## What Tests Cannot Cover

Some things need a real deployment. A change touching any of them should say in
the pull request what was verified and how:

- Packet capture against a live interface
- ipset and iptables rules actually taking effect
- The dashboard rendering real traffic
- Alert delivery to Discord or email
- Classification accuracy against real traffic
