# IPC Wire Format

**Files:** `stage1/src/ipc.rs`, `stage2/config.py`

Stage 1 serialises a feature vector and sends it over a Unix domain socket at
`/run/ddos_stage1/stage1.sock`. It reports when a window is flagged, and on a
heartbeat otherwise so a quiet target keeps updating.

Exactly 208 bytes, little endian.

| Offset | Size | Field | Description |
|-|-|-|-|
| 0 | 8 | `entropy` | Shannon source entropy |
| 8 | 8 | `ewma_rate` | Smoothed packet rate, pps |
| 16 | 8 | `mean_h` | Running mean of entropy |
| 24 | 8 | `mean_r` | Running mean of rate |
| 32 | 8 | `sigma_h` | Standard deviation of entropy |
| 40 | 8 | `sigma_r` | Standard deviation of rate |
| 48 | 8 | `proto_ratio` | TCP share, legacy |
| 56 | 8 | `dominant_ip_ratio` | Share from the busiest source |
| 64 | 8 | `timestamp` | Window close time |
| 72 | 8 | `proto_tcp` | TCP share |
| 80 | 8 | `proto_udp` | UDP share |
| 88 | 8 | `proto_icmp` | ICMP share |
| 96 | 8 | `proto_sctp` | SCTP share |
| 104 | 8 | `proto_gre` | GRE share |
| 112 | 8 | `proto_esp` | ESP share |
| 120 | 8 | `k_multiplier` | The boundary multiplier in force this window |
| 128 | 8 | `cooldown_counter` | Windows remaining in cooldown |
| 136 | 8 | `egress_rate` | pps that reached the protected host |
| 144 | 8 | `drop_ratio` | Share that never got through, 0.0 to 1.0 |
| 152 | 8 | `source_port_entropy` | Shannon entropy of source ports, V7 |
| 160 | 8 | `ttl_variance` | Variance of TTL / hop limit values, V7 |
| 168 | 8 | `fingerprint_diversity` | Shannon entropy of TCP SYN fingerprint buckets, V7 |
| 176 | 16 | `dominant_ip` | Busiest source, IPv6 or mapped IPv4 |
| 192 | 16 | `victim_ip` | The protected host this window describes |

Python unpacks it with `struct.unpack('<22d16s16s', data)`.

## V7: Features Invariant Under Address Forgery

`source_port_entropy`, `ttl_variance`, and `fingerprint_diversity` answer a
gap the rest of the vector has: every other feature here is derived from
source *address* behaviour, and a randomized source flood forges a
different address on nearly every packet, which raises `entropy` and lowers
`dominant_ip_ratio` rather than the other way round. See
[detection.md](detection.md) for the full argument.

All three are computed from per window histograms keyed by the value
itself, port number, TTL, fingerprint bucket, never by source address.
Unlike `SOURCES`, none of the three need an operator configurable cap: port
space is 16 bit and TTL is 8 bit regardless of how many addresses or
packets a flood uses, and the fingerprint table is a small fixed set of
buckets (TCP option ordering plus a window size range, p0f style), not a
hash of arbitrary bytes.

`fingerprint_diversity` is `0.0` for a window with no TCP SYNs to
fingerprint, the same way `entropy` is `0.0` for an empty window: not
distinguishable from "very low diversity" on this field alone.

## Field Order Matters As Much As Size

Both sides hardcode the layout. A field inserted in the middle keeps the total
size correct while silently shifting the meaning of everything after it, which
produces plausible looking numbers rather than an error.

Any change to this table is a change to both stages in the same commit, and
both must be deployed together.

## Why Fields Are Written Manually

Fields are serialised one at a time with `byteorder` rather than transmuting
the struct. Rust may insert alignment padding that the Python side has no way
to know about, and a padding bug is invisible until the values are subtly
wrong.

## The Egress Sentinel

`egress_rate` and `drop_ratio` use `-1.0` to mean "not measured", not `0.0`.

A genuine zero drop ratio is a meaningful reading: it says enforcement is
removing nothing. That has to stay distinguishable from having no egress sensor
configured at all. Stage 2 converts `-1.0` to `None` on receipt.

## Why k and Cooldown Are Transmitted

Earlier versions hardcoded these on the Python side. The moment `--k` was set
to anything other than the default, Stage 2's idea of the boundary silently
diverged from Stage 1's, and the divergence widened further during cooldown
recovery when Stage 1 halves its own multiplier.

Stage 2 now uses the transmitted values for its own boundary and threshold
checks, so the two stages cannot disagree about sensitivity.

## Derived Features

Three more features are computed in Stage 2 rather than sent over the wire:

| Feature | Formula |
|-|-|
| `delta_rate` | `ewma_rate - mean_r` |
| `delta_entropy` | `entropy - mean_h` |
| `dominant_rate` | `ewma_rate * dominant_ip_ratio` |

`dominant_rate` estimates the pps of the single busiest source. It feeds both
the classifier and the enforcement logic, computed once and shared.
