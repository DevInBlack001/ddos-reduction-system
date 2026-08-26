# IPC Wire Format

**Files:** `stage1/src/ipc.rs`, `stage2/config.py`

Stage 1 serialises a feature vector and sends it over a Unix domain socket at
`/run/ddos_stage1/stage1.sock`. It reports when a window is flagged, and on a
heartbeat otherwise so a quiet target keeps updating.

Exactly 216 bytes, little endian.

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
| 176 | 8 | `is_warmup` | `1.0` if this window's mean/sigma are still from Stage 1's warm-up period, `0.0` otherwise, V7 |
| 184 | 16 | `dominant_ip` | Busiest source, IPv6 or mapped IPv4 |
| 200 | 16 | `victim_ip` | The protected host this window describes |

Python unpacks it with `struct.unpack('<23d16s16s', data)`.

## V7: The Warm-up Flag

Stage 1 sends a `FeatureVector` on every warm-up window too, not just once
warm-up completes, so the dashboard has something to show immediately rather
than sitting blank for the first 200 windows. Those windows' `mean_h`,
`mean_r`, `sigma_h`, and `sigma_r` come from whatever few samples the
accumulator has seen so far, not a converged baseline: `sigma_r` in
particular can read far below `--rate-sigma-floor`, something a converged
baseline can never produce, since the floor only clamps it once the
accumulator is being evaluated live.

Stage 1 already excludes these windows from its own anomaly evaluation, the
same warm-up gate that keeps `window_is_clean()` from running early. `
is_warmup` carries that same fact to Stage 2, because Stage 2 does its own,
separate evaluation: the RandomForest and Isolation Forest, both trained
entirely on converged-baseline data, have never seen a value like
`sigma_r=0.0`, and read "unfamiliar" as "anomalous" rather than "still
warming up". Found in production: five targets restarted together read as
`Anomalous` on 98.86% of windows during their warm-up period, on traffic
that was, by every other measure in the same report, unremarkable. Stage 2
now skips classification entirely on a warm-up window: `pred_class` stays
its default, `Normal`, the same "record but take no action" path an
ordinary Normal window already takes.

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
