# Classification and Enforcement

**Files:** `stage2/ipc_receiver.py`, `stage2/enforcement.py`, `stage2/config.py`

Every number below is a default. All of them are editable from the dashboard's
firewall page and stored in `enforcement_config.json`, so any block or throttle
can be explained by pointing at a specific inspectable value.

## Classification

A Random Forest scores each window as normal, flash crowd, or attack, using the
transmitted fields plus the three derived ones.

Statistical overrides then run on top of the prediction, so an extreme spike is
never missed because the classifier was unsure.

**Volumetric suspect**, which reopens the verdict:

```
ewma_rate > mean_r + k_multiplier * sigma_r
```

`k_multiplier` comes from Stage 1 and reflects its live, cooldown adjusted
sensitivity.

**Extreme single source rate**, which forces an attack classification:

```
dominant_rate > max(block_rate_floor_pps, mean_r + block_sigma_multiplier * sigma_r)
```

This checks the busiest single source, not aggregate volume. Aggregate volume
cannot separate one attacker producing an extreme rate from many real users
each producing a normal trickle, because a flash crowd's total scales with
participant count exactly the way an attacker's does. Checking the busiest
source instead means a large genuine crowd is no longer force classified as an
attack purely because enough people showed up.

**Concentration**, which also forces an attack classification:

```
entropy < mean_h - k_multiplier * sigma_h
  or
dominant_ip_ratio > dominant_ip_ratio_extreme_threshold
```

## The Four Tiers

Evaluated in order. Each works on a per source rate rollup summed across every
flow a given address is using, so splitting traffic across destination ports
does not dodge the thresholds.

**Tier 1, dominant source.** Blocks the busiest source outright when it is both
concentrated and fast enough to clear the live rate boundary.

**Tier 2, per source escalation.** Blocks any individual source clearing the
block threshold on its own, regardless of how concentrated the aggregate looks.
This closes the gap a purely aggregate gate leaves: spreading an attack across
many sources stops helping once each one is still individually far above human
rates.

**Tier 3, soft rate limit.** Any remaining source over the softer floor is
throttled to the configured cap rather than blocked. This is the reversible
tier, for sources that are elevated but ambiguous.

**Tier 4, aggregate fallback.** If a window is classified as an attack but
nothing above matched any individual source, traffic is distributed finely
enough that no single source stands out. Every active flow to that host is
throttled, rather than the system doing nothing.

The progression is deliberate: blocking is only used where attribution is
confident.

**Block hysteresis.** Tiers 1 and 2 additionally require consecutive attack
windows before firing, so one noisy window cannot trigger a block. Tiers 3 and
4 are immediate and ungated, since throttling is already reversible.

Both sets carry an expiry, so enforcement heals on its own if a decision was
wrong.

## Settings

| Setting | Default | Meaning |
|-|-|-|
| `dominant_ip_ratio_block_threshold` | 0.40 | Concentration needed for the Tier 1 fast path |
| `dominant_ip_ratio_extreme_threshold` | 0.75 | Above this, forced to attack regardless of entropy |
| `block_rate_floor_pps` | 300.0 | Absolute floor under the block threshold |
| `ratelimit_rate_floor_pps` | 50.0 | Absolute floor under the throttle threshold |
| `block_sigma_multiplier` | 10.0 | Sigma multiplier for the per source block bar |
| `block_hysteresis_windows` | 2 | Consecutive attack windows required before blocking |
| `block_duration_seconds` | 3600 | Block lifetime |
| `ratelimit_duration_seconds` | 3600 | Throttle lifetime |
| `ratelimit_hashlimit_pps` | 50 | The enforced packets per second cap |

The two floors stop a near idle host producing an absurdly low bar. A host
normally receiving two packets per second would otherwise have a learned
baseline that makes ten packets per second look like a flood.

`block_sigma_multiplier` is shared between the Tier 2 threshold and the extreme
rate override, kept as one value so the two cannot drift apart.

Changing `ratelimit_hashlimit_pps` rewrites the live iptables rule. The cap is
part of the rule itself and cannot be edited in place, so the old rule is
removed and a new one inserted.

## Kernel Mechanics

Two ipsets, both matched on **source** address, both attached to the `INPUT`
and `FORWARD` chains:

| Set | Action |
|-|-|
| `ddos_blocklist` | Unconditional drop |
| `ddos_ratelimit` | `hashlimit` with one bucket per source address |

A background thread polls the blocklist every 30 seconds and warns when it
passes 80 percent of capacity.

## Whitelist

Addresses on the whitelist are never blocked and never throttled, at any tier.
The check happens before any kernel call, so a whitelisted address produces no
enforcement and no incident record.

## NAT and Shared Addresses

`ddos_blocklist` is an unconditional drop matched on source address. When that
source is a carrier NAT, a corporate egress point, or a proxy, one entry cuts
off every legitimate user sharing it.

Addresses marked as shared are never added to the blocklist. The block call
detects the mark and delegates to the throttle path instead, so the source is
capped rather than dropped.

**What this does and does not fix.** The `hashlimit` rule uses one bucket per
source address, so everyone behind a shared address shares one throttle. This
is harm reduction, not a solution: legitimate users behind that address still
see degraded service, they are just not disconnected.

The underlying problem is that source attribution is destroyed at the gateway,
and only the NAT operator can resolve it. Asking the network that owns the
address to identify the offending host locally is planned work. Improving
detection so a large NAT crowd stops resembling a single source flood needs per
flow features the pipeline does not yet extract.

## Audit Records

Every action is recorded with the source, the protected host, that source's own
rate, and the window's classification.

The rate stored is the individual source's rate, not the window total. Using
the window aggregate meant a fallback throttling fifty sources wrote fifty
identical rows, each claiming the entire attack volume.

Entropy is stored as a window level value on purpose, since it describes the
distribution the decision was made against rather than anything per source.

An unknown rate is stored as null rather than zero. An operator blocking an
address by hand has no measured rate, and zero would read as an observation
that the source sent nothing.
