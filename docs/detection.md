# Detection

Three quantities per window, compared against a baseline the sensor maintains
itself.

## Welford's Online Variance

**File:** `stage1/src/welford.rs`

Tracking a running mean and standard deviation without storing every past
value. Accumulating a sum and a sum of squares and subtracting causes
catastrophic cancellation: two large numbers nearly cancel, leaving a result
dominated by floating point error, sometimes negative.

Each new sample runs five steps:

```
n     += 1
delta  = x - mean          surprise against the old mean
mean  += delta / n         shift the centre toward x
delta2 = x - mean          surprise against the new mean
M2    += delta * delta2    accumulate the cross product
```

Then `variance = M2 / (n - 1)`.

The two deltas are the point. `delta` measures how surprising the sample was
before the mean moved, `delta2` how far it still is after. Their product is the
exact correction that carries the sum of squares from the old mean to the new
one in a single step, with no stored history and no cancellation.

**Recency cap.** After long uptime `n` grows large, `delta / n` approaches
zero, and the mean freezes. The sample count is capped at 500. Once capped
every sample still runs the full update, and `M2` also decays exponentially so
the variance stays consistent with the mean's fixed recency window.

That makes this a bounded memory approximation of Welford's algorithm once
capped, not exact running variance. Cite it as such rather than as a direct
implementation of Welford (1962).

**Warm up.** The first 200 windows are excluded from anomaly evaluation.
Variance on a handful of samples is meaningless.

**Golden test.** `[4, 7, 13, 16]` gives mean 10.0 and variance 30.0 exactly,
verified on every test run.

## Smoothed Rate

**File:** `stage1/src/ewma.rs`

A packet rate that reacts to floods without being thrown by one bursty interval
or a scheduling delay.

The rate is computed once per window from the window's own elapsed time, not
per packet. Per packet updates suffer badly from timing jitter caused by
interrupt coalescing and virtualisation scheduling.

```
window_rate = packets_received / window_duration_seconds
ewma_new    = alpha * window_rate + (1 - alpha) * ewma_old
```

`alpha` controls responsiveness and is set with `--alpha`. Higher reacts faster
and is noisier, lower is smoother and slower. The default of 0.125 is a
conventional starting point for exponential smoothing, not a value proven
optimal for this use.

**It never resets.** Unlike entropy, which is computed fresh each window, the
rate carries memory across windows deliberately. A flood that ramps up
gradually is still caught because the accumulated rate keeps rising.

## Shannon Source Entropy

**File:** `stage1/src/entropy.rs`

Packet count alone cannot separate a flood from a flash crowd, since both are
high volume. Counting unique addresses misses the shape of the distribution:
ten addresses sending five packets each looks identical to one sending 41 and
nine sending one. Entropy captures the whole distribution in one number.

```
H_raw  = -sum( p(x) * log2(p(x)) )
H_norm = H_raw / log2(N)              N = unique source addresses
```

| Traffic | Normalized entropy |
|-|-|
| All packets from one address | 0.00, total concentration |
| Somewhat mixed | around 0.50 |
| Evenly spread | 1.00, maximum diversity |

Entropy falls during a concentrated flood, so the alarm fires when it drops
below its boundary rather than above.

**It resets every window.** The counter is cleared after each computation.
Entropy describes this window's diversity, not a trend. The trend is what the
Welford accumulator holds.

**A sample size gate applies.** An empty window scores 0.0, which is
indistinguishable from a maximally concentrated flood. Windows below a minimum
packet count therefore cannot raise an entropy anomaly, which also covers the
handful of packets from a single source that a quiet period produces.

### Spoofing Inverts This

A randomized source flood forges a different address on nearly every packet.
That raises entropy toward 1.0 and drives the dominant source ratio toward
zero, presenting as the opposite of the signature above.

Two consequences follow, neither hypothetical:

The entropy alarm cannot fire, because entropy is high rather than low.

The rate alarm is harder to trip. Entropy guided scaling widens `k` when
entropy is high, so a high entropy flood raises its own detection threshold.
Only the fixed emergency multiplier still applies.

Such a flood below that bar tends to be classified as a flash crowd.
Enforcement would not help much even if it were classified correctly: blocking
forged addresses punishes whoever really owns them and leaves the attacker
untouched.

Closing this needs features invariant under address forgery, which this
pipeline does not extract: source port entropy, TTL variance, and TCP option
fingerprint diversity. That is planned work, not a configuration change.

## The Anomaly Boundary

**Files:** `stage1/src/welford.rs`, `analysis.rs`, `state.rs`

| Metric | Fires when | Meaning |
|-|-|-|
| Rate | `r > mean_r + k * sigma_r` | Volume above normal |
| Entropy | `h < mean_h - k * sigma_h` | Diversity collapsed |

`k` defaults to 2.0 and is set with `--k`. Two standard deviations covers about
95 percent of a normal distribution.

Flags are a bitmask:

| Flag | Meaning |
|-|-|
| `0x01` | Rate only. Volumetric but diverse, possibly a flash crowd |
| `0x02` | Entropy only. Concentrated, lower volume |
| `0x03` | Both. High volume from a concentrated source |

Stage 2 takes this flag plus the rest of the feature vector and makes the final
call.

## Baseline Poisoning Defences

Two complementary mechanisms, not one.

**Freeze on anomaly.** Samples only enter the accumulator when the window is
clean and not in cooldown. During an active or recently resolved anomaly the
baseline stops updating entirely. This is what stops a slow ramp attacker from
dragging "normal" up to include their own flood.

**Recency cap.** Described above. On its own the cap would make the baseline
*more* poisonable, since shorter memory is easier to shift. The freeze is what
makes it safe. A recency cap without the freeze would be a net loss.

On top of both: a ceiling on the mean rate, rejection of outliers beyond five
sigma, and reversion to a peacetime reference if the mean drifts more than 50
percent from an ultra slow reference average.

## Baseline Persistence

**File:** `stage1/src/persistence.rs`

Baselines live in memory, so any restart wipes them and forces a fresh warm up.
The real risk is not the downtime. If the restart happens while an attack is
running, warm up builds "normal" directly out of attack traffic, with no
peacetime reference to anchor it.

**Only clean windows are saved.** The periodic save is triggered from the same
gate that decides whether to feed a sample into the accumulator live. The file
on disk therefore can never be a mid attack snapshot. A crash during a flood
reloads whatever the last good baseline was before it started.

**It does not wait for a clean shutdown.** Saving only on shutdown does nothing
when power is lost. A snapshot every 45 seconds means the worst case is losing
the last 45 seconds of drift, never the whole baseline.

Every write is atomic, a temporary file followed by a rename, so a power loss
mid write leaves the previous complete file rather than a corrupt one. A
missing or unparseable file is treated exactly like no prior baseline: a fresh
warm up, not a crash.

**A one hour TTL, not indefinite.** The recency cap already treats anything
older than a few minutes of continuous traffic as not fully trustworthy.
Reloading a multi hour old baseline would contradict that and risk resurrecting
one from a different point in the daily cycle, an overnight baseline loaded
into a busy afternoon. The default is sized for "the process just restarted",
not "resume from last week".

**What is saved:** per protected host, both accumulators, the smoothed rate,
the cooldown counter, and both peacetime references. One JSON file under
`/var/lib`, chosen so it survives a reboot.
