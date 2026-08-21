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

**A sample size gate applies.** Entropy is 0.0 both for an empty window and for
one where a single client happened to be the only one active. Neither is a
flood, and on the entropy figure alone neither is distinguishable from one.

Windows below `--entropy-min-packets` (default 100) therefore cannot raise an
entropy anomaly. Concentration only means something when there were enough
packets for it to be surprising: "every packet came from one source" is
trivially true when there was one participant.

This is deliberately separate from the threshold that decides when a window
closes, which is much lower. Sharing one number would mean that raising the
anomaly bar silently changed the windowing.

### Spoofing Inverts This

A randomized source flood forges a different address on nearly every packet.
That raises entropy toward 1.0 and drives the dominant source ratio toward
zero, presenting as the opposite of the signature above.

Two consequences follow, neither hypothetical:

The entropy alarm cannot fire, because entropy is high rather than low.

The rate alarm is harder to trip. Entropy guided scaling widens `k` when
entropy is high, so a high entropy flood raises its own detection threshold.
Only the emergency multiplier still applies: a rate more than
`--emergency-volume-sigma` (default 10.0) standard deviations above the mean
bypasses entropy scaling regardless of how high entropy has climbed.

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

### Bounds on Sigma

Both standard deviations are clamped, and the floors matter more than the
ceilings.

| Setting | Default |
|-|-|
| `--entropy-sigma-floor` | 0.05 |
| `--entropy-sigma-ceiling` | 0.15 |
| `--rate-sigma-floor` | 50.0 |
| `--rate-sigma-ceiling-ratio` | 0.2 |
| `--rate-sigma-ceiling-floor` | 10000.0 |

Without a floor the boundary collapses onto the mean. Entropy is normalized to
[0, 1], so a baseline learned during uniform traffic produces a standard
deviation near zero, `mean - k * sigma` lands on `mean`, and about half of
ordinary windows fall below their own mean by definition. That is a degenerate
statistic, not a sensitive detector, and it spends the margin needed to
recognise a real flood.

The rate sigma ceiling is `--rate-sigma-ceiling-ratio` of the mean, or
`--rate-sigma-ceiling-floor`, whichever is larger, so the boundary can widen
with genuinely variable traffic without drifting so far that nothing ever
trips it.

The defaults are starting points, not values proven optimal. The right floor
depends on how much a given network's traffic naturally varies, which is why
it is a flag rather than a constant.

### Choosing Targets

Protect the services, not the machine in front of them. A gateway carries its
own management traffic, from many sources, at a volume and variability that
has nothing in common with the hosts behind it, and its address usually sits
in the same range. `--victim-subnet` sweeps it in; `--victim-ips` does not.

Including one is expensive twice over. Its spread sets the global floors, so
every real target is measured against a number derived from infrastructure.
And because those floors then fit it badly, it flags continuously, which means
the enforcement tiers throttle the sources talking to it. On a gateway those
sources are the operators and the management plane.

The symptom is a host that flags a large fraction of its windows on rate while
entropy stays near maximum and dominance stays low. That combination is
distributed legitimate traffic, not an attack. Removing one such host from a
four target set took the remaining three from roughly a fifth of their windows
flagged to none.

If a gateway genuinely needs protecting, it needs its own baseline, which
means its own sensor.

### Measuring the Floors

`scripts/calibrate.py` derives both floors from the sensor's own log rather
than from a guess. It reads the per window debug lines out of the journal,
keeps only the windows the sensor treated as ordinary (cooldown at zero, so
neither an anomaly nor one of the windows following one), and waits until
every protected host has 1000 of them.

For each host it takes the mean, the trimmed peak rate, the trimmed entropy
trough, and a median absolute deviation as a robust standard deviation. The
recommended floor is the larger of that spread and the value that puts the
boundary just past ordinary traffic:

```
rate floor    = max(robust_sigma(r), (peak_r * (1 + margin) - mean_r) / k)
entropy floor = max(robust_sigma(h), (mean_h - trough_h * (1 - margin)) / k)
```

`k` is read from the sensor's own startup line. The rate uses `--k` rather
than the entropy scaled `k` actually applied at runtime, because that scaling
only ever widens the boundary, so `--k` is the tightest case and gives the
larger floor.

One set of floors covers every target, so the widest host wins. Erring high
costs sensitivity on the quietest host; erring low flags the busiest one
continuously, which also freezes its baseline. The first is recoverable and
the second is not. The script warns when the per host values differ by more
than a factor of four, because one global value then fits neither.

That warning marks a real limit rather than a tuning inconvenience. The
baselines are per victim but the floors are global, so a set of protected
hosts carrying very different volumes cannot be fitted by one number. The
rate sigma *ceiling* already avoids this by scaling against each target's own
mean; the floor does not. See
[roadmap.md](roadmap.md#relative-sigma-floors).

```bash
sudo python3 scripts/calibrate.py --auto-debug              # measure, report
sudo python3 scripts/calibrate.py --auto-debug --apply      # measure and save
sudo python3 scripts/calibrate.py --since -6h               # reuse history
sudo python3 scripts/calibrate.py --reset                   # back to defaults
```

The per window samples are logged at debug level only, so `--auto-debug`
raises `RUST_LOG` for the run and lowers it again afterwards. It raises only
the analysis module, not every module, and checks after the restart that the
setting actually reached the service rather than waiting out the collection
timeout to find out. While no usable sample has arrived the script says which
of the two reasons applies: a host still in warm-up, named with its progress,
or nothing at debug level in the journal at all. `--apply` writes
`/etc/ddos_stage1/tuning.env`, which the unit reads through an optional
`EnvironmentFile` and expands at the end of `ExecStart`. Later flags win, so
a calibration overrides whatever the installer chose without the script
needing to know the interface, the targets, or the capture mode. Deleting the
file returns those values.

The script also reports when a host's traffic has outgrown its learned mean,
which is a state the baseline cannot leave on its own, since every flagged
window freezes it. `--clear-baseline` deletes the persisted file so the
sensor relearns at the current level.

### Cooldown

A real anomaly, evaluated against `--k` rather than the tightened boundary
below, opens a cooldown window of `--cooldown-windows` (default 10) windows.
Inside it, `k` is reduced by `--cooldown-k-factor` (default 0.5, floored at
1.0), so a target recovering from a resolved anomaly stays easier to
re-detect than it would under the ordinary boundary.

`--entropy-k-fallback` (default 0.8) is the divisor entropy guided k scaling
uses before a baseline entropy has been learned, i.e. during warm-up.

## Baseline Poisoning Defences

Two complementary mechanisms, not one.

**Freeze on anomaly.** Samples only enter the accumulator when the window is
clean and not in cooldown. During an active or recently resolved anomaly the
baseline stops updating entirely. This is what stops a slow ramp attacker from
dragging "normal" up to include their own flood.

**Recency cap.** Described above. On its own the cap would make the baseline
*more* poisonable, since shorter memory is easier to shift. The freeze is what
makes it safe. A recency cap without the freeze would be a net loss.

On top of both: a ceiling on the mean rate (`--rate-mean-cap`, default
10000.0 pps), rejection of outliers beyond `--outlier-sigma` (default 5.0)
standard deviations, and reversion to a peacetime reference if the mean
drifts more than 50 percent away from it. The reference itself is an EWMA
with weight `--peacetime-ewma-weight` (default 0.001), deliberately far
slower than `--alpha`: it needs to move slower than the mean it guards, or it
cannot distinguish drift from ordinary variation.

**The peacetime reference is seeded from the mean it guards.** It is an
extremely slow average, so it takes on the order of a thousand windows to
converge on its own. Seeding it from a single window instead sets it to
whatever that one moment happened to read, and comparing that against a mean
built from two hundred windows disagrees immediately. The guard then reports
ordinary variation as poisoning and overwrites a correctly learned baseline
with a worse number. Seeded from the mean, the two start in agreement and
diverge only when something genuinely drifts.

**One narrow exception to the freeze.** A window flagged only on entropy, at a
normal rate, with dominance below `--distributed-dominance`, still updates the
baseline. That combination cannot be a concentrated flood: low entropy means
concentration, and concentration would show as a high dominant ratio.

The exception exists because the freeze and a too tight boundary reinforce each
other. If the boundary sits close to the mean, ordinary windows get flagged,
the baseline stops updating, the standard deviation never grows to reflect real
variation, and the false positives sustain themselves. Every other flagged
window still freezes, so the slow ramp defence is unchanged.

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
