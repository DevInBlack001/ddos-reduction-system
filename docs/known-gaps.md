# Known Gaps

See [Roadmap](roadmap.md) for planned milestones and
[Lessons Learned](lessons-learned.md) for gaps that were here and are now
closed.

**Randomized source spoofing detection is shipped but unproven.** V7 added
the features meant to close this: source port entropy, TTL variance, and
TCP option fingerprint diversity, all invariant under address forgery,
computed and sent over the wire on both capture backends. But on the
current training set, `source_port_entropy` ranks fourth of fourteen
features by importance, and `ttl_variance` and `fingerprint_diversity`
contribute almost nothing, consistent with a single-topology capture
(one hop count, one attack tool's TCP stack) rather than a defect in the
features themselves. See [detection.md](detection.md). Closing this needs
a more topologically varied capture.

**Distributed, low rate connection and flow state pressure is not
detected.** A low rate accumulation of long lived or half open
connections, or an equivalent build up of low rate UDP pseudo flows,
spread across many real, non spoofed sources reads as normal rate and
high entropy today, the same numbers a legitimate high traffic period
produces. Nothing in the current feature set measures accumulation over
more than one window or the completion state of a flow. It needs the V13
features, not a configuration change.

**The source histogram is attacker fillable.** Its key includes the source
address and it holds a bounded number of entries. A randomized source
flood fills it, after which entropy is computed from a truncated
histogram. Memory stays bounded, which is the part that matters, but the
measurement degrades under exactly the attack class above.

`--max-sources` raises the bound without rebuilding the object, which buys
accuracy under a wider flood. It does not close the exposure: measured on
2026-08-22 at a peak of 17,962 packets per second sustained across the
flood phase, from roughly 2,200 distinct addresses, `SOURCES` reached
2,190 of its 65,536 entries and `FLOWS` reached 2,212 of 8,192, error
counter at zero throughout; `FLOWS` is the tighter of the two at 27%
occupancy. A randomized source flood forging a source per packet at the
same rate would fill `SOURCES` in under four seconds and a million in
under a minute: the map holds under a real flood's address count, and
degrades once an attacker targets the key itself. `dominant_ip_ratio`
shares the exposure, since it reads from the same per-source counts.

The map is exact: once full, `bump()`'s `insert()` call for a new key
simply fails and is discarded (`stage1-ebpf/src/main.rs`), so packets from
any source past the 65,536th distinct one are invisible to both entropy
and dominance for the rest of the window. `--max-sources` moves that
line, not what happens at it.

Proposed fix, not yet built: replace the exact per-source `HashMap` with a
Count-Min Sketch, a fixed-size counter array a packet always increments
regardless of how many distinct sources have been seen, so no packet goes
uncounted no matter how wide the flood spreads its addresses. The
tradeoff is hash-collision noise in the frequency estimate rather than a
capacity wall; that noise is bounded by the sketch's width and settles at
a known error rate for a given traffic volume, unlike the current
structure's failure mode, which degrades without bound as the flood grows
past the cap. A small fixed-size heavy-hitter structure (Misra-Gries or
Space-Saving) alongside it would give `dominant_ip_ratio` the same
protection. Needs the same measurement discipline V7's histograms got: a
real flood before trusting the entropy figures it produces.

**One rate figure is unexplained but not concerning.** Measured on
2026-08-22 comparing the two capture backends: the two quiet hosts agreed
within 7%; the busiest differed by 18%. With packet counts agreeing within
6% at the capture layer and entropy within 1%, that reads as traffic
variation on the most variable host across runs 14 minutes apart, not a
measurement difference. Pinning it needs a generator producing a
repeatable load, run once per backend.

Two traps when repeating this. The capture counters are not directly
comparable: libpcap's `raw_captured` is cumulative per interface, while
the kernel's `ingress` is per drain interval, so the first must be read as
a final value and the second as a sum. And the comparison must be
restricted to equivalent phases. Totalling a whole run makes the backends
look 49% apart, which is entirely the flood phase differing in peak and
duration between two runs of a generator that does not repeat exactly.

**The training set and the deployed sigma floors are captured under
different tuning.** The canonical training set has `sigma_h` near 0.05 to
0.08 and `sigma_r` pinned at 50.0 in 57% of rows. A gateway running
recalibrated floors writes `sigma_h` 0.4944, later 0.2263 and about 0.08,
and a different `sigma_r` range. The Random Forest ignores both columns,
the Isolation Forest does not: measured 2026-09-18, it flags 100% of the
gateway's Normal and Flash Crowd rows as outliers, and 27.3% and 0.0% with
only those two columns swapped into the training set's range. This
accounts for most of the Isolation Forest labeling nearly every live
window `Anomalous`. Fixing it takes a recapture of all three labels under
the floors that will be deployed, or training the Isolation Forest on rows
from the deployed regime. Until then, do not merge gateway captures into
the older training set. See
[training.md](training.md#capture-under-the-tuning-you-deploy).

**The confidence gate depends on tree depth.** The depth sweep picks depth
3 (tied with 4 and 5 at 0.997). At depth 3 the Random Forest's probability
on live DDoS windows tops out near 0.86, so a 0.90 gate accepts 2.7% to
26% of them depending on which rows a run sees, and 71% of the rejected
rows sit between 0.85 and 0.90. At depth 4 the same rows clear 0.90 93% of
the time with the same accuracy. The gate at depth 3 is close to
arbitrary, and at depth 4 it passes nearly everything the two models
agree on. The independent check is the second model. Open: choose a depth
rule, or a threshold, that makes the gate mean something. See
[training.md](training.md#confidence-and-tree-depth).
