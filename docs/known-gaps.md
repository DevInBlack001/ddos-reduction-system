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
