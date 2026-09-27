# Known Gaps

See [Roadmap](roadmap.md) for planned milestones and
[Lessons Learned](lessons-learned.md) for gaps that were here and are now
closed. Ordered easiest and most self-contained first, hardest and most
resource-dependent last.

**The confidence gate depends on tree depth.** The depth sweep picks depth
3 (tied with 4 and 5 at 0.997). At depth 3 the Random Forest's probability
on live DDoS windows tops out near 0.86, so a 0.90 gate accepts 2.7% to
26% of them depending on which rows a run sees, and 71% of the rejected
rows sit between 0.85 and 0.90. At depth 4 the same rows clear 0.90 93% of
the time with the same accuracy. Choosing a depth rule or a threshold that
makes the gate meaningful is open. Tuning work against data already in
hand, no capture or infrastructure needed. See
[training.md](training.md#confidence-and-tree-depth).

**The training set and the deployed sigma floors are captured under
different tuning.** The canonical training set has `sigma_h` near 0.05 to
0.08 and `sigma_r` pinned at 50.0 in 57% of rows. A gateway running
recalibrated floors writes `sigma_h` 0.4944, later 0.2263 and about 0.08,
and a different `sigma_r` range. The Random Forest ignores both columns,
the Isolation Forest measured 2026-09-18 flags 100% of the gateway's
Normal and Flash Crowd rows as outliers, 27.3% and 0.0% with only those
two columns swapped into the training set's range. This accounts for most
of the Isolation Forest labeling nearly every live window `Anomalous`.
Fixing it takes a recapture of all three labels under the floors that
will be deployed, or training the Isolation Forest on rows from the
deployed regime. Do not merge gateway captures into the older training
set until then. Resolvable with the lab environment already available,
a recapture session, no new hardware or milestone. See
[training.md](training.md#capture-under-the-tuning-you-deploy).

**Randomized source spoofing detection is shipped but unproven.** V7 added
the features meant to close this: source port entropy, TTL variance, and
TCP option fingerprint diversity, all invariant under address forgery,
computed and sent over the wire on both capture backends. On the current
training set, `source_port_entropy` ranks fourth of fourteen features by
importance, and `ttl_variance` and `fingerprint_diversity` contribute
almost nothing, consistent with a single-topology capture, one hop count,
one attack tool's TCP stack. See [detection.md](detection.md). Closing
this needs a more topologically varied capture, more lab setup than the
two gaps above but nothing outside the current lab environment.

**Distributed, low rate connection and flow state pressure is not
detected.** A low rate accumulation of long lived or half open
connections, or an equivalent build up of low rate UDP pseudo flows,
spread across many real, non spoofed sources reads as normal rate and
high entropy today, the same numbers a legitimate high traffic period
produces. Nothing in the current feature set measures accumulation over
more than one window or the completion state of a flow. Closing this
needs the wire format and capture backend changes V15 already plans;
blocked on that milestone rather than open on its own.

**A new institution with no prior logs has nothing to train the first
models on.** Stage 1's baseline calibration works from zero: warm-up
learns a target's own rate and entropy from its live traffic starting at
first boot, and `scripts/calibrate.py` derives sigma floors the same way,
no prior dataset needed. The RandomForest and Isolation Forest are fit
offline against a labeled feature CSV, and a fresh deployment has no such
CSV of its own. It structurally cannot generate the DDoS or Flash Crowd
rows within any reasonable pilot window: an institution's network will
not organically produce a real attack or a real surge to label just
because a sensor is watching. Once a first model exists for a given
institution, the rest of the pipeline already handles ongoing
improvement: `anomalous_capture.csv`, confidence gated auto labeling, and
periodic retraining were all built for that. The open question is where
the very first labeled DDoS and Flash Crowd rows for a brand new network
come from.

If the institution already keeps its own traffic logs, those can be
labeled against that institution's own history, sidestepping the cold
start for the sessions the logs already cover. Not every institution
will have logs in a usable form, or logs covering an actual attack or
surge, so this only closes the gap where it happens to apply. No
milestone on the roadmap covers this; it depends on a specific
institution's cooperation, authorization, and possibly hardware to
generate seed traffic on their network, resources outside the project's
own lab environment, which is why it sits last. Open.
