# Roadmap

Milestones are numbered V1 upward. Release tags do not match those numbers:
V1 through V5 shipped as 0.1 through 0.5, with patches up to 0.5.5 closing the
0.x line. V6 ships as 1.0.0, because it changes the architecture rather than
adding to it.

Each milestone is developed on its own branch and merged into master once it
works, and the tag follows the merge.

## Completed

**V1, initial pipeline.** Feature extraction and the first dashboard.

**V2, adaptive baselines.** Entropy guided thresholds, cluster rate limiting,
and the baseline poisoning defences.

**V3, multi target scaling.** Several protected hosts tracked concurrently on
one ingress interface, each with its own baseline.

**V4, baseline persistence.** Baselines saved and restored across restarts, so
a restart during an attack cannot build "normal" out of attack traffic.

**V5, egress processing.** A second capture thread on the egress interface,
making drop effectiveness a measurement rather than an inference. Also NAT safe
enforcement: addresses marked as shared are throttled but never hard blocked.

**V6, XDP and eBPF acceleration.** Packet counting moved into the driver path
using Aya, so it happens before the kernel builds a socket buffer per packet.
Selected with `--capture-mode kernel`, alongside the original libpcap backend
rather than replacing it.

The one structural break in the roadmap. Counters live in kernel maps that user
space drains once per window, instead of a packet at a time crossing a channel.
Everything else on this list is additive by comparison.

Detection did not move. There is no floating point in BPF, so entropy, the
rate, and every boundary stay in user space exactly where they were.

Tuning became measurable in the same milestone. `scripts/calibrate.py` derives
the sigma floors from the sensor's own window log rather than leaving an
operator to read journal excerpts by hand, and every value it can set is a
flag with a documented default rather than a constant.

## Planned

**V7, evasion resistant features and a second model.** On branch `v7`, code
complete, not yet merged or tagged. Two parts.

Part one adds source port entropy, TTL variance, and TCP fingerprint
diversity as features. Those three are invariant under source address
forgery, which is what makes them the answer to both randomized source
spoofing and large NAT crowds reading as single source floods. See
[detection.md](detection.md) for why the pre-V7 feature set cannot see
either.

Computed from new per window histograms keyed by the field value itself, port
number, TTL, fingerprint bucket, not by source address. `SOURCES` is capped
because address space is effectively unbounded for an attacker to spread
across; port and TTL space are not (16 and 8 bit fields), so a value keyed
histogram has a fixed ceiling regardless of how many addresses or packets a
flood uses. Extending `SOURCES` itself instead would inherit its fillability
problem at exactly the moment a randomized source flood makes it matter most.

Part two adds a second model rather than a voting layer over several: an
Isolation Forest, unsupervised, trained on the same feature set with the
label column unused, running in production alongside the existing
RandomForest rather than replacing or gating it. It answers a different
question than the RandomForest does, not what class a window looks like but
whether it looks like anything the training data contained at all, which is
what closes the gap a supervised model cannot: an attack shaped differently
from anything captured has no guaranteed reason to trip a classifier trained
only on what it was shown. Surfaced as a distinct `Anomalous` state; it does
not drive enforcement in this milestone. See
[enforcement.md](enforcement.md#classification) and
[training.md](training.md#the-isolation-forest).

Verified against a real 35,442 row, 12 session capture: RandomForest LOSO
accuracy 0.989, DDoS precision 0.97 and recall 0.98. The eBPF side has since
loaded and run on the sensor VM: the verifier accepted both programs, all
seven maps bound, and the kernel and libpcap backends agreed within 1.1% on
entropy and 4 to 6% on ingress packet counts. The non-technical explainer is
written, [docs/explainer.md](explainer.md). Still open before this merges:
dashboard visibility for the three raw features.

A retrain against jittered traffic generators, rather than the scripted,
mechanically regular timing the original 35,442 row capture used, is
done: 25,449 rows across three fresh sessions per label, real `sigma_r`
variation confirmed across every label, LOSO accuracy 0.982. See
[Benchmark](#benchmark-flod-vs-fixed-threshold) below for what that
recapture made possible.

**V8, automated playbooks.** Granular incident reports and multi stage response
playbooks executed during severe events.

**V9, federated peer signalling.** Cooperating gateways exchange authenticated
advisory reports, so the peer that owns an address, the only party able to see
individual hosts behind its own NAT, investigates and acts locally instead of
the receiving gateway blackholing a shared address.

Conceptually aligned with IETF DOTS. Requires mutual authentication and a
static peer registry, and applies only within a federation of cooperating
gateways, not to arbitrary sources.

**V10, multi interface aggregation.** Traffic statistics aggregated across
several parallel ingress uplinks.

Deferred behind everything above because the current topology uses its two
interfaces as the ingress and egress of a single path, not as parallel uplinks.
There is nothing to aggregate yet.

## Relative Sigma Floors

The sigma floors are global while the baselines they bound are per victim, so
a set of protected hosts carrying different volumes cannot be fitted by one
value. Measured across three hosts spanning 3.7 times in mean rate, the per
host rate floors spanned 4.4 times. Expressed as a fraction of each host's own
mean they spanned 1.2 times, sitting between 0.22 and 0.26.

The consequence is uneven sensitivity. One global floor sized for the busiest
host leaves the quietest needing several times its own normal volume before
anything trips, while sizing it for the quietest flags the busiest
continuously. A flagged window then freezes the baseline, because the
`window_is_clean()` exception covers an entropy only flag and a busy host
trips on rate, so the standard deviation cannot grow to reflect the variation
that caused it. That is the same failure the entropy floor once had, on the
other axis.

The effect is much worse when a host that is not a protected service ends up
in the target set. A gateway carrying its own management traffic measured
seven times the volume of the services behind it, pushing the floor span to
8.9 times and flagging a third of its own windows as attacks. Excluding it
took every remaining host to zero flagged windows. A relative floor reduces
the sensitivity spread, but it does not make it correct to protect
infrastructure alongside the services it fronts.

The intended fix mirrors what the rate sigma *ceiling* already does, one line
below in the same expression: scale against the target's own mean, keeping
the absolute flag as a backstop for a target still near zero during warm-up.

```
floor_r = max(rate_sigma_floor_ratio * mean_r, rate_sigma_floor)
```

Explicit per target overrides were considered and deferred. Targets are
created on first sight, so a table calibrated today has no entry for a host
that appears tomorrow and a global fallback is needed regardless. A ratio
already yields a different floor per target, derived from that target's own
traffic, and follows it as the traffic changes. An override belongs on top of
that later if some host proves the ratio wrong for it specifically.

One invariant needs asserting at startup as part of this work: the floor must
stay below the ceiling. A floor ratio near 0.30 exceeds the default ceiling
ratio of 0.20, and `raw.max(floor).min(ceiling)` resolves that silently in the
ceiling's favour, producing a smaller sigma than either setting intends. It is
currently masked because `rate_sigma_ceiling_floor` holds the ceiling at a
flat value at ordinary volumes.

## Known Gaps

Not roadmap items, but currently true and worth stating plainly.

**Randomized source spoofing is not detected.** Covered in
[detection.md](detection.md). It needs the V7 features, not a configuration
change.

**The source histogram is attacker fillable.** Its key includes the source
address and it holds a bounded number of entries. A randomized source flood
fills it, after which entropy is computed from a truncated histogram. Memory
stays bounded, which is the part that matters, but the measurement degrades
under exactly the attack class above.

`--max-sources` raises the bound without rebuilding the object, which buys
accuracy under a wider flood. It does not close the exposure: at the rate
measured above, a flood forging a source per packet fills 65,536 entries in
under four seconds and a million in under a minute. Whether V7's features are
derived from this structure or from something not attacker keyed is a decision
for the start of that milestone.

**Rows written before this release carry the wrong entropy.** `log_incident`
used to read the most recent window across all protected hosts, so an action
taken for one host could be stamped with another's measurement, and an
unrecorded value was stored as zero rather than null. Both are fixed, but
existing rows were not rewritten, because the correct value for them is not
recoverable. Zero entropy on a row older than this release means unknown.

**The kernel maps hold under a flood.** Measured on 2026-08-22 at a peak of
17,962 packets per second sustained across the flood phase: `SOURCES` reached
2,190 of its 65,536 entries and `FLOWS` reached 2,212 of 8,192, with the error
counter at zero across all 116 drain intervals and the drain count steady
throughout.

That flood came from roughly 2,200 distinct addresses, which is the shape being
claimed here. `FLOWS` is the tighter of the two at 27% occupancy, so a flood
from four times as many sources would fill it. A randomized source flood at the
same packet rate would fill `SOURCES` in under four seconds, which is the
attacker fillable case described below rather than a contradiction of this
result.

Both backends have also been exercised across the same scenario set: ordinary
traffic, a flash crowd, a flood, and the mixed cases. Both handled all of them.

**Entropy is preserved across the two backends.** Measured on 2026-08-22, over
200 warm-up windows per protected host on each backend, with no persisted
baseline available so each learned its own: the mean entropy differed by 1.1%,
0.9%, and 0.2% across the three hosts. Warm-up windows report the raw rate and
entropy before any boundary is computed, so the figures are unaffected by the
two runs carrying different tuning.

**The two see the same packets.** Over the steady phase of the same runs,
before the load generator ramped, ingress counts agreed within 4 to 6%. Both
runs carried the same sequence of ordinary traffic, a ramp, and a flood, and
their profiles track each other throughout.

**One rate figure is unexplained but not concerning.** The two quiet hosts
agreed within 7%; the busiest differed by 18%. With packet counts agreeing
within 6% at the capture layer and entropy within 1%, that reads as traffic
variation on the most variable host across runs 14 minutes apart, not a
measurement difference. Pinning it needs a generator producing a repeatable
load, run once per backend.

Two traps when repeating this. The capture counters are not directly
comparable: libpcap's `raw_captured` is cumulative per interface, while the
kernel's `ingress` is per drain interval, so the first must be read as a final
value and the second as a sum. And the comparison must be restricted to
equivalent phases. Totalling a whole run makes the backends look 49% apart,
which is entirely the flood phase differing in peak and duration between two
runs of a generator that does not repeat exactly.

No throughput comparison has been made. That is a separate question from
whether detection is preserved, and less important.

**Scripted traffic generators can make the rate look artificially steady,
fixed by jittering generator timing.** `sigma_r`, the standard deviation
Stage 1 learns for a target's rate, comes from window to window variation
in a smoothed EWMA rate. A load testing tool or flood tool that paces every
request or packet on a fixed, regular interval, rather than the
independent, uncoordinated timing real clients or a real botnet have,
produces almost no such variation, so `sigma_r` reads at or near its
configured floor for the entire capture regardless of how much traffic is
actually flowing. A training set built this way teaches a model "this
traffic is mechanically regular" rather than the intended class signature,
which will not transfer to traffic with natural jitter. Fixed on the
generator side: randomised inter request wait time, varying the active
source or user count over the session rather than holding it flat, and
avoiding an unpaced flood mode in favour of short, randomised bursts.
Confirmed on a real recapture, real `sigma_r` variation across every label
rather than a value pinned at the floor. See [training.md](training.md).

## Benchmark: FLOD vs. Fixed Threshold

`scripts/benchmark_fixed_threshold.py` answers the question this
project's own thesis rests on: does an adaptive boundary actually beat a
static one, on real captured data, not just in the abstract. Run
offline against an already-captured training CSV, no live traffic
needed. FLOD's own side of the comparison is the trained RandomForest
evaluated by Leave-One-Session-Out, the same held-out methodology
`stage2/train.py`'s own accuracy claims already rest on, not a
hand-derived proxy. The fixed-threshold side is one constant, some
multiple of the observed mean Normal rate, chosen once before scoring
either arm.

Three scenarios: Normal, Flash Crowd, DDoS, the classes the training
data's label column actually carries. Run against a fresh 25,449 row,
nine session capture with jittered generator timing: LOSO accuracy
0.982, FLOD precision 100.0% and recall 95.4% with a 0.0% false
positive rate, against the fixed threshold's precision 52.1%, recall
100.0%, and a 57.9% false positive rate. The number that matters most:
of real Flash Crowd traffic, FLOD correctly left 100.0% alone, the
fixed threshold flagged all of it as an attack. A threshold set low
enough to catch the DDoS sessions here catches the legitimate surge
too, because both read as an elevated rate and rate is the only signal
a fixed threshold has.

```bash
python3 scripts/benchmark_fixed_threshold.py <path-to-training.csv>
```

## References

1. T. Bai et al., "ATS-DTA: Adaptive two-stage DDoS detection," *Cybersecurity*, vol. 9, 2026.
2. S. Abiramasundari and V. Ramaswamy, "DDoS detection using supervised ML," *Scientific Reports*, 2025.
3. E. Cohen and M. Strauss, "Maintaining time-decaying stream aggregates," *Journal of Algorithms*, 2004.
4. W. Eddy, "TCP SYN Flooding Attacks and Common Mitigations," RFC 4987, IETF, 2007.
5. NIST SP 800-61 Rev. 2, "Computer Security Incident Handling Guide," 2012.
