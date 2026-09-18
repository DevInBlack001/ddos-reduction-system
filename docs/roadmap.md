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
Selected with `--capture-mode kernel`, alongside the original libpcap backend.

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
written, [docs/explainer.md](explainer.md). Dashboard visibility for the
three raw features is also done.

A retrain against jittered traffic generators, rather than the scripted,
mechanically regular timing the original 35,442 row capture used, is
done: 25,449 new rows across nine fresh sessions, merged with the
original capture into a 60,891 row, 21 session dataset, real `sigma_r`
variation confirmed across every label, RandomForest LOSO accuracy
0.997 on the full merged set. See
[Benchmark](#benchmark-flod-vs-fixed-threshold) below for what that
recapture made possible.

V8 through V12 below are ordered by difficulty rather than by any priority
between them, easiest first, so the milestone number is a build-order
estimate, not a ranking of importance. Kernel level work has consistently
been the most expensive part of this project to get right (the eBPF
milestone's own "compiled, passed its own tests, and did nothing" episode,
recorded elsewhere in this project's notes, is the cautionary example),
which is why the firewall backend work below sits behind the playbook work
despite being smaller in surface area.

**V8, confidence gated automatic labeling.** Passively collected network
logs, including Isolation Forest output and traffic captured before any
model has been trained on this deployment, are labeled automatically after
a configurable delay (hours to weeks, an operator setting rather than a
constant, per this project's own tuning convention) instead of requiring an
admin to label everything by hand. A human labeling a large volume of
traffic by hand is slow and error prone, but labeling all of it
automatically is not a safe substitute either.

Only windows a local model reads as confidently one class or another, far
from any decision boundary, are auto-labeled and folded into training data.
Anything ambiguous still lands in the existing human reviewed
`anomalous_capture.csv` queue rather than being labeled automatically. This
is a deliberate extension of, not a replacement for, the decision recorded
elsewhere in this project not to feed `Anomalous` windows back into training
automatically: doing that unconditionally reopens the same poisoning path,
shape traffic to sit near the boundary and get mislabeled, that the manual
review step exists to close. Keeping the ambiguous cases gated on a human
keeps that defence intact while removing most of the manual burden for the
large volume of traffic that is not ambiguous.

Self contained inside Stage 2: no new kernel level code and no new protocol,
built directly on models and a review queue that already exist. The easiest
of the five below for exactly that reason.

Shipped as `1.3.0`. "Confident" turned
out to need a second model rather than a threshold on the RandomForest's own
`predict_proba`: a `RandomForest` re-confirming its own margin on a row it
already has a blind spot for just reproduces that blind spot with new-found
confidence. `stage2/train_second_model.py` trains a
`HistGradientBoostingClassifier` on the same cleaned feature set, a
structurally different learning process (boosting corrects its own trees'
errors sequentially, rather than the RandomForest's bagged, independently
grown trees), and `stage2/auto_label.py` only stages a row once both models
agree on the class and both clear `AUTO_LABEL_CONFIDENCE_THRESHOLD` on it.

The delay is a single configurable setting
(`AUTO_LABEL_DELAY_HOURS`), not adjustable per label class. A second
safeguard sits alongside confidence and delay: both models must have been
trained after the row was captured, so a stale, unretrained model can never
confirm its own blind spot even with a second opinion agreeing. See
[training.md](training.md#confidence-gated-automatic-labeling).

A dedicated security review found and fixed concurrent file access, unbounded
capture growth, and resource contention issues; see [security.md](security.md#process-and-filesystem-isolation)
for the details.

Confirmed against a real run on the sensor VM. The first unattended run of
`ddos-stage2-auto-label.timer` against real captured data auto-labeled
32,597 rows, surfacing two real findings. The
freshness safeguard first blocked labeling entirely, correctly: the
deployed RandomForest predated every captured row, so nothing could clear
the "trained after capture" check until `ddos-stage2-retrain.timer` (see
[training.md](training.md#periodic-retraining)) gave it something to
retrain against. Once that ran, 32,595 of the 32,597 labeled rows turned
out to be zero-traffic windows both models agreed on for the wrong reason:
a shared blind spot in the training corpus. See
[training.md](training.md#degenerate-windows-are-never-auto-labeled) for
the guard this added. The retrain timer itself also only covered the RF
and second model; the Isolation Forest, which depends on neither
safeguard, stayed on the model trained at initial setup until a live
functional test found the consequence directly: genuinely benign live
traffic scored `Anomalous` on effectively every window, fixed by chaining
`train_isolation_forest.py` into the same retrain run.

`scripts/calibrate.py` was also re-run on the sensor VM against a real
100-simulated-user load, deriving `--rate-sigma-floor 7.8
--entropy-sigma-floor 0.4944 --entropy-sigma-ceiling 0.9` from actually
observed traffic rather than the shipped defaults. A full seven-phase live
benchmark (`scripts/benchmark_live.sh`, extended this session from four
phases to the full sequence: Normal, Flash Crowd, Attacker, every pairwise
mix, then all three together) then ran against the freshly calibrated,
freshly retrained deployment: zero Stage 1 flags on pure Normal traffic,
0% of Flash Crowd traffic escalated to DDoS, 100% escalation once all
three traffic types combined. Full results:
[Live Benchmark: v1.3.0](benchmark-live-v1.3.0.md). All fixes and the
benchmark script rewrite are on `v8`.

**V9, operator defined playbooks and granular incident reporting.** The
four existing enforcement tiers keep running automatically on every window
exactly as they do today; a playbook is a separate layer on top that starts
when a trigger condition fires and adds three kinds of stage the tiers do
not do on their own: escalate a target over time without waiting for an
operator, fire an external alert as a scripted step rather than a one shot
notification, and generate an incident report the moment the playbook
fires rather than waiting for one to be pulled later.

A playbook belongs to an operator, not to this codebase: different
deployments will want different sequences, so playbooks are defined, not
hardcoded, editable either through a form builder or as a JSON or YAML
document, both views round tripping to one stored definition rather than
being two separate systems. A trigger can be any of a tier being reached, a
run of consecutive attack classified windows past the existing hysteresis
count, or several protected hosts under attack at once, and a playbook may
combine more than one. Stages are linear, no branching, since nothing asked
of this milestone needs it and a conditional stage graph is a materially
bigger and harder to secure thing to build than the sequence anyone has
actually described wanting.

Incident reporting gains two things alongside this: a timeline of which
stage fired when and against which source or host, distinct from the
existing window by window classification log, and a per source breakdown
within a single incident rather than only the aggregate view the current
PDF and CSV export give.

Large in surface area (a new schema, a new dashboard builder, a stateful
per host execution engine) but entirely application level, no verifier to
satisfy and no kernel programming risk, which is why it ranks below V8 on
raw scope but above V10 on difficulty.

**V10, firewall backend abstraction.** Enforcement currently assumes
`iptables` and two `ipset`s unconditionally. Not every deployment runs
`iptables` as its live ruleset, some run `nftables` instead, sometimes with
`iptables` only present as a compatibility shim over it, and detecting
which one is actually managing the host's traffic and using that one,
rather than installing a second, competing ruleset, is the point of this
milestone.

A third candidate sits alongside the other two rather than replacing them:
blocking directly in an XDP program when the kernel capture backend
(`--capture-mode kernel`) is already loaded and running in driver mode,
which drops a packet before the kernel builds a socket buffer for it at
all, strictly cheaper per packet than either `nftables` or `iptables`
since both only see a packet after it has already gone further into the
stack. That gap matters most exactly during the highest packet rate
moment of a flood, which is when the cheapest possible drop path pays off
most. The advantage is conditional, not automatic: driver mode XDP support
is NIC and driver dependent the same way it already is for detection, so
on hardware without it, or when the pcap capture backend is active instead,
XDP is not a candidate at all and the choice is strictly `nftables` versus
`iptables`.

Ranked below V9 despite a smaller surface area because kernel level work
of any kind, XDP based blocking included, has been the consistently most
expensive category of work in this project to get right the first time,
where the application level playbook work above carries no equivalent
verifier or driver risk.

**V11, multi interface aggregation.** Traffic statistics aggregated across
several parallel ingress uplinks.

The code itself is likely not the hard part, it would reuse the per CPU
summing pattern already solved for the eBPF maps, but the milestone is
blocked on a topology that does not exist yet: the current deployment uses
its two interfaces as the ingress and egress of a single path, not as
parallel uplinks, so there is nothing to aggregate or verify against until
that changes. Ranked by readiness rather than by code difficulty for that
reason; revisit this position if a multi uplink topology becomes available
sooner than the milestones ranked above it are ready to build.

**V12, federated peer signalling.** Cooperating gateways exchange authenticated
advisory reports, so the peer that owns an address, the only party able to see
individual hosts behind its own NAT, investigates and acts locally instead of
the receiving gateway blackholing a shared address.

Conceptually aligned with IETF DOTS. Requires mutual authentication and a
static peer registry, and applies only within a federation of cooperating
gateways, not to arbitrary sources. The highest complexity and the highest
stakes of the five: a new wire protocol and a cross organization trust
boundary, where a design mistake means one gateway trusting another's report
it should not have.

**V13, connection and flow state pressure detection.** The window level rate
and entropy features, V7's port, TTL, and fingerprint histograms included,
all describe volume. None of them describe state: how many flows are open,
how long they stay open, or what fraction of a window's flows ever complete
a handshake. A distributed, low rate accumulation of long lived or half open
connections from many real, non spoofed sources reads as normal rate and
high entropy, the same numbers a legitimate high traffic period produces,
because nothing in the current feature set measures accumulation over more
than one window. Not limited to TCP: the same blind spot covers a UDP flood
built from many low rate pseudo flows that never carry a handshake to look
for in the first place, and it is the generalization this milestone targets,
not a TCP specific one.

Two parts, the same shape as V7.

Part one instruments both capture backends. `FLOWS` already tracks a
bounded set of flows; it gains a first seen timestamp and a small state
field, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, TIME_WAIT, updated from the
flags already being read off every packet. The state distribution itself is
exported as a bounded, value keyed histogram, the same principle V7's
`PORT_HIST` and `TTL_HIST` established: keyed by the state enum, not by
source or flow, so its size is fixed by the number of states rather than by
how many flows or addresses an attacker can generate. `FLOWS` staying flow
keyed is an accepted, stated tradeoff rather than a gap left unnoticed: a
flood built from many low rate flows is exactly the shape that grows
`FLOWS` fastest, the same caveat already carried by `SOURCES` and `FLOWS`
today, extended rather than newly introduced. The wire format gains the
state distribution counts, a connection duration accumulator, and open and
closed flow counts for the window; Stage 2 derives the ratios (established,
incomplete, long lived) and a growth rate from them. Multiple observation
timescales, the fast and slow accumulation the raw window alone cannot
show, come from a second EWMA decay constant over the existing per window
cadence rather than a second polling interval or a second window close
path, the delicate code this project has already decided not to touch
twice.

Part two is traffic generation and retraining, the harder half in practice
if this project's own history with generator timing is any guide. Three new
shapes: low rate TCP state exhaustion (many connections opened slowly, few
completed or closed), the same pattern spread across many real sources
rather than one, and a UDP pseudo flow equivalent. Captured, cleaned, and
merged into the training set the same way the V7 recapture was, retrained
with the existing RandomForest pipeline, and scored against the existing
Isolation Forest without retraining it first, since the point of an
unsupervised second model is to see whether it already reads the new class
as unlike its training data before it is ever shown one. Benchmarked
against the current, pre V13 model with `benchmark_fixed_threshold.py`'s
own LOSO methodology on the new classes specifically, not folded into the
aggregate accuracy figure where a small new class could hide inside a large
one.

Connection and flow state pressure becomes a new playbook trigger once V9
exists, and the mitigation response, rate limiting new connections versus
limiting concurrent connections per source versus the existing tiers, is a
playbook's job to sequence rather than a new enforcement tier grafted onto
the existing four. No new mitigation subsystem is built here for that
reason.

Appended after the five above rather than interleaved among them: it
changes both capture backends and the wire format a second time since V7,
real kernel and verifier risk on top of an already ordered set of
milestones, and is a new addition to the roadmap rather than a reordering
of what it already said.

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

**Distributed, low rate connection and flow state pressure is not detected.**
A low rate accumulation of long lived or half open connections, or an
equivalent build up of low rate UDP pseudo flows, spread across many real,
non spoofed sources reads as normal rate and high entropy today, the same
numbers a legitimate high traffic period produces. Nothing in the current
feature set measures accumulation over more than one window or the
completion state of a flow. It needs the V13 features, not a configuration
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
needed. Covers both trained models, not the RandomForest alone: the
RandomForest by Leave-One-Session-Out, the same held-out methodology
`stage2/train.py`'s own accuracy claims already rest on, and the
Isolation Forest under the same LOSO standard, which is stricter than
`stage2/train_isolation_forest.py`'s own self-evaluation (unsupervised,
so it has no held-out label to score against in production, but a
benchmark can hold it to a higher bar). Also reports real training
time, prediction latency and throughput, model size on disk, and this
process's own CPU time and peak memory, measured directly rather than
via an external sampler. Full methodology, hardware, and results:
[Benchmark Results](benchmark-results.md).

Three scenarios: Normal, Flash Crowd, DDoS, the classes the training
data's label column actually carries. Latest run, against the full
60,891 row, 21 session corrected dataset: RandomForest LOSO accuracy
0.997, precision 99.7%, recall 99.2%, false positive rate 0.1%. Fixed
threshold: precision 43.5%, recall 98.9%, false positive rate 52.5%.
The number that matters most: of real Flash Crowd traffic, the
RandomForest correctly left 100.0% alone, the fixed threshold flagged
all of it as an attack. A threshold set low enough to catch the DDoS
sessions here catches the legitimate surge too, because both read as an
elevated rate and rate is the only signal a fixed threshold has. The
Isolation Forest, evaluated the same way even though this is a narrower
question than what it is actually for, correctly left 100.0% of Flash
Crowd alone too.

```bash
python3 scripts/benchmark_fixed_threshold.py <path-to-training.csv>
```

## References

1. T. Bai et al., "ATS-DTA: Adaptive two-stage DDoS detection," *Cybersecurity*, vol. 9, 2026.
2. S. Abiramasundari and V. Ramaswamy, "DDoS detection using supervised ML," *Scientific Reports*, 2025.
3. E. Cohen and M. Strauss, "Maintaining time-decaying stream aggregates," *Journal of Algorithms*, 2004.
4. W. Eddy, "TCP SYN Flooding Attacks and Common Mitigations," RFC 4987, IETF, 2007.
5. NIST SP 800-61 Rev. 2, "Computer Security Incident Handling Guide," 2012.
