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

**V7, evasion resistant features and a second model.** Shipped as
`1.2.0`. Two parts.

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
label column unused, running alongside the existing
RandomForest rather than replacing or gating it. It answers a different
question than the RandomForest does, not what class a window looks like but
whether it looks like anything the training data contained at all, which is
what closes the gap a supervised model cannot: an attack shaped differently
from anything captured has no guaranteed reason to trip a classifier trained
only on what it was shown. Surfaced as a distinct `Anomalous` state; it does
not drive enforcement in this milestone. See
[enforcement.md](enforcement.md#classification) and
[training.md](training.md#the-isolation-forest).

Verified against a 35,442 row, 12 session capture from the simulated lab environment: RandomForest LOSO
accuracy 0.989, DDoS precision 0.97 and recall 0.98. The eBPF side has since
loaded and run on the lab gateway: the verifier accepted both programs, all
seven maps bound, and the kernel and libpcap backends agreed within 1.1% on
entropy and 4 to 6% on ingress packet counts. The non-technical explainer is
written, [docs/explainer.md](explainer.md). Dashboard visibility for the
three raw features is also done.

A retrain against jittered traffic generators, rather than the scripted,
mechanically regular timing the original 35,442 row capture used, is
done: 25,449 new rows across nine fresh sessions, merged with the
original capture into a 60,891 row, 21 session dataset, `sigma_r`
variation confirmed across every label, RandomForest LOSO accuracy
0.997 on the full merged set. See
[Benchmark](#benchmark-flod-vs-fixed-threshold) below for what that
recapture made possible.

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
of the milestones that followed V7 for exactly that reason.

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

Confirmed in the simulated lab environment. The first unattended run of
`ddos-stage2-auto-label.timer` against captured data auto-labeled
32,597 rows, surfacing two findings. The
freshness safeguard first blocked labeling entirely, correctly: the
deployed RandomForest predated every captured row, so nothing could clear
the "trained after capture" check until `ddos-stage2-retrain.timer` (see
[training.md](training.md#periodic-retraining)) gave it something to
retrain against. Once that ran, 32,595 of the 32,597 labeled rows turned
out to be zero-traffic windows both models agreed on for the wrong reason:
a shared blind spot in the training set. See
[training.md](training.md#degenerate-windows-are-never-auto-labeled) for
the guard this added. The retrain timer itself also only covered the RF
and second model; the Isolation Forest, which depends on neither
safeguard, stayed on the model trained at initial setup until a live
functional test found the consequence directly: benign generated
traffic scored `Anomalous` on effectively every window, fixed by chaining
`train_isolation_forest.py` into the same retrain run.

`scripts/calibrate.py` was also re-run on the lab gateway against a
100-simulated-user load, deriving `--rate-sigma-floor 7.8
--entropy-sigma-floor 0.4944 --entropy-sigma-ceiling 0.9` from actually
observed traffic rather than the shipped defaults. A full seven-phase live
benchmark (`scripts/benchmark_live.sh`, extended this session from four
phases to the full sequence: Normal, Flash Crowd, Attacker, every pairwise
mix, then all three together) then ran against the freshly calibrated,
freshly retrained deployment: zero Stage 1 flags on pure Normal traffic,
0% of Flash Crowd traffic escalated to DDoS, 100% escalation once all
three traffic types combined. Full results:
[Live Benchmark: v1.3.0](benchmark-live-v1.3.0.md).

Shipped as `1.4.0`: a dashboard page for reviewing and merging or
discarding a completed run's staged rows without needing the terminal
(see [training.md](training.md#reviewing-from-the-dashboard)), and
`scripts/benchmark_live.sh` gained a system-health sampler, real CPU
time, memory, and packet throughput for both services over a session,
not only detection outcomes. See [Live Benchmark:
v1.3.0](benchmark-live-v1.3.0.md#system-health-recording-first-run)
for the first run's results.

`1.4.1` made the depth and leaf node sweeps prefer the simplest candidate
within a tolerance of the best accuracy. `1.5.0` added `ddos_capture.csv`, a
third capture file, so automatic labeling can stage DDoS rows. `1.6.0` added
paging to the Auto Label review page, so a staged queue larger than 500 rows
can be reviewed in full. `1.6.1` stopped Stage 2 from waiting on the auto-label
job, limited enforcement to the flows of the host under attack, chose the
Random Forest's tree depth by how often its answers clear the confidence
threshold, and added the live benchmark that compares the kernel and libpcap
capture backends.

## Planned

V9 through V14 below are ordered by difficulty, easiest first, so the
milestone number is a build-order estimate that carries no ranking of
importance. Kernel level work has consistently
been the most expensive part of this project to get right (the eBPF
milestone's own "compiled, passed its own tests, and did nothing" episode,
recorded elsewhere in this project's notes, is the cautionary example),
which is why the firewall backend work below sits behind the playbook work
despite being smaller in surface area. V15 and V16 are exceptions to that
ordering, both appended after the fact rather than slotted in by
difficulty: V15 sits last because it is the only one with no path to
validation right now, and V16 because it was decided after V9 through V15
were already numbered, even though in practice it is small, self
contained in `stage1/src/analysis.rs`, and worth doing ahead of V9 rather
than in number order.

**V9, operator defined playbooks, granular incident reporting, and a redesigned
web interface.** The
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

The reports also gain system performance, for the incident's own time range and
beside the detection figures. The live benchmark already measures what would go
in: packets per second through the gateway and how many were dropped at
capture, the interface and the firewall, Stage 1 and Stage 2 CPU and memory,
context switches, the Stage 2 latency breakdown (handoff from the sensor,
inference, the enforcement call, and window close to rule applied), the time
from the start of an attack to the first DDoS verdict and the first block, and
how consistently the verdict held. A reader can then tell whether the gateway
was under strain while it mitigated. Today those figures exist only as
benchmark output read from the journal and a sampler, so Stage 2 would first
need to keep them itself: the latency summary it already logs every 30 seconds
and periodic samples of its own and Stage 1's counters, stored with the same
retention as the incident data.

The whole web interface is redesigned in the same milestone. The console is
functional and plain: static styling, no motion, and nothing that gives a first
time visitor a reason to keep looking, which limits how many people will try the
project however well the detection works. The redesign covers the layout,
typography and color, the charts, and motion where it helps someone read the
state of the gateway, across every page under `stage2/static/`. It sits in V9
because the playbook builder and the redesigned reports are new pages, and
building them on the old styling would mean designing them twice. Not designed
yet, and it should be checked in a browser as it is built.

Large in surface area (a new schema, a new dashboard builder, a stateful
per host execution engine, and a redesign of every page) but entirely
application level, no verifier to satisfy and no kernel programming risk, which
is why it ranks below V8 on raw scope but above V10 on difficulty.

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

**V14, kernel space inference and enforcement.** Since V6 the kernel counts
packets and user space decides. V14 moves the decision and the drop into the
kernel together: the trained Random Forest is compiled into an eBPF program,
so a verdict and the drop it triggers both happen at XDP, before the kernel
builds a socket buffer for the packet. The goal is fast inference and fast
enforcement at once.

The user space Random Forest stays in place as a fallback. If the kernel
program fails to load, is rejected by the verifier, fails its equivalence
check, or errors at runtime, the sensor reverts to the user space classifier
and enforcement path that runs today and keeps protecting the hosts. A kernel
fault degrades to V6 behaviour with a logged reason and a dashboard
indicator, and never takes the sensor down. The time that switch takes is a
number worth setting a target for. The live benchmark already measures the
same quantities for a capture mode change: downtime while the sensor
restarts, and rollback time back to the previous mode.

Placement. V14 comes after V13 for two reasons. It reuses what V10 builds:
the XDP blocking path, verifier experience, map based policy lookup, and
swapping a program in place. And it compiles against a fixed feature set, and
V13 is the last milestone on the roadmap that changes the features. The
fixed feature set stops being a blocker once the program is regenerated every
time the model retrains, potentially daily. A feature change from V13 then
becomes one more reason to recompile. The compile step joins the retrain
cycle V8 built, so it cannot drift into a separate file that goes stale:

1. Retrain the model (the V8 timer).
2. Compile it to an eBPF program.
3. Check the program against the user space model on identical inputs, and
   proceed only when the answers match. This check is a requirement for the
   design and is not built yet.
4. Swap the program into XDP through the V10 path.

Risks to check early. First, where the time goes. FLOD classifies once per
window and classifies no individual packet. If the slow part is collecting
the window, moving the classifier alone will not cut response time. The live
benchmark records the pieces of that path (window close to Stage 2 handoff,
inference, the enforcement call, and window close to rule applied) so the
breakdown can be measured during an attack in the simulated lab environment before any kernel work starts.
Second, floating point. Entropy and rates use it and BPF has none, so the
design needs an answer for how those features are produced inside the
kernel. Third, program size: a forest of trees per window has to fit the
verifier's instruction and stack limits.

Suggested order of work: prototype on its own branch after V10 lands, and
prove that the kernel output matches the user space model before anything
else. Treat the prototype as exploration. It becomes a committed milestone
once it earns that.

**V15, out-of-band, mirror-port deployment mode.** Not started, and blocked
on hardware: suitable switch or router mirror/SPAN capability is not
available yet to validate against, since the whole point is behaviour a
virtual switch or Linux bridge can only approximate. FLOD today sits on the
forwarding path, an ingress and an egress interface belonging to the same
box that enforces. This is a second deployment mode alongside that one, not
a replacement for it: a switch or router mirrors (SPANs) a copy of its
traffic to FLOD, which runs the existing detection pipeline unchanged,
entropy, the baselines, the models, and instead of enforcing locally with
iptables and ipset, sends a mitigation policy back to the forwarding device
to apply as an ACL or rate limit. Detection stays out of the forwarding
path entirely; a mirror port copies traffic rather than delaying it, so
nothing here adds a hop to normal forwarding.

The tradeoff is that mitigation becomes a feedback loop rather than a local
decision, so the time from detection to enforcement is a new quantity worth
measuring on its own: mirror delivery, feature extraction, classification,
policy generation, and rule application, each as its own figure, plus how
much traffic reaches the protected network during that window. V10's
firewall backend abstraction is related but not sufficient by itself: V10
chooses which local mechanism enforces on the same box, where this needs a
policy sent to and applied on a separate device entirely, authenticated,
with the same conservative handling of an uncertain classification this
project already applies locally, rule expiration and safe removal, and a
cap on how quickly new rules can be created. Early development does not
need real switching hardware: a virtual switch, a Linux bridge, or a mock
enforcement adapter behind an abstract ACL and rate-limit interface is
enough to build and test the feedback loop itself, with real hardware kept
as a later validation step once the pipeline works. Ranked last because it
is the only planned milestone with no path to validation right now, not
because of scope or difficulty.

**V16, relative sigma floors.** The rate and entropy sigma floors are
global while the baselines they bound are per victim, so one set of
protected hosts carrying different volumes cannot be fitted by a single
value. Measured across three hosts spanning 3.7 times in mean rate, the
per host rate floors spanned 4.4 times; expressed as a fraction of each
host's own mean they spanned only 1.2 times, sitting between 0.22 and
0.26.

The consequence is uneven sensitivity. A global floor sized for the
busiest host leaves the quietest needing several times its own normal
volume before anything trips, while sizing it for the quietest flags the
busiest continuously. A flagged window then freezes the baseline, since
the `window_is_clean()` exception covers an entropy only flag and a busy
host trips on rate, so the standard deviation cannot grow to reflect the
variation that caused it: the same failure the entropy floor once had, on
the other axis. It is worse when a host that is not a protected service
ends up in the target set; a gateway carrying seven times the volume of
the services behind it pushed the floor span to 8.9 times and flagged a
third of its own windows, and excluding it took every remaining host to
zero flagged windows.

The fix mirrors what the rate sigma ceiling already does one line below
in the same expression: scale against the target's own mean, keeping the
absolute floor as a backstop for a target still near zero during warm-up.

```
floor_r = max(rate_sigma_floor_ratio * mean_r, rate_sigma_floor)
```

Explicit per target overrides were considered and deferred. Targets are
created on first sight, so a table calibrated today has no entry for a
host that appears tomorrow, and a global fallback is needed regardless. A
ratio already yields a different floor per target, derived from that
target's own traffic, and follows it as the traffic changes; an override
belongs on top of that later if some host proves the ratio wrong for it
specifically.

One invariant needs asserting at startup as part of this work: the floor
must stay below the ceiling. A floor ratio near 0.30 exceeds the default
ceiling ratio of 0.20, and `raw.max(floor).min(ceiling)` resolves that
silently in the ceiling's favour, producing a smaller sigma than either
setting intends. Currently masked because `rate_sigma_ceiling_floor` holds
the ceiling at a flat value at ordinary volumes.

Appended after V15 rather than placed by difficulty among V9 through V14,
the same way V13 and V15 were: a later addition to an already ordered set,
not a reordering of it. Smaller and lower risk than any of them,
contained to `stage1/src/analysis.rs`, `AnalysisConfig`, and a CLI flag,
with no wire format or kernel change, so its actual build order can run
ahead of its number.

**A possible future as a plugin for other platforms.** No milestone number,
and not a commitment: a direction to keep in mind. FLOD runs today as its own
gateway on Linux, with Stage 1 on the packet path and Stage 2 enforcing
through iptables and ipset. Firewall and router platforms such as OPNsense
and pfSense have plugin systems, and packaging FLOD as a plugin would let
people use it inside a firewall they already run. The main obstacle is that
those two are FreeBSD based and use pf, so neither the XDP and TC capture
nor the ipset enforcement would carry over. A port would need a capture
backend and an enforcement backend for each platform, with detection
(entropy, the baselines, the models) staying as it is, since it does not
depend on either. V10's firewall backend abstraction is the natural
starting point, and a libpcap capture already exists as the portable
option. Platforms that are Linux based would be closer to a packaging job.
Which platforms, and whether the effort is worth it, is undecided.

## Known Gaps

Moved to a dedicated file: [known-gaps.md](known-gaps.md). Gaps that have
since closed live in [Lessons Learned](lessons-learned.md).

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
