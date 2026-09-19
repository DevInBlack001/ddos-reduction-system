# Live Benchmark: v1.3.0

Full results of a seven-phase traffic campaign run in the simulated lab
environment against the deployed gateway with `scripts/benchmark_live.sh`,
extended in this release from
four phases to the complete sequence below. Where
[Benchmark Results](benchmark-results.md) answers "does the trained model
generalize," this answers "does the deployed pipeline, warm-up, hysteresis,
block tiers, and confidence gated labeling all included, behave the way
that implies."

## Environment

Same gateway `benchmark-results.md` describes, inside the simulated lab
environment. Traffic is generated with Locust (Normal, Flash Crowd) and hping3
(Attacker) against five protected hosts, from separate generator machines that
are not the gateway. Sigma floors were re-derived the same day by
`scripts/calibrate.py` against a 100 simulated user load (`--rate-sigma-floor 7.8
--entropy-sigma-floor 0.4944 --entropy-sigma-ceiling 0.9`), and the
RandomForest, Isolation Forest, and second model were all retrained the
same day, before this run.

## Phases

Each traffic type introduced alone first, then every pairwise
combination, then all three together. Session ran 06:53:33 to 07:27:37
UTC, roughly 34 minutes, warm-up included.

| Phase | Stage 1 flags | DDoS verdicts | Enforcement actions | Result |
|---|---:|---:|---:|---|
| Normal | 0 | 0 | 0 | Clean |
| Flash Crowd | 2,313 | 0 | 0 | 0.0% false positive |
| Attacker | 2,220 | 115 | 2,459 | Mitigated |
| Normal + Flash Crowd | 88 | 33 | 713 | 37.5%, small sample |
| Normal + Attacker | 2,498 | 1,047 | 2,400 | 41.9% escalation |
| Flash Crowd + Attacker | 2,490 | 1,364 | 3,248 | 54.8% escalation |
| All three | 2,795 | 2,796 | 3,438 | 100% escalation |

Firewall state at close: 0 blocked, 198 rate-limited.

The Normal + Flash Crowd row follows the Attacker phase directly. Runs on
2026-09-18 showed that verdicts logged in the first second or two of a phase
that follows an attack come from the previous generator still stopping, not
from the traffic the phase is meant to test. Some of this row's 33 verdicts
may be of that kind. The original logs were not kept, so it cannot be
checked.

The Attacker phase's 5.2% figure counts only hysteresis gated "Class-2
window" log lines, a narrower metric than actual enforcement volume.
2,459 real rate-limit actions fired in that phase; most mitigation on a
pure attack phase happens through immediate per-source rate-limiting
before the hysteresis threshold is ever reached.

## The Isolation Forest's "Anomalous" label

The Isolation Forest labeled nearly every Normal and Flash Crowd window
`Anomalous` in its own log, even freshly retrained the same day. An earlier
version of this section called that correct operation, on the reasoning that
the lab's live traffic profile differs from a captured session. A check on
2026-09-18 points to a tuning mismatch as the main cause.

The training corpus was captured under the old sigma floors (`sigma_h`
around 0.05 to 0.08, `sigma_r` pinned at 50.0 in 57% of rows). The gateway
runs recalibrated floors, so its rows carry `sigma_h` 0.4944 and a different
`sigma_r` range. The Random Forest barely uses those two columns (importance
0.0015 and 0.0020). The Isolation Forest fits on all of them. Scored against
3,000 auto-labeled Normal rows from the gateway, it flags 100% as outliers
as they stand and 27.3% once only `sigma_h` and `sigma_r` are swapped into
the corpus's range. For Flash Crowd rows the figures are 100% and 0.0%.

The label never drives enforcement on its own, and the zero enforcement
actions during Normal and Flash Crowd above confirm that directly. The
blocking decision belongs to the RandomForest, whose 0% false positive rate
on real Flash Crowd traffic is the number that matters. The corpus and the
deployed floors need to be captured under the same tuning for `Anomalous` to
mean what it says. See [Training](training.md#capture-under-the-tuning-you-deploy).

This is exactly the situation confidence gated automatic labeling
(`stage2/auto_label.py`, this release's own milestone) exists to resolve
without a person reviewing every window by hand. A manual run against
the queue this session generated (31,463 rows) auto-labeled 9,538 of
them (7,336 Normal, 2,202 Flash Crowd, 0 DDoS), checked afterward for
degenerate zero-traffic rows and found none.

## On generalization

The offline benchmark's precision figures come from Leave-One-Session-Out
cross-validation: a model that memorized rows would fail its own held-out
fold. This session's live traffic was generated fresh the same morning
and never existed in any training file before it; correctly classifying
traffic that never existed is a property of a learned decision boundary,
checked directly against freshly generated traffic in the simulated lab
environment.

The limit: every training session and this benchmark ran on the
same lab topology, the same five targets, the same subnet, the same
generator toolkit. These results demonstrate generalization across
traffic sessions on this network. Portability to a network
with a different structure from the simulated lab environment is a separate,
open question this benchmark does not answer.

## Reproducing this

```bash
cp scripts/benchmark_live.example.env my-benchmark.env
# edit my-benchmark.env: gateway, generator hosts, SSH keys, targets
bash scripts/benchmark_live.sh my-benchmark.env
```

Needs a running deployment reachable by SSH, and generator hosts with
whatever load tooling your start/stop commands invoke (this run used
`locust` and `hping3`, both already present on the lab VMs). Wall time
scales with the phase durations in the config; this run's seven phases
totaled just over 30 minutes plus warm-up.

## Distribution-shift follow-up

A separate, smaller follow-up on the same deployment, same day, testing a
real question the seven-phase run above cannot answer on its own: every
training session and that benchmark ran on one lab topology, so the
numbers above show generalization across traffic sessions on this
network, not portability to a different one. No retrain for this
follow-up; the same models from the run above scored everything, a
static-transfer test.

**What was actually tested, and what was not.** The original plan
covered two kinds of distribution shift: the traffic generator's own
shape (request timing, protocol weighting) and the network path itself
(latency, jitter, loss, MTU). Only the first was achievable here. The
lab's attacker and flash-crowd VMs have no outbound internet access, so
`tc` could not be installed on them to shape traffic at the source.
Applying `tc netem` on the sensor's own capture interface instead
(`ens192`, XDP attached in driver mode) silently broke packet counting:
generated traffic kept flowing and received HTTP responses the whole time, but
the kernel backend reported zero ingress packets, and removing the
`netem` qdisc afterward did not restore it. Only a full restart of
`ddos-stage1` brought capture back. Confirmed this was the qdisc change
itself, not the MTU change alone, by reverting MTU first and observing
capture stayed broken. Worth knowing on its own: modifying `tc` qdisc
state on an XDP driver-mode interface can silently disable capture
without detaching the program or logging an error.

**What ran instead.** Two new generators, same targets, same source
pools, deliberately different traffic shape: a bursty-polling Locust
variant (short rapid-request bursts separated by long idle gaps, instead
of the baseline's smooth uniform wait) for Normal traffic, and a
protocol-reweighted attack variant (roughly 70% UDP, 30% SYN, instead of
the baseline's even three-way split across SYN, UDP, and ICMP) for
Attacker traffic. Flash Crowd reused the unchanged generator. The
`ddos-stage1` restart needed to recover capture also reset warm-up and
the learned baseline, so this run started from a freshly relearned,
less mature baseline than the seven-phase run above had.

| Phase | Stage 1 flags | DDoS verdicts | Enforcement actions | Result |
|---|---:|---:|---:|---|
| Normal (shape B) | 0 | 0 | 0 | Clean |
| Flash Crowd (unchanged) | 2,065 | 2 | 92 | ~0.1% escalated, not 0% |
| Attacker (shape B) | 1,983 | 0 | 2,147 | Real mitigation held |

Normal held clean under a request-timing pattern the model had never
seen. Attacker held under a protocol mix the model had never seen,
2,147 real enforcement actions is comparable mitigation strength to the
original run's 2,459, even though the hysteresis-gated Class-2 log line
count reads lower here for the same reason noted above. Flash Crowd is
the one real blemish: 2 windows escalated to DDoS this time, against a
clean 0 in the original run. It cannot be cleanly attributed to shape
variation alone, since Flash Crowd's own generator was not varied here;
the freshly relearned baseline from the forced restart is a real,
unresolved confound. It is recorded separately from the clean seven-phase
numbers above.

**Still open.** Network-path-level distribution shift, latency, jitter,
loss, MTU, an added routing hop, remains untested. It needs either
internet access on the generator VMs to install `tc` there, or applying
`netem` somewhere that is not the sensor's own XDP-bound interface.

## System-health recording: first run

`scripts/benchmark_live.sh` gained a system-health sampler this
session: real CPU time and memory for both services over the whole
run, and real packet throughput and drop counts parsed from the
capture backend's own existing periodic log line. A run against the
gateway on 2026-09-18 confirms the tooling itself works correctly
against the deployed gateway in the simulated lab environment, as well as the
synthetic test it was built against. The packet counts for the kernel backend were wrong at first: the
kernel status line resets its counters every interval, so each line is that
interval's own count, and the analysis read it as a running total. Fixed
after the 1.5.0 reruns by summing the samples inside a phase, and checked
against an independent sum of the raw log.

**Confirmed from the raw session output**, independently reproducible
with `python3 scripts/analyze_live_benchmark.py <output-dir>`:

| Service | Avg CPU (whole session) | Peak RSS | Restarts |
|---|---:|---:|---:|
| Stage 1 | ~2.3% | 7.2 MB | 0 |
| Stage 2 | ~28% | 306.4 MB | 0 |

774 samples over roughly 33 minutes, PID unchanged throughout for both
services. Total detection activity for the session: 73 Class-2 (DDoS)
verdicts, 2,492 mitigation actions, ending at 32 hard blocks and 132
rate-limits, all directly reproducible from `stage2.log` and the final
`ipset` dump.

**What this run does not establish.** `benchmark_live.sh`'s own phase
tracking stopped recording four phases early, `phase_boundaries.tsv`
has no boundary past "Normal + Flash Crowd," while the real detection
activity above continued for roughly 35 more minutes after that. That
means the phase-by-phase breakdown a normal run reports, and
specifically the number that matters most for this project's own
thesis, whether Flash Crowd traffic ever escalated to a DDoS verdict,
cannot be reconstructed from this session's artifacts. The totals above
are real; which phase produced which verdict is not known for most of
this run. A clean rerun with working phase attribution is planned
before this run's numbers are treated as a detection-accuracy result.

## Reruns on 2026-09-18

Four more full campaigns ran the same day. Only one has intact files to check
against (17:10 to 17:28 UTC, "run 4"), and the first rerun (14:14 to 14:32,
"run 1") was checked before its files were overwritten.

| Phase | Run 1 flags / verdicts | Run 4 flags / verdicts |
|---|---:|---:|
| Normal | 0 / 0 | 0 / 0 |
| Flash Crowd | 0 / 0 | 0 / 0 |
| Attacker | 1,689 / 28 | 1,670 / 600 |
| Normal + Flash Crowd | 296 / 0 | 52 / 0 |
| Normal + Attacker | 1,444 / 32 | 1,432 / 560 |
| Flash Crowd + Attacker | 1,428 / 0 | 1,375 / 1,003 |
| All three | 1,715 / 2 | 1,667 / 1,199 |

Every phase without an attacker has no real false positive verdict in either
run. The 7 verdict lines in run 4's Normal + Flash Crowd phase are stamped in
its first 1.2 seconds, the attacker generator stopping.

**The two runs cannot be compared for escalation.** Run 1 changed nothing
during the session. Each later run recalibrated the sigma floors during its
own first phase from about 35 windows (rate floor 29.4, then 2.9, then 3.2,
against about 6,200 windows per target in the calibration behind the original
7.8), restarted `ddos-stage1` several times, and had NetworkManager restarted
on the gateway every two minutes. Run 4's journal shows five clean
`ddos-stage1` restarts, two of them inside the attacker phase. Escalation
rose from 0 to 2% in run 1 to 36 to 73% in run 4, and the tuning changes and
restarts are enough to account for that without any change in detection
quality. A benchmark that shows a real difference needs the sigma floors set
before the session starts and left alone until it ends.

Total kernel ingress per run varied from 1.8 million to 5.6 million packets
across the reruns. Restarting NetworkManager to keep packets flowing suggests
capture stalled at times, the silent failure described above for `tc`
changes. That has not been investigated.
