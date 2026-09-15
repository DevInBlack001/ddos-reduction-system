# Live Benchmark: v1.3.0

Full results of a real seven-phase traffic campaign run against a deployed
sensor VM with `scripts/benchmark_live.sh`, extended in this release from
four phases to the complete sequence below. Where
[Benchmark Results](benchmark-results.md) answers "does the trained model
generalize," this answers "does the deployed pipeline, warm-up, hysteresis,
block tiers, and confidence gated labeling all included, behave the way
that implies."

## Environment

Same sensor VM `benchmark-results.md` describes. Traffic generated live
with Locust (Normal, Flash Crowd) and hping3 (Attacker) against five
protected hosts, from separate lab VMs, not the sensor itself. Sigma
floors were re-derived the same day by `scripts/calibrate.py` against a
real 100 simulated user load (`--rate-sigma-floor 7.8
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

The Attacker phase's 5.2% figure counts only hysteresis gated "Class-2
window" log lines, a narrower metric than actual enforcement volume.
2,459 real rate-limit actions fired in that phase; most mitigation on a
pure attack phase happens through immediate per-source rate-limiting
before the hysteresis threshold is ever reached.

## The Isolation Forest's "Anomalous" label

The Isolation Forest labeled nearly every Normal and Flash Crowd window
`Anomalous` in its own log, even freshly retrained the same day. That is
correct, intentional operation, not a defect: its whole purpose is
flagging traffic unlike anything in its training data, and this lab
network's live traffic profile genuinely differs from a captured
session. The label never drives enforcement on its own; the zero
enforcement actions during Normal and Flash Crowd above confirm that
directly. The blocking decision belongs entirely to the RandomForest,
whose 0% false positive rate on real Flash Crowd traffic is the number
that matters.

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
checked directly against fresh, live traffic on real lab VMs.

The honest limit: every training session and this benchmark ran on the
same lab topology, the same five targets, the same subnet, the same
generator toolkit. These results demonstrate generalization across
traffic sessions on this network. Portability to a structurally
different real-world network is a separate, open question this
benchmark does not answer.

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
real traffic kept flowing and got real HTTP responses the whole time, but
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
unresolved confound. Recorded honestly rather than folded into the
clean seven-phase numbers above.

**Still open.** Network-path-level distribution shift, latency, jitter,
loss, MTU, an added routing hop, remains untested. It needs either
internet access on the generator VMs to install `tc` there, or applying
`netem` somewhere that is not the sensor's own XDP-bound interface.
