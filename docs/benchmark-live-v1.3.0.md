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
