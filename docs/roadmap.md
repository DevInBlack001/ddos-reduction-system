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

**V7, ensemble classification.** A multi model voting layer for evasion and
stealth attacks, adding source port entropy, TTL variance, and TCP fingerprint
diversity as features.

Those three are the ones invariant under source address forgery, which is what
makes them the answer to both randomized source spoofing and large NAT crowds
reading as single source floods. See [detection.md](detection.md) for why the
current feature set cannot see either.

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
value. Measured on four hosts spanning roughly seven times in mean rate, the
per host rate floors spanned 8.9 times. Expressed as a fraction of each
host's own mean they spanned 1.2 times, and all four sat near 0.30.

The busiest host is the one that suffers. Its boundary lands inside its own
normal range, so ordinary traffic flags on rate at around 1.15 times the
boundary while entropy stays near maximum and dominance stays low, which is
the signature of distributed legitimate traffic rather than an attack. Every
one of those windows then freezes the baseline, because the
`window_is_clean()` exception covers an entropy only flag and this is a rate
flag, so the standard deviation cannot grow to reflect the variation that
caused it. That is the same failure the entropy floor once had, on the other
axis.

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

**Rows written before this release carry the wrong entropy.** `log_incident`
used to read the most recent window across all protected hosts, so an action
taken for one host could be stamped with another's measurement, and an
unrecorded value was stored as zero rather than null. Both are fixed, but
existing rows were not rewritten, because the correct value for them is not
recoverable. Zero entropy on a row older than this release means unknown.

**The kernel backend has not been measured under load.** It has been seen
working on ordinary traffic. How the maps behave during a real flood is
untested, and no throughput comparison against libpcap has been made.

## References

1. T. Bai et al., "ATS-DTA: Adaptive two-stage DDoS detection," *Cybersecurity*, vol. 9, 2026.
2. S. Abiramasundari and V. Ramaswamy, "DDoS detection using supervised ML," *Scientific Reports*, 2025.
3. E. Cohen and M. Strauss, "Maintaining time-decaying stream aggregates," *Journal of Algorithms*, 2004.
4. W. Eddy, "TCP SYN Flooding Attacks and Common Mitigations," RFC 4987, IETF, 2007.
5. NIST SP 800-61 Rev. 2, "Computer Security Incident Handling Guide," 2012.
