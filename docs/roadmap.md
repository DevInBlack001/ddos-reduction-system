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

## Planned

**V6, XDP and eBPF acceleration.** Move packet processing into the driver path
using Aya, so filtering happens before the kernel builds a socket buffer per
packet.

This is the one structural break in the roadmap. Capture largely stops existing
as it is written today, counters move into kernel maps read from user space,
and dropping happens in XDP rather than through ipset. Everything else on this
list is additive by comparison.

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

## Known Gaps

Not roadmap items, but currently true and worth stating plainly.

**Entropy false positives on consistent traffic.** When normal traffic is very
uniform, the variance is small, so the boundary sits close to the mean and
ordinary fluctuation crosses it. Raising the multiplier or the absolute floors
works around it. A floor under the variance estimate is the likely fix.

**Randomized source spoofing is not detected.** Covered in
[detection.md](detection.md). It needs the V7 features, not a configuration
change.

## References

1. T. Bai et al., "ATS-DTA: Adaptive two-stage DDoS detection," *Cybersecurity*, vol. 9, 2026.
2. S. Abiramasundari and V. Ramaswamy, "DDoS detection using supervised ML," *Scientific Reports*, 2025.
3. E. Cohen and M. Strauss, "Maintaining time-decaying stream aggregates," *Journal of Algorithms*, 2004.
4. W. Eddy, "TCP SYN Flooding Attacks and Common Mitigations," RFC 4987, IETF, 2007.
5. NIST SP 800-61 Rev. 2, "Computer Security Incident Handling Guide," 2012.
