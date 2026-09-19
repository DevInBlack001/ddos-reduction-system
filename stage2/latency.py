"""
latency.py: per window latency figures for Stage 2, summarized as one log
line per interval so a benchmark can read them back from the journal.
"""

import math

KINDS = ("handoff", "inference", "enforcement", "window_to_rule", "busy")
# Samples kept per kind between two summaries. Extra samples are counted
# but not stored, so a burst cannot grow memory without bound.
MAX_SAMPLES_PER_KIND = 10000


class LatencyStats:
    def __init__(self):
        self._samples = {kind: [] for kind in KINDS}
        self._counts = {kind: 0 for kind in KINDS}

    def record(self, kind, milliseconds):
        if kind not in self._samples:
            raise KeyError(kind)
        self._counts[kind] += 1
        if len(self._samples[kind]) < MAX_SAMPLES_PER_KIND:
            self._samples[kind].append(milliseconds)

    def has_samples(self):
        return any(self._counts.values())

    def summary_line(self, interval_secs):
        """One key=value line for the interval, then start a new one."""
        parts = ["Latency: summary", f"interval_secs={interval_secs:g}"]
        for kind in KINDS:
            values = sorted(self._samples[kind])
            count = self._counts[kind]
            if not values:
                parts.append(f"{kind}_n=0")
                continue
            rank = max(0, math.ceil(0.95 * len(values)) - 1)
            parts.append(
                f"{kind}_n={count} {kind}_mean_ms={sum(values) / len(values):.3f} "
                f"{kind}_p95_ms={values[rank]:.3f} {kind}_max_ms={values[-1]:.3f}"
            )
        self._samples = {kind: [] for kind in KINDS}
        self._counts = {kind: 0 for kind in KINDS}
        return " | ".join(parts)
