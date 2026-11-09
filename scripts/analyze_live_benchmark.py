#!/usr/bin/env python3
"""
analyze_live_benchmark.py: reports on a session captured by
scripts/benchmark_live.sh.

Give it a session directory (one subdirectory per backend run, for example
kernel_run1 and pcap_run1) and it prints each run's report, then a
comparison of the backends. Give it a single run directory and it prints
that run's report only.

Not directly comparable, row for row, to scripts/benchmark_fixed_threshold.py:
that script scores every post-warmup CSV row, this one only sees what Stage 1
actually forwarded to Stage 2 (anomaly-or-heartbeat windows), which is a
narrower view with a different denominator.

Usage: python3 scripts/analyze_live_benchmark.py <session-or-run-dir>
       [--zero-loss-capture-pct N] [--zero-loss-probe-pct N]
A run directory holds stage1.log, stage2.log, firewall.log,
phase_boundaries.tsv, and optionally system_samples.csv, clk_tck.txt,
firewall_counters.tsv, mode_switch.txt, run_info.txt, probe_rtt.csv (latency probe),
and limits.tsv (limit ladder).
"""

import argparse
import calendar
import csv
import json
import os
import re
import statistics
import sys
from datetime import datetime

MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
    "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}

PHASE_ORDER = (
    "normal", "flash_crowd", "attacker", "normal_flashcrowd",
    "normal_attacker", "flashcrowd_attacker", "all_three",
)
ATTACK_PHASES = ("attacker", "normal_attacker", "flashcrowd_attacker", "all_three")
# Phases where the attack generator starts from off. In the others it is
# already running from the previous phase.
FRESH_ATTACK_PHASES = ("attacker", "normal_attacker")
SWEEP_RE = re.compile(r"^(attacker|normal_attacker)_([a-z0-9_]{1,20})$")
LIMIT_RE = re.compile(r"^limit_([a-z0-9]{1,10})_(\d{1,9}|max)$")
# Defaults for what counts as loss-free in a limit step. Starting points, set
# with --zero-loss-capture-pct and --zero-loss-probe-pct.
ZERO_LOSS_CAPTURE_PCT = 99.0
ZERO_LOSS_PROBE_PCT = 1.0
BIN_SECS = 10
# Older than this, a boundary sample of a cumulative counter is treated as
# missing. The status lines come every 5 seconds while packets flow.
MAX_SAMPLE_AGE_SECS = 30
LATENCY_KINDS = ("handoff", "inference", "enforcement", "window_to_rule")

CLASS2_PATTERNS = (
    "Class-2 window",
    "Class-2 verdict but no active flow data",
    "Aggregate cap fallback: class-2 verdict",
)


def phase_info(name):
    """(known, is attack phase, attack starts from off in it, attack type).

    The seven standard phases have fixed names. The attack type sweep adds
    attacker_<type> (the attack alone, starting from off) and
    normal_attacker_<type> (the same attack with Normal traffic added).
    """
    if name in PHASE_ORDER:
        return True, name in ATTACK_PHASES, name in FRESH_ATTACK_PHASES, None
    if LIMIT_RE.match(name):
        return True, True, False, None
    m = SWEEP_RE.match(name)
    if m:
        return True, True, m.group(1) == "attacker", m.group(2)
    return False, False, False, None


def load_variants(run_dir):
    """phase -> {class: (variant, description)} from traffic_variants.tsv."""
    path = os.path.join(run_dir, "traffic_variants.tsv")
    result = {}
    if not os.path.exists(path):
        return result
    with open(path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3:
                result.setdefault(parts[0], {})[parts[1]] = (parts[2], parts[3] if len(parts) > 3 else "")
    return result


def to_dt(ts):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"unrecognized timestamp {ts!r}")


def seconds_between(start_ts, end_ts):
    return (to_dt(end_ts) - to_dt(start_ts)).total_seconds()


def load_phases(run_dir):
    path = os.path.join(run_dir, "phase_boundaries.tsv")
    phases = []
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            name, ts = line.split("\t")
            phases.append((name, ts))
    # Pair each phase with the timestamp of the one after it, so every phase
    # has a [start, end) window; the last one runs to session_end.
    return [(phases[i][0], phases[i][1], phases[i + 1][1]) for i in range(len(phases) - 1)]


TS_RE = re.compile(r"^(\w+)\s+(\d+) (\d{2}:\d{2}:\d{2})(\.\d+)?")


def line_time(line, year_hint):
    # journalctl's default format carries month and day but no year;
    # reconstruct a full "YYYY-MM-DD HH:MM:SS[.ffffff]" from each line's own
    # month/day rather than a single date captured once at the start of the
    # session. A benchmark run can cross midnight, and a single fixed date
    # silently drops every line after the rollover from every phase window.
    m = TS_RE.match(line)
    if not m:
        return None
    month_name, day, time_part, fraction = m.groups()
    month = MONTHS.get(month_name)
    if month is None:
        return None
    return f"{year_hint}-{month}-{int(day):02d} {time_part}{fraction or ''}"


def load_events(path, year_hint):
    """Every timestamped line of a journal capture as (timestamp, line)."""
    events = []
    with open(path) as f:
        for line in f:
            ts = line_time(line, year_hint)
            if ts is not None:
                events.append((ts, line))
    return events


def events_in(events, start_ts, end_ts):
    return [(ts, line) for ts, line in events if start_ts <= ts < end_ts]


CAPTURE_STATUS_RE = re.compile(
    r"Capture: status \| interface=(\S+) \| raw_captured=(\d+) \| timeouts=(\d+) "
    r"\| parse_failed=(\d+) \| non_ip=(\d+) \| truncated=(\d+) \| forwarded=(\d+)"
)
KERNEL_STATUS_RE = re.compile(
    r"Kernel: status \| interface=(\S+) \| ingress=(\d+) \| egress=(\d+) \| sources=\d+ "
    r"\([\d.]+% of map\) \| flows=(\d+) \| ports=(\d+) \| ttls=(\d+) \| fingerprints=(\d+) "
    r"\| drains=(\d+) \| errors=(\d+)"
)


def first_capture_interface(stage1_events):
    """The interface named by the first capture status line."""
    for _, line in stage1_events:
        m = CAPTURE_STATUS_RE.search(line) or KERNEL_STATUS_RE.search(line)
        if m:
            return m.group(1)
    return None


def parse_traffic_samples(stage1_events, interface=None):
    # Both capture backends already log a periodic status line at info level,
    # inside the same journalctl window this script already reads. With an
    # egress interface configured the libpcap backend runs one capture thread
    # per interface and each logs its own counters, so the lines of the two
    # interfaces interleave and must be kept apart: mixing them makes the
    # cumulative counters jump between two unrelated series.
    samples = []
    for ts, line in stage1_events:
        m = CAPTURE_STATUS_RE.search(line)
        if m and interface is not None and m.group(1) != interface:
            continue
        if m:
            samples.append((ts, "pcap", {
                "raw_captured": int(m.group(2)),
                "timeouts": int(m.group(3)),
                "parse_failed": int(m.group(4)),
                "non_ip": int(m.group(5)),
                "truncated": int(m.group(6)),
                "forwarded": int(m.group(7)),
            }))
            continue
        m = KERNEL_STATUS_RE.search(line)
        if m and interface is not None and m.group(1) != interface:
            continue
        if m:
            samples.append((ts, "kernel", {
                "ingress": int(m.group(2)),
                "egress": int(m.group(3)),
                "flows": int(m.group(4)),
                "ports": int(m.group(5)),
                "ttls": int(m.group(6)),
                "fingerprints": int(m.group(7)),
                "drains": int(m.group(8)),
                "errors": int(m.group(9)),
            }))
    return samples


def counters_at_or_before(samples, target_ts):
    # Every field in the pcap status line only ever increases across the
    # session, so the last sample at or before target_ts is the cumulative
    # total going into that instant.
    result = None
    for ts, backend, counters in samples:
        if ts > target_ts:
            break
        result = (backend, counters, ts)
    return result


def traffic_delta(samples, start_ts, end_ts):
    # The pcap status line carries running totals, so a phase is the last
    # sample minus the one before it. The kernel status line resets after
    # every log, each one is that interval's own count, so a phase is the
    # sum of the samples inside it.
    in_phase = [(b, c) for ts, b, c in samples if start_ts <= ts < end_ts]
    if in_phase and in_phase[0][0] == "kernel":
        total = {k: 0 for k in in_phase[0][1]}
        for _, counters in in_phase:
            for k, v in counters.items():
                total[k] += v
        return "kernel", total
    # The libpcap status line is only logged when a packet arrives, so a quiet
    # spell leaves a hole in the samples. A total taken across such a hole
    # would credit the previous phase's traffic to this one, so a boundary
    # sample that is too old is not used.
    before = counters_at_or_before(samples, start_ts)
    after = counters_at_or_before(samples, end_ts)
    if before is None or after is None or before[0] != after[0]:
        return None
    if (seconds_between(before[2], start_ts) > MAX_SAMPLE_AGE_SECS
            or seconds_between(after[2], end_ts) > MAX_SAMPLE_AGE_SECS):
        return None
    backend, before_counters = before[0], before[1]
    after_counters = after[1]
    return backend, {k: after_counters[k] - before_counters[k] for k in before_counters}


def load_system_samples(run_dir):
    path = os.path.join(run_dir, "system_samples.csv")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [row for row in csv.DictReader(f) if row.get("timestamp")]


def load_clk_tck(run_dir):
    path = os.path.join(run_dir, "clk_tck.txt")
    if not os.path.exists(path):
        return 100
    with open(path) as f:
        try:
            return int(f.read().strip())
        except ValueError:
            return 100


def load_key_values(path):
    """Read a key=value file into a dict, empty if the file is absent."""
    result = {}
    if not os.path.exists(path):
        return result
    with open(path) as f:
        for line in f:
            if "=" in line and not line.startswith("check="):
                key, _, value = line.rstrip("\n").partition("=")
                result[key] = value
    return result


def load_checks(path):
    checks = []
    if not os.path.exists(path):
        return checks
    with open(path) as f:
        for line in f:
            m = re.match(r"check=(\S+) result=(\S+) detail=(.*)", line.strip())
            if m:
                checks.append(m.groups())
    return checks


def window_samples(samples, start_ts, end_ts, field):
    return [s for s in samples if start_ts <= s["timestamp"] < end_ts and s.get(field) not in (None, "")]


def cumulative_delta(samples, start_ts, end_ts, field):
    """(increase, seconds between the first and last sample) for a counter."""
    rows = window_samples(samples, start_ts, end_ts, field)
    if len(rows) < 2:
        return None
    first, last = rows[0], rows[-1]
    span = seconds_between(first["timestamp"], last["timestamp"])
    if span <= 0:
        return None
    try:
        increase = float(last[field]) - float(first[field])
    except ValueError:
        return None
    if increase < 0:
        return None
    return increase, span


def rate(samples, start_ts, end_ts, field):
    result = cumulative_delta(samples, start_ts, end_ts, field)
    return None if result is None else result[0] / result[1]


def process_metrics(samples, start_ts, end_ts, clk_tck, prefix):
    """CPU, memory, and context switches for one service in one phase."""
    pid_field = f"{prefix}_pid"
    window = window_samples(samples, start_ts, end_ts, pid_field)
    if len(window) < 2:
        return None
    pids = {s[pid_field] for s in window}
    if len(pids) > 1:
        return {"restarted": True, "pids": sorted(pids)}
    result = {"restarted": False}
    ticks = cumulative_delta(samples, start_ts, end_ts, f"{prefix}_cpu_ticks")
    if ticks:
        result["cpu_pct"] = 100.0 * ticks[0] / (clk_tck * ticks[1])
    rss = [int(s[f"{prefix}_rss_kb"]) for s in window if s.get(f"{prefix}_rss_kb")]
    if rss:
        result["rss_avg_mb"] = (sum(rss) / len(rss)) / 1024
        result["rss_max_mb"] = max(rss) / 1024
    vol = rate(samples, start_ts, end_ts, f"{prefix}_vol_ctxt")
    nonvol = rate(samples, start_ts, end_ts, f"{prefix}_nonvol_ctxt")
    if vol is not None and nonvol is not None:
        result["ctxt_per_sec"] = vol + nonvol
        result["nonvol_ctxt_per_sec"] = nonvol
    return result


SYS_CPU_FIELDS = ("sys_user", "sys_nice", "sys_system", "sys_idle",
                  "sys_iowait", "sys_irq", "sys_softirq", "sys_steal")


def system_cpu_metrics(samples, start_ts, end_ts):
    deltas = {}
    for field in SYS_CPU_FIELDS:
        result = cumulative_delta(samples, start_ts, end_ts, field)
        if result is None:
            return None
        deltas[field] = result[0]
    total = sum(deltas.values())
    if total <= 0:
        return None
    idle = deltas["sys_idle"] + deltas["sys_iowait"]
    return {
        "busy_pct": 100.0 * (total - idle) / total,
        "kernel_pct": 100.0 * (deltas["sys_system"] + deltas["sys_irq"] + deltas["sys_softirq"]) / total,
        "softirq_pct": 100.0 * deltas["sys_softirq"] / total,
    }


def egress_stall_share(samples, start_ts, end_ts, min_rx=50):
    """Share of sample intervals with incoming traffic and no egress traffic.

    Forwarded traffic leaves through the egress interface, so incoming traffic
    with none leaving means the gateway was not forwarding (a down egress
    interface, a lost route). Attack traffic that the firewall drops also
    shows this, so a small share is normal in an attack phase.
    """
    rows = [s for s in samples if start_ts <= s["timestamp"] < end_ts
            and s.get("ingress_rx_packets") not in (None, "") and s.get("egress_tx_packets") not in (None, "")]
    total = stalled = 0
    for previous, current in zip(rows, rows[1:]):
        try:
            rx = int(current["ingress_rx_packets"]) - int(previous["ingress_rx_packets"])
            tx = int(current["egress_tx_packets"]) - int(previous["egress_tx_packets"])
        except ValueError:
            continue
        if rx < 0 or tx < 0:
            continue
        if rx > min_rx:
            total += 1
            stalled += int(tx == 0)
    return None if total == 0 else 100.0 * stalled / total


def network_metrics(samples, start_ts, end_ts):
    metrics = {}
    rx = cumulative_delta(samples, start_ts, end_ts, "ingress_rx_packets")
    if rx:
        metrics["ingress_pps"] = rx[0] / rx[1]
    rx_bytes = cumulative_delta(samples, start_ts, end_ts, "ingress_rx_bytes")
    if rx_bytes:
        metrics["ingress_mbps"] = rx_bytes[0] * 8 / rx_bytes[1] / 1e6
    dropped = cumulative_delta(samples, start_ts, end_ts, "ingress_rx_dropped")
    if dropped:
        metrics["nic_rx_dropped"] = dropped[0]
    errors = cumulative_delta(samples, start_ts, end_ts, "ingress_rx_errors")
    if errors:
        metrics["nic_rx_errors"] = errors[0]
    stall = egress_stall_share(samples, start_ts, end_ts)
    if stall is not None:
        metrics["egress_stall_pct"] = stall
    tx = cumulative_delta(samples, start_ts, end_ts, "egress_tx_packets")
    if tx:
        metrics["egress_pps"] = tx[0] / tx[1]
    tx_bytes = cumulative_delta(samples, start_ts, end_ts, "egress_tx_bytes")
    if tx_bytes:
        metrics["egress_mbps"] = tx_bytes[0] * 8 / tx_bytes[1] / 1e6
    return metrics


def ts_epoch(ts):
    """Seconds since the epoch for a gateway UTC timestamp."""
    dt = to_dt(ts)
    return calendar.timegm(dt.timetuple()) + dt.microsecond / 1e6


def load_probe_samples(run_dir):
    """[(epoch on the probe host's clock, round trip in ms or None if lost)]."""
    path = os.path.join(run_dir, "probe_rtt.csv")
    samples = []
    if not os.path.exists(path):
        return samples
    with open(path) as f:
        for row in csv.reader(f):
            if len(row) < 2 or not row[0].strip().isdigit():
                continue
            try:
                rtt = float(row[1]) if row[1].strip() else None
            except ValueError:
                continue
            samples.append((int(row[0]), rtt))
    return samples


def percentile(sorted_values, pct):
    """Nearest rank percentile of an ascending list."""
    rank = max(1, -(-len(sorted_values) * pct // 100))
    return sorted_values[int(rank) - 1]


def probe_metrics(samples, start_ts, end_ts, offset_secs=0.0):
    """Round trip time and loss of the probe packets sent in one phase.

    offset_secs is the probe host's clock minus the gateway's, so probe
    timestamps line up with the gateway's phase boundaries.
    """
    low = ts_epoch(start_ts) + offset_secs
    high = ts_epoch(end_ts) + offset_secs
    rtts = [rtt for epoch, rtt in samples if low <= epoch < high]
    if len(rtts) < 3:
        return None
    received = [r for r in rtts if r is not None]
    result = {"sent": len(rtts), "lost": len(rtts) - len(received),
              "loss_pct": 100.0 * (len(rtts) - len(received)) / len(rtts)}
    if received:
        ordered = sorted(received)
        result.update({
            "min_ms": ordered[0], "mean_ms": sum(received) / len(received),
            "p50_ms": percentile(ordered, 50), "p95_ms": percentile(ordered, 95),
            "p99_ms": percentile(ordered, 99), "max_ms": ordered[-1],
            "jitter_ms": (sum(abs(b - a) for a, b in zip(received, received[1:])) / (len(received) - 1)
                          if len(received) > 1 else 0.0),
        })
    return result


def load_limits(run_dir):
    """Ladder rows from limits.tsv: (phase, profile, target pps or None for max, payload bytes, generators)."""
    path = os.path.join(run_dir, "limits.tsv")
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            try:
                rows.append((parts[0], parts[1], None if parts[2] == "max" else int(parts[2]),
                             int(parts[3]), int(parts[4])))
            except ValueError:
                continue
    return rows


def limit_step(m, target_pps, capture_pct, probe_pct):
    """One limit step's figures and whether it ran without loss."""
    net = m.get("network") or {}
    probe = m.get("probe") or {}
    step = {
        "target_pps": target_pps,
        "ingress_pps": net.get("ingress_pps"), "ingress_mbps": net.get("ingress_mbps"),
        "egress_pps": net.get("egress_pps"), "egress_mbps": net.get("egress_mbps"),
        "captured_pps": m.get("captured_pps"),
        "nic_rx_dropped": net.get("nic_rx_dropped"), "nic_rx_errors": net.get("nic_rx_errors"),
        "firewall_drop_pps": m.get("firewall_drop_pps"),
        "stage1_cpu_pct": (m.get("stage1") or {}).get("cpu_pct"),
        "system_busy_pct": (m.get("system_cpu") or {}).get("busy_pct"),
        "system_softirq_pct": (m.get("system_cpu") or {}).get("softirq_pct"),
        "probe_loss_pct": probe.get("loss_pct"), "probe_mean_ms": probe.get("mean_ms"),
        "probe_p95_ms": probe.get("p95_ms"),
    }
    ingress, captured = step["ingress_pps"], step["captured_pps"]
    step["capture_share_pct"] = 100.0 * captured / ingress if ingress and captured is not None else None
    if target_pps and ingress is not None:
        step["achieved_pct"] = 100.0 * ingress / target_pps
    reasons = []
    if ingress is None:
        step["loss_free"] = None
        step["loss_reasons"] = ["no interface counters"]
        return step
    if step["nic_rx_dropped"]:
        reasons.append(f"{step['nic_rx_dropped']:.0f} NIC rx drops")
    if step["nic_rx_errors"]:
        reasons.append(f"{step['nic_rx_errors']:.0f} NIC rx errors")
    if step["capture_share_pct"] is not None and step["capture_share_pct"] < capture_pct:
        reasons.append(f"capture saw {step['capture_share_pct']:.1f}% of the interface packets")
    if step["probe_loss_pct"] is not None and step["probe_loss_pct"] > probe_pct:
        reasons.append(f"{step['probe_loss_pct']:.1f}% of probes lost")
    step["loss_free"] = not reasons
    step["loss_reasons"] = reasons
    return step


def summarize_limits(phases, ladder, capture_pct=ZERO_LOSS_CAPTURE_PCT, probe_pct=ZERO_LOSS_PROBE_PCT):
    """Per profile: the steps in ladder order, the peak rates, and the highest loss-free step.

    The loss-free figure is the last step of the unbroken run of loss-free
    steps from the bottom of the ladder, so a lucky clean step above the first
    failure does not count.
    """
    profiles = {}
    for phase, profile, target, payload, generators in ladder:
        m = phases.get(phase)
        if m is None:
            continue
        entry = profiles.setdefault(profile, {"payload_bytes": payload, "generators": generators, "steps": []})
        step = limit_step(m, target, capture_pct, probe_pct)
        step["phase"] = phase
        entry["steps"].append(step)
    for entry in profiles.values():
        steps = entry["steps"]
        measured = [s for s in steps if s["ingress_pps"] is not None]
        entry["peak_pps"] = max((s["ingress_pps"] for s in measured), default=None)
        entry["peak_mbps"] = max((s["ingress_mbps"] for s in measured if s["ingress_mbps"] is not None), default=None)
        entry["peak_capture_pps"] = max((s["captured_pps"] for s in steps if s["captured_pps"] is not None), default=None)
        entry["peak_egress_mbps"] = max((s["egress_mbps"] for s in steps if s["egress_mbps"] is not None), default=None)
        best = None
        for s in steps:
            if not s["loss_free"]:
                entry["first_loss_phase"] = s["phase"]
                entry["first_loss_reasons"] = s["loss_reasons"]
                break
            best = s
        entry["loss_free_pps"] = best["ingress_pps"] if best else None
        entry["loss_free_mbps"] = best["ingress_mbps"] if best else None
        entry["loss_free_phase"] = best["phase"] if best else None
    return profiles


ANOMALY_RE = re.compile(
    r"ANOMALY window \d+ \[victim=\S+?\] \| flags=0x([0-9a-fA-F]+) \| r=([\d.]+) \(boundary=[\d.]+\) \| "
    r"h=([\d.]+) \(boundary=[\d.]+\) \| proto_ratio=([\d.]+) \| dom_ratio=([\d.]+)"
)


def anomaly_signal_stats(events):
    """Which signal flagged each anomaly window, and what it looked like.

    Stage 1 forwards only flagged windows and heartbeats, so these figures
    describe the flagged windows, and are not a sample of all traffic.
    """
    rate_only = entropy_only = both = 0
    entropy_values, dominance_values = [], []
    for _, line in events:
        m = ANOMALY_RE.search(line)
        if not m:
            continue
        flags = int(m.group(1), 16)
        has_rate, has_entropy = bool(flags & 0x01), bool(flags & 0x02)
        if has_rate and has_entropy:
            both += 1
        elif has_entropy:
            entropy_only += 1
        elif has_rate:
            rate_only += 1
        entropy_values.append(float(m.group(3)))
        dominance_values.append(float(m.group(5)))
    total = rate_only + entropy_only + both
    if total == 0:
        return {}
    return {
        "flagged_rate_only": rate_only,
        "flagged_entropy_only": entropy_only,
        "flagged_both": both,
        "entropy_flag_pct": 100.0 * (entropy_only + both) / total,
        "mean_entropy": sum(entropy_values) / len(entropy_values),
        "mean_dominance": sum(dominance_values) / len(dominance_values),
    }


LATENCY_LINE_RE = {
    kind: re.compile(
        rf"{kind}_n=(\d+)(?: {kind}_mean_ms=([\d.]+) {kind}_p95_ms=([\d.]+) {kind}_max_ms=([\d.]+))?"
    )
    for kind in LATENCY_KINDS
}


def latency_metrics(stage2_events):
    """Merge the Stage 2 interval summaries that fall inside one phase."""
    merged = {}
    for kind in LATENCY_KINDS:
        count, weighted, worst_p95, worst_max = 0, 0.0, 0.0, 0.0
        for _, line in stage2_events:
            if "Latency: summary" not in line:
                continue
            m = LATENCY_LINE_RE[kind].search(line)
            if not m or not m.group(2):
                continue
            n = int(m.group(1))
            count += n
            weighted += n * float(m.group(2))
            worst_p95 = max(worst_p95, float(m.group(3)))
            worst_max = max(worst_max, float(m.group(4)))
        if count:
            merged[kind] = {
                "n": count,
                "mean_ms": weighted / count,
                "p95_ms": worst_p95,
                "max_ms": worst_max,
            }
    return merged


def first_time_after(events, start_ts, end_ts, predicate):
    for ts, line in events:
        if start_ts <= ts < end_ts and predicate(line):
            return seconds_between(start_ts, ts)
    return None


def bin_consistency(class2_times, start_ts, end_ts, expect_attack):
    """Share of BIN_SECS bins whose verdicts match what the phase should show.

    An attack phase is measured from the first bin that holds a verdict on,
    so the time taken to notice the attack is not counted as inconsistency
    (that is what the time to first detection reports). A benign phase counts
    the bins with no DDoS verdict.
    """
    span = seconds_between(start_ts, end_ts)
    bins = int(span // BIN_SECS)
    if bins < 1:
        return None
    hit = set()
    for ts in class2_times:
        index = int(seconds_between(start_ts, ts) // BIN_SECS)
        if 0 <= index < bins:
            hit.add(index)
    if not expect_attack:
        return 100.0 * (bins - len(hit)) / bins
    if not hit:
        return 0.0
    first = min(hit)
    remaining = bins - first
    return 100.0 * len([i for i in hit if i >= first]) / remaining


def firewall_drops(firewall_rows, phase_names_in_order):
    """Packets matched by DROP rules per phase, from boundary snapshots.

    A snapshot named for a phase is taken as that phase begins, so a phase's
    count is the next snapshot minus its own.
    """
    totals = {}
    for name, ts, chain, set_name, target, packets, _ in firewall_rows:
        if target != "DROP":
            continue
        totals.setdefault(name, {}).setdefault(set_name, 0)
        totals[name][set_name] += int(packets)
    result = {}
    for i in range(len(phase_names_in_order) - 1):
        here, following = phase_names_in_order[i], phase_names_in_order[i + 1]
        if here not in totals and following not in totals:
            continue
        result[here] = {
            set_name: max(0, totals.get(following, {}).get(set_name, 0) - totals.get(here, {}).get(set_name, 0))
            for set_name in set(totals.get(here, {})) | set(totals.get(following, {}))
        }
    return result


def load_firewall_rows(run_dir):
    path = os.path.join(run_dir, "firewall_counters.tsv")
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 7:
                rows.append(tuple(parts))
    return rows


def analyze_run(run_dir, capture_pct=ZERO_LOSS_CAPTURE_PCT, probe_pct=ZERO_LOSS_PROBE_PCT):
    windows = load_phases(run_dir)
    if not windows:
        raise SystemExit(f"[-] No phase boundaries in {run_dir}; did benchmark_live.sh run to completion?")
    year_hint = windows[0][1].split("-")[0]
    stage1_events = load_events(os.path.join(run_dir, "stage1.log"), year_hint)
    stage2_events = load_events(os.path.join(run_dir, "stage2.log"), year_hint)
    info_early = load_key_values(os.path.join(run_dir, "run_info.txt"))
    ingress_iface = info_early.get("ingress_iface") or first_capture_interface(stage1_events)
    egress_iface = info_early.get("egress_iface") or None
    traffic_samples = parse_traffic_samples(stage1_events, ingress_iface)
    egress_capture_samples = (parse_traffic_samples(stage1_events, egress_iface)
                              if egress_iface and egress_iface != ingress_iface else [])
    system_samples = load_system_samples(run_dir)
    clk_tck = load_clk_tck(run_dir)
    firewall = firewall_drops(load_firewall_rows(run_dir), [w[0] for w in windows] + ["session_end"])
    info = load_key_values(os.path.join(run_dir, "run_info.txt"))
    switch = load_key_values(os.path.join(run_dir, "mode_switch.txt"))
    variants = load_variants(run_dir)
    probe_samples = load_probe_samples(run_dir)
    try:
        probe_offset = float(info.get("probe_clock_offset_secs") or 0)
    except ValueError:
        probe_offset = 0.0

    phases = {}
    for name, start_ts, end_ts in windows:
        known, is_attack, is_fresh, attack_type = phase_info(name)
        if not known:
            continue
        s1 = events_in(stage1_events, start_ts, end_ts)
        s2 = events_in(stage2_events, start_ts, end_ts)
        duration = seconds_between(start_ts, end_ts)
        m = {"start": start_ts, "end": end_ts, "duration_secs": duration,
             "is_attack": is_attack, "is_fresh": is_fresh, "attack_type": attack_type,
             "variants": variants.get(name, {})}
        m.update(anomaly_signal_stats(s1))

        anomaly_by_victim = {}
        for _, line in s1:
            if "ANOMALY" in line:
                v = re.search(r"victim=(\S+?)\]", line)
                if v:
                    anomaly_by_victim[v.group(1)] = anomaly_by_victim.get(v.group(1), 0) + 1
        class2_times = [ts for ts, line in s2 if any(p in line for p in CLASS2_PATTERNS)]
        m["anomaly_by_victim"] = anomaly_by_victim
        m["anomaly_windows"] = sum(anomaly_by_victim.values())
        m["class2_verdicts"] = len(class2_times)
        m["enforcement_actions"] = sum(1 for _, line in s2 if "MITIGATION TRIGGERED" in line)
        m["blocks"] = sum(1 for _, line in s2 if "MITIGATION TRIGGERED: Blocked" in line)
        m["ratelimits"] = sum(1 for _, line in s2 if "MITIGATION TRIGGERED: Rate-limited" in line)
        if m["anomaly_windows"] > 0:
            m["class2_rate_pct"] = 100.0 * m["class2_verdicts"] / m["anomaly_windows"]

        m["consistency_pct"] = bin_consistency(class2_times, start_ts, end_ts, is_attack)
        if is_fresh:
            m["first_anomaly_secs"] = first_time_after(stage1_events, start_ts, end_ts, lambda l: "ANOMALY" in l)
            m["first_class2_secs"] = first_time_after(
                stage2_events, start_ts, end_ts, lambda l: any(p in l for p in CLASS2_PATTERNS))
            m["first_block_secs"] = first_time_after(
                stage2_events, start_ts, end_ts, lambda l: "MITIGATION TRIGGERED: Blocked" in l)
            m["first_ratelimit_secs"] = first_time_after(
                stage2_events, start_ts, end_ts, lambda l: "MITIGATION TRIGGERED: Rate-limited" in l)

        delta = traffic_delta(traffic_samples, start_ts, end_ts)
        if delta:
            backend, counts = delta
            m["capture_backend"] = backend
            if backend == "pcap":
                m["captured_packets"] = counts["raw_captured"]
                m["forwarded_packets"] = counts["forwarded"]
                m["capture_dropped"] = counts["parse_failed"] + counts["non_ip"] + counts["truncated"]
                m["capture_unparseable"] = counts["parse_failed"]
                m["capture_non_ip"] = counts["non_ip"]
                m["capture_truncated"] = counts["truncated"]
                m["capture_timeouts"] = counts["timeouts"]
            else:
                m["captured_packets"] = counts["ingress"]
                m["egress_packets"] = counts["egress"]
                m["map_drain_errors"] = counts["errors"]
                m["drains"] = counts["drains"]
            if duration > 0:
                m["captured_pps"] = m["captured_packets"] / duration
            if backend == "pcap" and egress_capture_samples:
                egress_delta = traffic_delta(egress_capture_samples, start_ts, end_ts)
                if egress_delta and egress_delta[0] == "pcap":
                    m["egress_captured_packets"] = egress_delta[1]["raw_captured"]

        if system_samples:
            m["stage1"] = process_metrics(system_samples, start_ts, end_ts, clk_tck, "stage1")
            m["stage2"] = process_metrics(system_samples, start_ts, end_ts, clk_tck, "stage2")
            m["system_cpu"] = system_cpu_metrics(system_samples, start_ts, end_ts)
            m["system_ctxt_per_sec"] = rate(system_samples, start_ts, end_ts, "sys_ctxt")
            m["network"] = network_metrics(system_samples, start_ts, end_ts)
        if name in firewall:
            m["firewall_dropped"] = sum(firewall[name].values())
            m["firewall_dropped_by_set"] = firewall[name]
            if duration > 0:
                m["firewall_drop_pps"] = m["firewall_dropped"] / duration
        m["latency"] = latency_metrics(s2)
        if probe_samples:
            m["probe"] = probe_metrics(probe_samples, start_ts, end_ts, probe_offset)
        phases[name] = m

    return {
        "limits": summarize_limits(phases, load_limits(run_dir), capture_pct, probe_pct),
        "run_dir": run_dir,
        "mode": info.get("mode") or ("kernel" if any(p.get("capture_backend") == "kernel" for p in phases.values()) else "pcap"),
        "run": info.get("run", "1"),
        "info": info,
        "switch": switch,
        "verify": load_checks(os.path.join(run_dir, "mode_verify.txt")),
        "calibration": load_calibration(run_dir),
        "phases": phases,
        "variants": variants,
        "system_samples": system_samples,
    }


CALIBRATION_ROW_RE = re.compile(
    r"^(\S+)\s+(\d+)\s+([\d.]+)%\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$"
)


def parse_calibration_log(text):
    """Per target rows, the notes calibrate.py printed, and the floors it recommended."""
    targets, notes, flags = [], [], ""
    lines = [l.strip() for l in text.replace("\r", "\n").split("\n")]
    for i, line in enumerate(lines):
        m = CALIBRATION_ROW_RE.match(line)
        if m:
            targets.append({
                "target": m.group(1), "windows": int(m.group(2)), "flagged_pct": float(m.group(3)),
                "mean_pps": float(m.group(4)), "peak_pps": float(m.group(5)),
                "rate_floor": float(m.group(6)), "entropy_floor": float(m.group(7)),
            })
        elif line.startswith(("warning:", "note:")):
            notes.append(line)
        elif line.startswith("Recommended, covering every target:") and i + 1 < len(lines):
            flags = lines[i + 1]
    return targets, notes, flags


def floor_from_flags(flags, name):
    m = re.search(rf"--{name} ([\d.]+)", flags or "")
    return float(m.group(1)) if m else None


def load_calibration(run_dir):
    info = load_key_values(os.path.join(run_dir, "calibration.txt"))
    if not info:
        return None
    text = ""
    path = os.path.join(run_dir, "calibration.log")
    if os.path.exists(path):
        with open(path, errors="replace") as f:
            text = f.read()
    targets, notes, flags = parse_calibration_log(text)
    flags = flags or info.get("recommended_flags", "")
    return {
        "info": info,
        "apply": load_key_values(os.path.join(run_dir, "calibration_apply.txt")),
        "targets": targets,
        "notes": notes,
        "rate_floor": floor_from_flags(flags, "rate-sigma-floor"),
        "entropy_floor": floor_from_flags(flags, "entropy-sigma-floor"),
        "mean_pps": (sum(t["mean_pps"] for t in targets) / len(targets)) if targets else None,
    }


def print_calibration(result):
    cal = result.get("calibration")
    if not cal:
        return
    info, applied = cal["info"], cal["apply"]
    print(f"--- Calibration ({info.get('mode', '?')}) during the warm-up stage, {result['mode']} backend ---")
    print(f"  Outcome: {info.get('status', '?')}, took {info.get('duration_secs', '?')}s, asked for "
          f"{info.get('windows_requested', '?')} clean windows per target (exit {info.get('exit_code', '?')})")
    for t in cal["targets"]:
        print(f"    {t['target']}: {t['windows']} clean windows, {t['flagged_pct']:.1f}% flagged, "
              f"mean {t['mean_pps']:.1f} pps, peak {t['peak_pps']:.1f} pps, "
              f"floors rate {t['rate_floor']:.1f} entropy {t['entropy_floor']:.4f}")
    if info.get("recommended_flags"):
        print(f"  Recommended for all targets: {info['recommended_flags']}")
    if info.get("status") == "applied":
        print(f"  Floors in force before: {applied.get('tuning_before', 'n/a')}")
        print(f"  Floors in force after:  {applied.get('tuning_after', 'n/a')}")
        print(f"  Restart to apply them: first capture status line after "
              f"{applied.get('downtime_to_first_status_secs', 'n/a')}s"
              + (" (timed out)" if applied.get("timed_out") == "1" else "")
              + f"; baseline back after ~{info.get('rewarm_secs', '?')}s"
              + ("" if info.get("rewarm_ok") == "1" else " (not confirmed)"))
    elif info.get("status") == "failed":
        print("  Calibration produced no usable floors, so this run used the floors already in force.")
    for note in cal["notes"]:
        print(f"  {note}")
    print()


def fmt(value, spec=".1f", missing="n/a"):
    return missing if value is None else format(value, spec)


def fmt_secs(value):
    return "n/a" if value is None else f"{value:.1f}s"


def print_run_report(result):
    info = result["info"]
    print(f"=== Run report: {result['mode']} backend, run {result['run']} ===")
    first_phase = next(iter(result["phases"].values()), None)
    if first_phase:
        print(f"Session start: {first_phase['start']} (UTC)")
    if info:
        print(f"Warm-up: {'complete' if info.get('warmed') == '1' else 'not confirmed'} "
              f"after ~{info.get('warmup_secs', '?')}s")
        sources = ", ".join(f"{label} {info[key]}" for label, key in
                            (("attack", "attack_sources"), ("normal", "normal_sources"),
                             ("flash crowd", "flashcrowd_sources")) if info.get(key))
        if sources:
            print(f"Source addresses: {sources}")
        for label, key in (("Normal", "normal_variants"), ("Flash Crowd", "flashcrowd_variants"),
                           ("Attack", "attack_variants")):
            if info.get(key):
                print(f"{label} variants in rotation: {info[key]}")
    print()

    for name, m in result["phases"].items():
        print(f"--- Phase: {name} ({m['start']} to {m['end']}, {m['duration_secs']:.0f}s) ---")
        if m["variants"]:
            print("  Traffic: " + ", ".join(
                f"{cls} '{v}'" + (f" ({d})" if d else "") for cls, (v, d) in m["variants"].items()))
        if "entropy_flag_pct" in m:
            print(f"  Signals on anomaly windows: {m['flagged_rate_only']} rate only, "
                  f"{m['flagged_entropy_only']} entropy only, {m['flagged_both']} both "
                  f"({m['entropy_flag_pct']:.1f}% involve entropy); mean entropy {m['mean_entropy']:.3f}, "
                  f"mean dominant source share {m['mean_dominance']:.3f}")
        print(f"  Anomaly-flagged windows (Stage 1): {m['anomaly_windows']}"
              + (f" across {len(m['anomaly_by_victim'])} targets" if m["anomaly_by_victim"] else ""))
        for victim, count in sorted(m["anomaly_by_victim"].items()):
            print(f"    {victim}: {count}")
        print(f"  Class-2 (DDoS) verdicts (Stage 2): {m['class2_verdicts']}")
        print(f"  Enforcement actions triggered: {m['enforcement_actions']} "
              f"({m['blocks']} blocks, {m['ratelimits']} rate limits)")
        if "class2_rate_pct" in m:
            label = "escalation rate" if m["is_attack"] else "false-positive rate (of anomaly-flagged windows)"
            print(f"  {label}: {m['class2_rate_pct']:.1f}%")
        if m["consistency_pct"] is not None:
            what = "attack verdicts in the bins after the first detection" if m["is_attack"] \
                else "bins with no DDoS verdict"
            print(f"  Detection consistency ({BIN_SECS}s bins, {what}): {m['consistency_pct']:.1f}%")
        if m["is_fresh"]:
            print("  Time from phase start to: "
                  f"first anomaly flag {fmt_secs(m.get('first_anomaly_secs'))}, "
                  f"first DDoS verdict {fmt_secs(m.get('first_class2_secs'))}, "
                  f"first block {fmt_secs(m.get('first_block_secs'))}, "
                  f"first rate limit {fmt_secs(m.get('first_ratelimit_secs'))}")

        if "captured_packets" not in m:
            print("  Traffic: no capture status samples in this phase window")
        elif m["capture_backend"] == "pcap":
            egress_part = (f" ({m['egress_captured_packets']} more on the egress interface)"
                           if "egress_captured_packets" in m else "")
            print(f"  Traffic (pcap): {m['captured_packets']} captured ({fmt(m.get('captured_pps'), ',.0f')} pps){egress_part}, "
                  f"{m['forwarded_packets']} forwarded, {m['capture_dropped']} dropped "
                  f"({m['capture_unparseable']} unparseable, {m['capture_non_ip']} non-IP, "
                  f"{m['capture_truncated']} truncated), {m['capture_timeouts']} read timeouts")
        else:
            print(f"  Traffic (kernel): {m['captured_packets']} ingress packets ({fmt(m.get('captured_pps'), ',.0f')} pps), "
                  f"{m['egress_packets']} egress packets, {m['map_drain_errors']} map drain errors "
                  f"across {m['drains']} drains")
        net = m.get("network") or {}
        if net:
            print(f"  Interface: ingress {fmt(net.get('ingress_pps'), ',.0f')} pps / {fmt(net.get('ingress_mbps'))} Mbit/s, "
                  f"egress {fmt(net.get('egress_pps'), ',.0f')} pps / {fmt(net.get('egress_mbps'))} Mbit/s, "
                  f"NIC rx drops {fmt(net.get('nic_rx_dropped'), '.0f')}, rx errors {fmt(net.get('nic_rx_errors'), '.0f')}")
        # Only phases with legitimate traffic can show a forwarding failure. In an
        # attack-only phase the firewall drops the attack, so no egress is expected.
        has_legitimate = any(cls in m["variants"] for cls in ("normal", "flashcrowd"))
        if has_legitimate and net.get("egress_stall_pct", 0) > 20:
            print(f"  WARNING: {net['egress_stall_pct']:.0f}% of the sample intervals had incoming traffic and no "
                  "egress traffic. The gateway was probably not forwarding, so this phase may not reflect the system.")
        if "firewall_dropped" in m:
            print(f"  Firewall drops (DROP rules on the ddos ipsets): {m['firewall_dropped']} packets "
                  f"({fmt(m.get('firewall_drop_pps'), ',.1f')} pps)")

        for label, key in (("Stage 1", "stage1"), ("Stage 2", "stage2")):
            summary = m.get(key)
            if "stage1" not in m:
                continue
            if summary is None:
                print(f"  {label} system health: no samples in this phase window")
            elif summary["restarted"]:
                print(f"  {label} system health: process restarted during this phase "
                      f"(pids {', '.join(summary['pids'])}), figures skipped")
            else:
                print(f"  {label} system health: {fmt(summary.get('cpu_pct'))}% CPU, "
                      f"RSS avg {fmt(summary.get('rss_avg_mb'))} MB / peak {fmt(summary.get('rss_max_mb'))} MB, "
                      f"{fmt(summary.get('ctxt_per_sec'), ',.0f')} context switches/s "
                      f"({fmt(summary.get('nonvol_ctxt_per_sec'), ',.0f')} involuntary)")
        cpu = m.get("system_cpu")
        if cpu:
            print(f"  System CPU: {cpu['busy_pct']:.1f}% busy, {cpu['kernel_pct']:.1f}% in the kernel, "
                  f"{cpu['softirq_pct']:.1f}% in softirq, {fmt(m.get('system_ctxt_per_sec'), ',.0f')} context switches/s")
        latency = m.get("latency") or {}
        if latency:
            parts = []
            for kind in LATENCY_KINDS:
                if kind in latency:
                    v = latency[kind]
                    parts.append(f"{kind} {v['mean_ms']:.2f} ms mean / {v['p95_ms']:.2f} p95 / {v['max_ms']:.2f} max (n={v['n']})")
            print("  Stage 2 latency: " + "; ".join(parts))
        else:
            print("  Stage 2 latency: no Latency summary lines (Stage 2 predates the latency log, or no windows arrived)")
        probe = m.get("probe")
        if probe and "mean_ms" in probe:
            print(f"  Packet latency through the gateway: {probe['mean_ms']:.2f} ms mean / {probe['p50_ms']:.2f} p50 / "
                  f"{probe['p95_ms']:.2f} p95 / {probe['p99_ms']:.2f} p99 / {probe['max_ms']:.2f} max, "
                  f"jitter {probe['jitter_ms']:.2f} ms, {probe['lost']} of {probe['sent']} probes lost "
                  f"({probe['loss_pct']:.1f}%)")
        elif probe:
            print(f"  Packet latency through the gateway: all {probe['sent']} probes lost")
        print()

    print_limits(result)
    print_switch(result)


def print_limits(result):
    limits = result.get("limits") or {}
    for profile, entry in limits.items():
        print(f"--- Gateway limits, {profile} packets ({entry['payload_bytes']} byte payload, "
              f"{entry['generators']} generator(s), {result['mode']} backend) ---")
        print(f"  {'target pps':>12}{'interface pps':>15}{'Mbit/s':>10}{'capture pps':>13}{'capture %':>11}"
              f"{'NIC drops':>11}{'sys CPU %':>11}{'RTT p95 ms':>12}{'probe loss %':>14}  loss free")
        for s in entry["steps"]:
            target = "max" if s["target_pps"] is None else f"{s['target_pps']:,}"
            verdict = {True: "yes", False: "no", None: "n/a"}[s["loss_free"]]
            print(f"  {target:>12}{fmt(s['ingress_pps'], ',.0f'):>15}{fmt(s['ingress_mbps']):>10}"
                  f"{fmt(s['captured_pps'], ',.0f'):>13}{fmt(s['capture_share_pct']):>11}"
                  f"{fmt(s['nic_rx_dropped'], ',.0f'):>11}{fmt(s['system_busy_pct']):>11}"
                  f"{fmt(s['probe_p95_ms'], '.2f'):>12}{fmt(s['probe_loss_pct']):>14}  {verdict}")
        print(f"  Peak: {fmt(entry['peak_pps'], ',.0f')} packets/s at the interface, "
              f"{fmt(entry['peak_mbps'])} Mbit/s in, {fmt(entry['peak_egress_mbps'])} Mbit/s out, "
              f"{fmt(entry['peak_capture_pps'], ',.0f')} packets/s seen by the capture backend")
        print(f"  Highest loss-free step: {fmt(entry['loss_free_pps'], ',.0f')} packets/s, "
              f"{fmt(entry['loss_free_mbps'])} Mbit/s"
              + (f" ({entry['loss_free_phase']})" if entry.get("loss_free_phase") else ""))
        if entry.get("first_loss_phase"):
            print(f"  First step with loss: {entry['first_loss_phase']} ({'; '.join(entry['first_loss_reasons'])})")
        print()


def print_limits_comparison(by_mode, modes):
    profiles = []
    for runs in by_mode.values():
        for r in runs:
            for p in (r.get("limits") or {}):
                if p not in profiles:
                    profiles.append(p)
    if not profiles:
        return
    print("--- Gateway limits by backend ---")
    for profile in profiles:
        print(f"  {profile} packets")
        print(f"    {'':<28}" + "".join(f"{m:>14}" for m in modes))
        for label, key, spec in (("Peak interface packets/s", "peak_pps", ",.0f"),
                                 ("Peak capture packets/s", "peak_capture_pps", ",.0f"),
                                 ("Peak bandwidth in (Mbit/s)", "peak_mbps", ".1f"),
                                 ("Peak bandwidth out (Mbit/s)", "peak_egress_mbps", ".1f"),
                                 ("Loss-free packets/s", "loss_free_pps", ",.0f"),
                                 ("Loss-free bandwidth (Mbit/s)", "loss_free_mbps", ".1f")):
            cells = []
            for m in modes:
                values = [(r.get("limits") or {}).get(profile, {}).get(key) for r in by_mode[m]]
                values = [v for v in values if v is not None]
                cells.append(fmt(sum(values) / len(values) if values else None, spec))
            print(f"    {label:<28}" + "".join(f"{c:>14}" for c in cells))
    print()


def print_switch(result):
    switch = result["switch"]
    if switch:
        print(f"--- Switch to the {result['mode']} backend ---")
        print(f"  Sensor stop took {switch.get('stop_secs', 'n/a')}s")
        print(f"  Downtime until capture attached: {switch.get('downtime_to_attach_secs', 'n/a')}s")
        print(f"  Downtime until the first capture status line: {switch.get('downtime_to_first_status_secs', 'n/a')}s"
              + (" (timed out)" if switch.get("timed_out") == "1" else ""))
        for name, outcome, detail in result["verify"]:
            print(f"  Check {name}: {outcome} ({detail})")
        print()


def system_health_whole_run(result):
    samples = result["system_samples"]
    print(f"--- System health, whole run ({result['mode']}) ---")
    if not samples:
        print("  No system_samples.csv found; the sampler was not reached.")
        return
    for label, prefix in (("Stage 1", "stage1"), ("Stage 2", "stage2")):
        pids = {s[f"{prefix}_pid"] for s in samples if s.get(f"{prefix}_pid")}
        if not pids:
            print(f"  {label}: never sampled (service not running, or unit name mismatch)")
            continue
        if len(pids) > 1:
            print(f"  {label}: restarted during the run (pids {', '.join(sorted(pids))})")
        rss = [int(s[f"{prefix}_rss_kb"]) for s in samples if s.get(f"{prefix}_rss_kb")]
        if rss:
            print(f"  {label}: peak RSS {max(rss) / 1024:.1f} MB, {len(samples)} samples over the run")


def print_firewall_state(run_dir):
    path = os.path.join(run_dir, "firewall.log")
    if not os.path.exists(path):
        return
    with open(path) as f:
        firewall = f.read()
    entries = re.findall(r"Number of entries: (\d+)", firewall)
    print(f"--- Final firewall state ({os.path.basename(run_dir)}) ---")
    if len(entries) >= 2:
        print(f"  Blocked (hard): {entries[0]}")
        print(f"  Rate-limited:   {entries[1]}")
    else:
        print(firewall)


COMPARISON_METRICS = (
    ("Ingress throughput, interface (packets/s)", lambda m: (m.get("network") or {}).get("ingress_pps"), ",.0f"),
    ("Ingress throughput, interface (Mbit/s)", lambda m: (m.get("network") or {}).get("ingress_mbps"), ".1f"),
    ("Packets/s seen by the capture backend", lambda m: m.get("captured_pps"), ",.0f"),
    ("Egress throughput, interface (packets/s)", lambda m: (m.get("network") or {}).get("egress_pps"), ",.0f"),
    ("Egress bandwidth, interface (Mbit/s)", lambda m: (m.get("network") or {}).get("egress_mbps"), ".1f"),
    ("Packet latency through the gateway, mean (ms)", lambda m: (m.get("probe") or {}).get("mean_ms"), ".2f"),
    ("Packet latency through the gateway, p95 (ms)", lambda m: (m.get("probe") or {}).get("p95_ms"), ".2f"),
    ("Packet latency jitter (ms)", lambda m: (m.get("probe") or {}).get("jitter_ms"), ".2f"),
    ("Probe packets lost (%)", lambda m: (m.get("probe") or {}).get("loss_pct"), ".1f"),
    ("Dropped at capture (packets)", lambda m: m.get("capture_dropped"), ",.0f"),
    ("Firewall drops (packets/s)", lambda m: m.get("firewall_drop_pps"), ",.1f"),
    ("Stage 1 CPU (%)", lambda m: (m.get("stage1") or {}).get("cpu_pct"), ".1f"),
    ("Stage 2 CPU (%)", lambda m: (m.get("stage2") or {}).get("cpu_pct"), ".1f"),
    ("System CPU busy (%)", lambda m: (m.get("system_cpu") or {}).get("busy_pct"), ".1f"),
    ("System CPU in softirq (%)", lambda m: (m.get("system_cpu") or {}).get("softirq_pct"), ".1f"),
    ("Stage 1 context switches/s", lambda m: (m.get("stage1") or {}).get("ctxt_per_sec"), ",.0f"),
    ("Stage 2 context switches/s", lambda m: (m.get("stage2") or {}).get("ctxt_per_sec"), ",.0f"),
    ("System context switches/s", lambda m: m.get("system_ctxt_per_sec"), ",.0f"),
    ("Stage 1 memory, average RSS (MB)", lambda m: (m.get("stage1") or {}).get("rss_avg_mb"), ".1f"),
    ("Stage 2 memory, average RSS (MB)", lambda m: (m.get("stage2") or {}).get("rss_avg_mb"), ".1f"),
    ("Window handoff latency, mean (ms)", lambda m: (m.get("latency") or {}).get("handoff", {}).get("mean_ms"), ".2f"),
    ("Inference latency, mean (ms)", lambda m: (m.get("latency") or {}).get("inference", {}).get("mean_ms"), ".2f"),
    ("Enforcement call latency, mean (ms)", lambda m: (m.get("latency") or {}).get("enforcement", {}).get("mean_ms"), ".2f"),
    ("Window close to rule applied, mean (ms)", lambda m: (m.get("latency") or {}).get("window_to_rule", {}).get("mean_ms"), ".1f"),
    ("Time to first anomaly flag (s)", lambda m: m.get("first_anomaly_secs"), ".1f"),
    ("Time to first DDoS verdict (s)", lambda m: m.get("first_class2_secs"), ".1f"),
    ("Time to first block, attack to drop (s)", lambda m: m.get("first_block_secs"), ".1f"),
    ("Detection consistency (%)", lambda m: m.get("consistency_pct"), ".1f"),
    ("Anomaly windows involving entropy (%)", lambda m: m.get("entropy_flag_pct"), ".1f"),
    ("Mean entropy of anomaly windows", lambda m: m.get("mean_entropy"), ".3f"),
    ("Mean dominant source share of anomaly windows", lambda m: m.get("mean_dominance"), ".3f"),
    ("DDoS verdict share of anomaly windows (%)", lambda m: m.get("class2_rate_pct"), ".1f"),
)


def all_phases(results):
    """The standard phases in order, then any sweep phases in the order they ran."""
    seen = []
    for r in results:
        for name in r["phases"]:
            if name not in seen:
                seen.append(name)
    standard = [n for n in PHASE_ORDER if n in seen]
    return standard + [n for n in seen if n not in PHASE_ORDER]


def mean_over_runs(runs, phase, getter):
    values = []
    for run in runs:
        m = run["phases"].get(phase)
        if m is None:
            continue
        try:
            v = getter(m)
        except (AttributeError, TypeError):
            v = None
        if v is not None:
            values.append(v)
    return (sum(values) / len(values)) if values else None


def spread_over_runs(runs, phase, getter):
    values = []
    for run in runs:
        m = run["phases"].get(phase)
        v = getter(m) if m else None
        if v is not None:
            values.append(v)
    if len(values) < 2:
        return None
    return statistics.pstdev(values)


def print_comparison(results):
    by_mode = {}
    for r in results:
        by_mode.setdefault(r["mode"], []).append(r)
    modes = list(by_mode)
    phases = all_phases(results)
    print("=== Backend comparison ===")
    print(f"Backends: {', '.join(f'{m} ({len(by_mode[m])} run(s))' for m in modes)}. "
          "Figures are per phase, averaged over runs of the same backend.")
    if len(modes) < 2:
        print("Only one backend ran, so there is nothing to compare.\n")
    print()

    header_modes = "".join(f"{m:>14}" for m in modes)
    delta_header = f"{'Δ ' + modes[1] + ' vs ' + modes[0]:>26}" if len(modes) == 2 else ""
    for label, getter, spec in COMPARISON_METRICS:
        rows = []
        for phase in phases:
            values = [mean_over_runs(by_mode[m], phase, getter) for m in modes]
            if all(v is None for v in values):
                continue
            rows.append((phase, values))
        if not rows:
            continue
        print(f"{label}")
        print(f"  {'phase':<22}{header_modes}{delta_header}")
        for phase, values in rows:
            cells = "".join(f"{fmt(v, spec):>14}" for v in values)
            delta = ""
            if len(modes) == 2 and values[0] not in (None, 0) and values[1] is not None:
                delta = f"{100.0 * (values[1] - values[0]) / values[0]:>+25.1f}%"
            elif len(modes) == 2:
                delta = f"{'n/a':>26}"
            print(f"  {phase:<22}{cells}{delta}")
        print()

    print_limits_comparison(by_mode, modes)
    print_calibration_comparison(by_mode, modes)
    print_attack_types(by_mode, modes, phases)
    print_agreement(by_mode, modes, phases)
    print_run_to_run(by_mode, phases)
    print_switching(results, by_mode)


def print_calibration_comparison(by_mode, modes):
    calibrated = {m: [r["calibration"] for r in runs if r.get("calibration")] for m, runs in by_mode.items()}
    if not any(calibrated.values()):
        return
    print("--- Calibration by backend ---")
    header = "".join(f"{m:>14}" for m in modes)
    print(f"  {'':<40}{header}")

    def avg(values):
        values = [v for v in values if v is not None]
        return sum(values) / len(values) if values else None

    rows = (
        ("Outcome (last run)", lambda cals: cals[-1]["info"].get("status") if cals else None, "s"),
        ("Recommended rate floor (pps)", lambda cals: avg([c["rate_floor"] for c in cals]), ".1f"),
        ("Recommended entropy floor", lambda cals: avg([c["entropy_floor"] for c in cals]), ".4f"),
        ("Mean rate per target (pps)", lambda cals: avg([c["mean_pps"] for c in cals]), ".1f"),
        ("Calibration time (s)", lambda cals: avg([float(c["info"].get("duration_secs", "nan")) for c in cals]), ".0f"),
        ("Restart to apply floors (s)",
         lambda cals: avg([float(c["apply"]["downtime_to_first_status_secs"]) for c in cals
                           if c["apply"].get("downtime_to_first_status_secs")]), ".1f"),
    )
    for label, getter, spec in rows:
        cells = []
        for m in modes:
            cals = calibrated.get(m) or []
            value = getter(cals) if cals else None
            cells.append("n/a" if value is None else (value if spec == "s" else format(value, spec)))
        print(f"  {label:<40}" + "".join(f"{c:>14}" for c in cells))
    if len(modes) == 2:
        a = avg([c["rate_floor"] for c in calibrated.get(modes[0]) or []])
        b = avg([c["rate_floor"] for c in calibrated.get(modes[1]) or []])
        if a and b and abs(b - a) / a > 0.10:
            print(f"  The rate floors differ by {100.0 * (b - a) / a:+.0f}% between the backends. With CALIBRATE=apply each")
            print("  backend then ran its phases under its own thresholds, which is part of any difference in the")
            print("  detection figures below.")
    print()


def attack_type_descriptions(results):
    """type -> description, from the variants each run recorded."""
    found = {}
    for r in results:
        for phase_variants in r["variants"].values():
            if "attack" in phase_variants:
                variant, description = phase_variants["attack"]
                if description and variant not in found:
                    found[variant] = description
    return found


def print_attack_types(by_mode, modes, phases):
    """One block per attack type covered by the sweep, backends side by side."""
    types = []
    for phase in phases:
        attack_type = phase_info(phase)[3]
        if attack_type and attack_type not in types:
            types.append(attack_type)
    if not types:
        return
    results = [r for runs in by_mode.values() for r in runs]
    descriptions = attack_type_descriptions(results)
    print("--- Attack types ---")
    print("  Each type runs alone, then with Normal traffic added. Entropy figures cover the anomaly")
    print("  windows Stage 1 forwarded. The share of source addresses an attack uses decides how far its")
    print("  entropy sits from Normal and Flash Crowd traffic.")
    rows = (
        ("alone: DDoS verdicts", "attacker_", lambda m: float(m["class2_verdicts"]), ",.0f"),
        ("alone: time to first block (s)", "attacker_", lambda m: m.get("first_block_secs"), ".1f"),
        ("alone: entropy involved (%)", "attacker_", lambda m: m.get("entropy_flag_pct"), ".1f"),
        ("alone: mean entropy", "attacker_", lambda m: m.get("mean_entropy"), ".3f"),
        ("with Normal: DDoS verdicts", "normal_attacker_", lambda m: float(m["class2_verdicts"]), ",.0f"),
        ("with Normal: detection consistency (%)", "normal_attacker_", lambda m: m.get("consistency_pct"), ".1f"),
        ("with Normal: entropy involved (%)", "normal_attacker_", lambda m: m.get("entropy_flag_pct"), ".1f"),
        ("with Normal: mean entropy", "normal_attacker_", lambda m: m.get("mean_entropy"), ".3f"),
    )
    header = "".join(f"{m:>14}" for m in modes)
    for attack_type in types:
        desc = descriptions.get(attack_type)
        print(f"  {attack_type}" + (f": {desc}" if desc else ""))
        print(f"    {'':<42}{header}")
        for label, prefix, getter, spec in rows:
            values = [mean_over_runs(by_mode[m], prefix + attack_type, getter) for m in modes]
            if all(v is None for v in values):
                continue
            print(f"    {label:<42}" + "".join(f"{fmt(v, spec):>14}" for v in values))
    print()


def phase_verdict(m):
    if m is None:
        return None
    return m["class2_verdicts"] > 0


def print_agreement(by_mode, modes, phases):
    """Per phase: did each backend issue a DDoS verdict, and did it act (a block
    or a rate limit)? Most mitigation comes from the enforcement tiers, which
    can act without a class 2 verdict, so both are shown."""
    if len(modes) < 2:
        return
    first, second = modes[0], modes[1]
    print(f"--- Detection agreement between {first} and {second} ---")
    print(f"  {'phase':<28}{'expected':>9}  {'DDoS verdict':<20}{'enforcement action':<22}")
    print(f"  {'':<28}{'':>9}  {first:>9}{second:>9}{'':>2}{first:>9}{second:>9}")
    totals = {"verdict": [0, 0, 0], "action": [0, 0, 0]}
    total = 0
    for phase in phases:
        v1 = mean_over_runs(by_mode[first], phase, lambda m: float(m["class2_verdicts"]))
        v2 = mean_over_runs(by_mode[second], phase, lambda m: float(m["class2_verdicts"]))
        a1 = mean_over_runs(by_mode[first], phase, lambda m: float(m["enforcement_actions"]))
        a2 = mean_over_runs(by_mode[second], phase, lambda m: float(m["enforcement_actions"]))
        if v1 is None or v2 is None:
            continue
        expected = phase_info(phase)[1]
        total += 1
        marks = []
        for key, x, y in (("verdict", v1, v2), ("action", a1 or 0.0, a2 or 0.0)):
            hit1, hit2 = x > 0, y > 0
            totals[key][0] += int(hit1 == hit2)
            totals[key][1] += int(hit1 == expected)
            totals[key][2] += int(hit2 == expected)
            marks.append(("acted" if hit1 else "quiet", "acted" if hit2 else "quiet"))
        v_words = ("verdict" if v1 > 0 else "quiet", "verdict" if v2 > 0 else "quiet")
        differ = " NO" if ((a1 or 0) > 0) != ((a2 or 0) > 0) or (v1 > 0) != (v2 > 0) else ""
        print(f"  {phase:<28}{('attack' if expected else 'clean'):>9}  {v_words[0]:>9}{v_words[1]:>9}{'':>2}"
              f"{marks[1][0]:>9}{marks[1][1]:>9}{differ}")
    if total:
        for key, label in (("verdict", "DDoS verdict"), ("action", "enforcement action")):
            agree, ok1, ok2 = totals[key]
            print(f"  {label}: the backends agree on {agree} of {total} phases; {first} matches the expected "
                  f"outcome in {ok1}, {second} in {ok2}.")
    print("  A phase is expected to act only when it holds an attack. A DDoS verdict in a clean phase is a")
    print("  false positive. An action there needs reading: rate limits on the sources of a concentrated Flash")
    print("  Crowd are a designed, reversible precaution, and a phase with no traffic at all (a generator that")
    print("  failed) counts as a miss.")
    print()


def print_run_to_run(by_mode, phases):
    repeated = {m: runs for m, runs in by_mode.items() if len(runs) > 1}
    if not repeated:
        return
    print("--- Run-to-run spread (standard deviation across repeated runs) ---")
    print("  Traffic variants rotate between runs by design, so this spread includes the effect of the")
    print("  different variants as well as ordinary variation between identical runs.")
    checks = (
        ("DDoS verdicts", lambda m: float(m["class2_verdicts"]), ".1f"),
        ("time to first block (s)", lambda m: m.get("first_block_secs"), ".2f"),
        ("captured packets/s", lambda m: m.get("captured_pps"), ",.0f"),
        ("consistency (%)", lambda m: m.get("consistency_pct"), ".1f"),
    )
    for mode, runs in repeated.items():
        print(f"  {mode}:")
        for label, getter, spec in checks:
            cells = []
            for phase in phases:
                s = spread_over_runs(runs, phase, getter)
                if s is not None:
                    cells.append(f"{phase} {format(s, spec)}")
            if cells:
                print(f"    {label}: " + ", ".join(cells))
    print()


def print_switching(results, by_mode):
    print("--- Downtime, warm-up, and rollback ---")
    for r in results:
        switch = r["switch"]
        if not switch:
            continue
        print(f"  Switch to {r['mode']} (run {r['run']}): capture attached after "
              f"{switch.get('downtime_to_attach_secs', 'n/a')}s, first status line after "
              f"{switch.get('downtime_to_first_status_secs', 'n/a')}s; "
              f"warm-up to a working baseline {r['info'].get('warmup_secs', 'n/a')}s "
              f"({'confirmed' if r['info'].get('warmed') == '1' else 'not confirmed'})")
    print()


def print_rollback(session_dir):
    path = os.path.join(session_dir, "rollback_switch.txt")
    emergency = os.path.join(session_dir, "rollback_emergency_switch.txt")
    used = path if os.path.exists(path) else emergency if os.path.exists(emergency) else None
    if used is None:
        return
    values = load_key_values(used)
    checks = load_checks(used.replace("_switch.txt", "_verify.txt"))
    original = load_key_values(os.path.join(session_dir, "original_state.txt"))
    print("--- Rollback to the original configuration ---")
    if used == emergency:
        print("  The benchmark was interrupted; this is the emergency rollback.")
    print(f"  tuning.env restore: {values.get('tuning_restore', 'n/a')}")
    print(f"  Rollback time until capture attached: {values.get('downtime_to_attach_secs', 'n/a')}s")
    print(f"  Rollback time until the first capture status line: {values.get('downtime_to_first_status_secs', 'n/a')}s"
          + (" (timed out)" if values.get("timed_out") == "1" else ""))
    print(f"  Baselines restored from the production file: {values.get('baselines_restored', 'n/a')}")
    for name, outcome, detail in checks:
        print(f"  Check {name}: {outcome} ({detail})")
    print()


def find_runs(directory):
    if os.path.exists(os.path.join(directory, "phase_boundaries.tsv")):
        return [directory]
    runs = []
    for entry in sorted(os.listdir(directory)):
        sub = os.path.join(directory, entry)
        if os.path.isdir(sub) and os.path.exists(os.path.join(sub, "phase_boundaries.tsv")):
            runs.append(sub)
    return runs


def json_safe(result):
    trimmed = {k: v for k, v in result.items() if k != "system_samples"}
    return trimmed


def analyze(directory, capture_pct=ZERO_LOSS_CAPTURE_PCT, probe_pct=ZERO_LOSS_PROBE_PCT):
    run_dirs = find_runs(directory)
    if not run_dirs:
        raise SystemExit(f"[-] No run directories with phase_boundaries.tsv under {directory}")
    print("=== FLOD Live Benchmark Report ===\n")
    results = [analyze_run(d, capture_pct, probe_pct) for d in run_dirs]
    for r in results:
        print_run_report(r)
        print_calibration(r)
        system_health_whole_run(r)
        print_firewall_state(r["run_dir"])
        print()
    if len(results) > 1 or os.path.exists(os.path.join(directory, "rollback_switch.txt")):
        print_comparison(results)
    if directory not in run_dirs:
        print_rollback(directory)
        with open(os.path.join(directory, "results.json"), "w") as f:
            json.dump([json_safe(r) for r in results], f, indent=2, default=str)
    print("Note: these counts are not a like-for-like comparison against")
    print("scripts/benchmark_fixed_threshold.py's own numbers. That script scores")
    print("every post-warmup CSV row; this report only sees windows Stage 1 chose")
    print("to forward to Stage 2 (anomaly-or-heartbeat), a narrower view of the")
    print("same system with a different denominator.")
    print("Attack phases after the first inherit blocks from the earlier ones, since a")
    print("block lasts an hour, so their time to first block reads shorter than a cold start.")
    print("Process CPU excludes work the kernel does on the process's behalf in softirq")
    print("context, which is why the system-wide figures are listed beside it.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Report on a session captured by scripts/benchmark_live.sh.")
    parser.add_argument("directory", help="session directory or a single run directory")
    parser.add_argument("--zero-loss-capture-pct", type=float, default=ZERO_LOSS_CAPTURE_PCT,
                        help="a limit step is loss-free only if the capture backend saw at least this share "
                             f"of the interface packets (default {ZERO_LOSS_CAPTURE_PCT}, a starting point)")
    parser.add_argument("--zero-loss-probe-pct", type=float, default=ZERO_LOSS_PROBE_PCT,
                        help="a limit step is loss-free only if at most this share of latency probes was lost "
                             f"(default {ZERO_LOSS_PROBE_PCT}, a starting point)")
    args = parser.parse_args()
    analyze(args.directory, args.zero_loss_capture_pct, args.zero_loss_probe_pct)
