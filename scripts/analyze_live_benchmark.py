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
narrower, real-world-shaped view with a different denominator.

Usage: python3 scripts/analyze_live_benchmark.py <session-or-run-dir>
A run directory holds stage1.log, stage2.log, firewall.log,
phase_boundaries.tsv, and optionally system_samples.csv, clk_tck.txt,
firewall_counters.tsv, mode_switch.txt, and run_info.txt.
"""

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
BIN_SECS = 10
LATENCY_KINDS = ("handoff", "inference", "enforcement", "window_to_rule")

CLASS2_PATTERNS = (
    "Class-2 window",
    "Class-2 verdict but no active flow data",
    "Aggregate cap fallback: class-2 verdict",
)


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


def parse_traffic_samples(stage1_events):
    # Both capture backends already log a periodic status line at info level,
    # inside the same journalctl window this script already reads.
    samples = []
    for ts, line in stage1_events:
        m = CAPTURE_STATUS_RE.search(line)
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
        result = (backend, counters)
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
    before = counters_at_or_before(samples, start_ts)
    after = counters_at_or_before(samples, end_ts)
    if before is None or after is None or before[0] != after[0]:
        return None
    backend, before_counters = before
    _, after_counters = after
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
    tx = cumulative_delta(samples, start_ts, end_ts, "egress_tx_packets")
    if tx:
        metrics["egress_pps"] = tx[0] / tx[1]
    tx_bytes = cumulative_delta(samples, start_ts, end_ts, "egress_tx_bytes")
    if tx_bytes:
        metrics["egress_mbps"] = tx_bytes[0] * 8 / tx_bytes[1] / 1e6
    return metrics


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


def analyze_run(run_dir):
    windows = load_phases(run_dir)
    if not windows:
        raise SystemExit(f"[-] No phase boundaries in {run_dir}; did benchmark_live.sh run to completion?")
    year_hint = windows[0][1].split("-")[0]
    stage1_events = load_events(os.path.join(run_dir, "stage1.log"), year_hint)
    stage2_events = load_events(os.path.join(run_dir, "stage2.log"), year_hint)
    traffic_samples = parse_traffic_samples(stage1_events)
    system_samples = load_system_samples(run_dir)
    clk_tck = load_clk_tck(run_dir)
    firewall = firewall_drops(load_firewall_rows(run_dir), [w[0] for w in windows] + ["session_end"])
    info = load_key_values(os.path.join(run_dir, "run_info.txt"))
    switch = load_key_values(os.path.join(run_dir, "mode_switch.txt"))

    phases = {}
    for name, start_ts, end_ts in windows:
        if name not in PHASE_ORDER:
            continue
        s1 = events_in(stage1_events, start_ts, end_ts)
        s2 = events_in(stage2_events, start_ts, end_ts)
        duration = seconds_between(start_ts, end_ts)
        m = {"start": start_ts, "end": end_ts, "duration_secs": duration}

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

        expect_attack = name in ATTACK_PHASES
        m["consistency_pct"] = bin_consistency(class2_times, start_ts, end_ts, expect_attack)
        if name in FRESH_ATTACK_PHASES:
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
        phases[name] = m

    return {
        "run_dir": run_dir,
        "mode": info.get("mode") or ("kernel" if any(p.get("capture_backend") == "kernel" for p in phases.values()) else "pcap"),
        "run": info.get("run", "1"),
        "info": info,
        "switch": switch,
        "verify": load_checks(os.path.join(run_dir, "mode_verify.txt")),
        "phases": phases,
        "system_samples": system_samples,
    }


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
    print()

    for name, m in result["phases"].items():
        print(f"--- Phase: {name} ({m['start']} to {m['end']}, {m['duration_secs']:.0f}s) ---")
        print(f"  Anomaly-flagged windows (Stage 1): {m['anomaly_windows']}"
              + (f" across {len(m['anomaly_by_victim'])} targets" if m["anomaly_by_victim"] else ""))
        for victim, count in sorted(m["anomaly_by_victim"].items()):
            print(f"    {victim}: {count}")
        print(f"  Class-2 (DDoS) verdicts (Stage 2): {m['class2_verdicts']}")
        print(f"  Enforcement actions triggered: {m['enforcement_actions']} "
              f"({m['blocks']} blocks, {m['ratelimits']} rate limits)")
        if "class2_rate_pct" in m:
            label = "escalation rate" if name in ATTACK_PHASES else "false-positive rate (of anomaly-flagged windows)"
            print(f"  {label}: {m['class2_rate_pct']:.1f}%")
        if m["consistency_pct"] is not None:
            what = "attack verdicts in the bins after the first detection" if name in ATTACK_PHASES \
                else "bins with no DDoS verdict"
            print(f"  Detection consistency ({BIN_SECS}s bins, {what}): {m['consistency_pct']:.1f}%")
        if name in FRESH_ATTACK_PHASES:
            print("  Time from phase start to: "
                  f"first anomaly flag {fmt_secs(m.get('first_anomaly_secs'))}, "
                  f"first DDoS verdict {fmt_secs(m.get('first_class2_secs'))}, "
                  f"first block {fmt_secs(m.get('first_block_secs'))}, "
                  f"first rate limit {fmt_secs(m.get('first_ratelimit_secs'))}")

        if "captured_packets" not in m:
            print("  Traffic: no capture status samples in this phase window")
        elif m["capture_backend"] == "pcap":
            print(f"  Traffic (pcap): {m['captured_packets']} captured ({fmt(m.get('captured_pps'), ',.0f')} pps), "
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
        print()

    print_switch(result)


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
    ("DDoS verdict share of anomaly windows (%)", lambda m: m.get("class2_rate_pct"), ".1f"),
)


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
        for phase in PHASE_ORDER:
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

    print_agreement(by_mode, modes)
    print_run_to_run(by_mode)
    print_switching(results, by_mode)


def phase_verdict(m):
    if m is None:
        return None
    return m["class2_verdicts"] > 0


def print_agreement(by_mode, modes):
    if len(modes) < 2:
        return
    first, second = modes[0], modes[1]
    print(f"--- Detection agreement between {first} and {second} ---")
    print(f"  {'phase':<22}{'expected':>10}{first:>10}{second:>10}{'agree':>8}")
    agree, total, correct = 0, 0, {mode: 0 for mode in modes[:2]}
    for phase in PHASE_ORDER:
        a = mean_over_runs(by_mode[first], phase, lambda m: float(m["class2_verdicts"]))
        b = mean_over_runs(by_mode[second], phase, lambda m: float(m["class2_verdicts"]))
        if a is None or b is None:
            continue
        expected = phase in ATTACK_PHASES
        va, vb = a > 0, b > 0
        total += 1
        agree += int(va == vb)
        correct[first] += int(va == expected)
        correct[second] += int(vb == expected)
        label = {True: "attack", False: "clean"}
        print(f"  {phase:<22}{label[expected]:>10}{('detected' if va else 'quiet'):>10}"
              f"{('detected' if vb else 'quiet'):>10}{('yes' if va == vb else 'NO'):>8}")
    if total:
        print(f"  The backends agree on {agree} of {total} phases; "
              f"{first} matches the expected verdict in {correct[first]}, {second} in {correct[second]}.")
    print()


def print_run_to_run(by_mode):
    repeated = {m: runs for m, runs in by_mode.items() if len(runs) > 1}
    if not repeated:
        return
    print("--- Run-to-run spread (standard deviation across repeated runs) ---")
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
            for phase in PHASE_ORDER:
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


def analyze(directory):
    run_dirs = find_runs(directory)
    if not run_dirs:
        raise SystemExit(f"[-] No run directories with phase_boundaries.tsv under {directory}")
    print("=== FLOD Live Benchmark Report ===\n")
    results = [analyze_run(d) for d in run_dirs]
    for r in results:
        print_run_report(r)
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
    print("to forward to Stage 2 (anomaly-or-heartbeat), a narrower, real-world")
    print("view of the same system with a different denominator.")
    print("Attack phases after the first inherit blocks from the earlier ones, since a")
    print("block lasts an hour, so their time to first block reads shorter than a cold start.")
    print("Process CPU excludes work the kernel does on the process's behalf in softirq")
    print("context, which is why the system-wide figures are listed beside it.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/analyze_live_benchmark.py <session-or-run-dir>")
        sys.exit(1)
    analyze(sys.argv[1])
