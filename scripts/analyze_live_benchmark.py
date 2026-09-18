#!/usr/bin/env python3
"""
analyze_live_benchmark.py: reports on a session captured by
scripts/benchmark_live.sh.

Not directly comparable, row for row, to scripts/benchmark_fixed_threshold.py:
that script scores every post-warmup CSV row, this one only sees what Stage 1
actually forwarded to Stage 2 (anomaly-or-heartbeat windows), which is a
narrower, real-world-shaped view, not an equivalent denominator. Reported as
such rather than presented as a matching number.

Usage: python3 scripts/analyze_live_benchmark.py <output-dir>
Expects <output-dir>/stage1.log, stage2.log, firewall.log, phase_boundaries.tsv,
written by benchmark_live.sh.
"""

import csv
import os
import re
import sys
from datetime import datetime

MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
    "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def load_phases(output_dir):
    path = os.path.join(output_dir, "phase_boundaries.tsv")
    phases = []
    with open(path) as f:
        for line in f:
            name, ts = line.rstrip("\n").split("\t")
            phases.append((name, ts))
    # Pair each phase with the timestamp of the one after it, so every phase
    # has a [start, end) window; the last one runs to session_end.
    windows = []
    for i in range(len(phases) - 1):
        windows.append((phases[i][0], phases[i][1], phases[i + 1][1]))
    return windows


def in_window(line_ts, start_ts, end_ts):
    return start_ts <= line_ts < end_ts


TS_RE = re.compile(r"^(\w+)\s+(\d+) (\d{2}:\d{2}:\d{2})")


def line_time(line, year_hint):
    # journalctl's default format carries month and day but no year;
    # reconstruct a full "YYYY-MM-DD HH:MM:SS" from each line's own month/day
    # rather than a single date captured once at the start of the session.
    # A benchmark run can cross midnight (Normal starting one day, the final
    # all-three phase finishing the next), and a single fixed date silently
    # drops every line after the rollover from every phase window, this was
    # caught by running the script for real, not by inspection.
    m = TS_RE.match(line)
    if not m:
        return None
    month_name, day, time_part = m.groups()
    month = MONTHS.get(month_name)
    if month is None:
        return None
    return f"{year_hint}-{month}-{int(day):02d} {time_part}"


CAPTURE_STATUS_RE = re.compile(
    r"Capture: status \| interface=(\S+) \| raw_captured=(\d+) \| timeouts=(\d+) "
    r"\| parse_failed=(\d+) \| non_ip=(\d+) \| truncated=(\d+) \| forwarded=(\d+)"
)
KERNEL_STATUS_RE = re.compile(
    r"Kernel: status \| interface=(\S+) \| ingress=(\d+) \| egress=(\d+) \| sources=\d+ "
    r"\([\d.]+% of map\) \| flows=(\d+) \| ports=(\d+) \| ttls=(\d+) \| fingerprints=(\d+) "
    r"\| drains=(\d+) \| errors=(\d+)"
)


def parse_traffic_samples(stage1_lines, year_hint):
    # Both capture backends already log a periodic cumulative status line at
    # info level, inside the same journalctl window this script already
    # reads. No new instrumentation needed for real packet counts and drop
    # reasons, just a second regex pass over the same log.
    samples = []
    for line in stage1_lines:
        ts = line_time(line, year_hint)
        if ts is None:
            continue
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
    # Every field in these status lines only ever increases across the
    # session, so the last sample at or before target_ts is the cumulative
    # total going into that instant.
    result = None
    for ts, backend, counters in samples:
        if ts > target_ts:
            break
        result = (backend, counters)
    return result


def traffic_delta(samples, start_ts, end_ts):
    before = counters_at_or_before(samples, start_ts)
    after = counters_at_or_before(samples, end_ts)
    if before is None or after is None or before[0] != after[0]:
        return None
    backend, before_counters = before
    _, after_counters = after
    return backend, {k: after_counters[k] - before_counters[k] for k in before_counters}


def load_system_samples(output_dir):
    path = os.path.join(output_dir, "system_samples.csv")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def load_clk_tck(output_dir):
    path = os.path.join(output_dir, "clk_tck.txt")
    if not os.path.exists(path):
        return 100
    with open(path) as f:
        try:
            return int(f.read().strip())
        except ValueError:
            return 100


def parse_ts(ts_str):
    return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")


def system_summary(samples, start_ts, end_ts, clk_tck, pid_field, ticks_field, rss_field):
    window = [s for s in samples if start_ts <= s["timestamp"] < end_ts and s.get(pid_field)]
    if len(window) < 2:
        return None
    pids = {s[pid_field] for s in window}
    if len(pids) > 1:
        return {"restarted": True, "pids": sorted(pids)}
    first, last = window[0], window[-1]
    try:
        delta_ticks = int(last[ticks_field]) - int(first[ticks_field])
    except (ValueError, TypeError):
        return None
    delta_wall = (parse_ts(last["timestamp"]) - parse_ts(first["timestamp"])).total_seconds()
    if delta_wall <= 0:
        return None
    rss_values = [int(s[rss_field]) for s in window if s.get(rss_field)]
    return {
        "restarted": False,
        "cpu_pct": 100.0 * delta_ticks / (clk_tck * delta_wall),
        "rss_avg_mb": (sum(rss_values) / len(rss_values)) / 1024 if rss_values else None,
        "rss_max_mb": max(rss_values) / 1024 if rss_values else None,
    }


def analyze(output_dir):
    windows = load_phases(output_dir)
    if not windows:
        print("[-] No phase boundaries found; did benchmark_live.sh run to completion?")
        sys.exit(1)
    year_hint = windows[0][1].split("-")[0]

    with open(os.path.join(output_dir, "stage1.log")) as f:
        stage1_lines = f.readlines()
    with open(os.path.join(output_dir, "stage2.log")) as f:
        stage2_lines = f.readlines()

    traffic_samples = parse_traffic_samples(stage1_lines, year_hint)
    system_samples = load_system_samples(output_dir)
    clk_tck = load_clk_tck(output_dir)

    print("=== FLOD Live Benchmark Report ===")
    print(f"Session start: {windows[0][1]} (UTC)\n")

    class2_patterns = [
        "Class-2 window",
        "Class-2 verdict but no active flow data",
        "Aggregate cap fallback: class-2 verdict",
    ]

    for name, start_ts, end_ts in windows:
        print(f"--- Phase: {name} ({start_ts} to {end_ts}) ---")

        anomaly_by_victim = {}
        for line in stage1_lines:
            ts = line_time(line, year_hint)
            if ts is None or not in_window(ts, start_ts, end_ts):
                continue
            if "ANOMALY" not in line:
                continue
            m = re.search(r"victim=(\S+?)\]", line)
            if m:
                anomaly_by_victim[m.group(1)] = anomaly_by_victim.get(m.group(1), 0) + 1

        class2_count = 0
        mitigation_count = 0
        for line in stage2_lines:
            ts = line_time(line, year_hint)
            if ts is None or not in_window(ts, start_ts, end_ts):
                continue
            if any(p in line for p in class2_patterns):
                class2_count += 1
            if "MITIGATION TRIGGERED" in line:
                mitigation_count += 1

        total_anomaly = sum(anomaly_by_victim.values())
        print(f"  Anomaly-flagged windows (Stage 1): {total_anomaly}"
              + (f" across {len(anomaly_by_victim)} targets" if anomaly_by_victim else ""))
        for victim, count in sorted(anomaly_by_victim.items()):
            print(f"    {victim}: {count}")
        print(f"  Class-2 (DDoS) verdicts (Stage 2): {class2_count}")
        print(f"  Enforcement actions triggered: {mitigation_count}")
        attack_phases = ("attacker", "normal_attacker", "flashcrowd_attacker", "all_three")
        if total_anomaly > 0:
            rate = class2_count / total_anomaly
            label = "escalation rate" if name in attack_phases else "false-positive rate (of anomaly-flagged windows)"
            print(f"  {label}: {rate:.1%}")

        delta = traffic_delta(traffic_samples, start_ts, end_ts)
        if delta is None:
            print("  Traffic: no capture status samples in this phase window")
        else:
            backend, counts = delta
            if backend == "pcap":
                dropped = counts["parse_failed"] + counts["non_ip"] + counts["truncated"]
                print(f"  Traffic (pcap): {counts['raw_captured']} captured, "
                      f"{counts['forwarded']} forwarded, {dropped} dropped "
                      f"({counts['parse_failed']} unparseable, {counts['non_ip']} non-IP, "
                      f"{counts['truncated']} truncated), {counts['timeouts']} read timeouts")
            else:
                print(f"  Traffic (kernel): {counts['ingress']} ingress packets, "
                      f"{counts['egress']} egress packets, {counts['errors']} map drain errors "
                      f"across {counts['drains']} drains")

        for label, pid_f, ticks_f, rss_f in (
            ("Stage 1", "stage1_pid", "stage1_cpu_ticks", "stage1_rss_kb"),
            ("Stage 2", "stage2_pid", "stage2_cpu_ticks", "stage2_rss_kb"),
        ):
            if not system_samples:
                continue
            summary = system_summary(system_samples, start_ts, end_ts, clk_tck, pid_f, ticks_f, rss_f)
            if summary is None:
                print(f"  {label} system health: no samples in this phase window")
            elif summary["restarted"]:
                pids = ", ".join(summary["pids"])
                print(f"  {label} system health: process restarted during this phase "
                      f"(pids {pids}), CPU figure skipped")
            else:
                rss_part = ""
                if summary["rss_avg_mb"] is not None:
                    rss_part = (f", RSS avg {summary['rss_avg_mb']:.1f} MB / "
                                f"peak {summary['rss_max_mb']:.1f} MB")
                print(f"  {label} system health: {summary['cpu_pct']:.1f}% CPU{rss_part}")
        print()

    firewall_path = os.path.join(output_dir, "firewall.log")
    if os.path.exists(firewall_path):
        with open(firewall_path) as f:
            firewall = f.read()
        entries = re.findall(r"Number of entries: (\d+)", firewall)
        print("--- Final firewall state ---")
        if len(entries) >= 2:
            print(f"  Blocked (hard): {entries[0]}")
            print(f"  Rate-limited:   {entries[1]}")
        else:
            print(firewall)

    print("\n--- System health (whole session) ---")
    if not system_samples:
        print("  No system_samples.csv found; the sampler either wasn't reached")
        print("  or benchmark_live.sh predates this feature.")
    else:
        for label, pid_f, ticks_f, rss_f in (
            ("Stage 1", "stage1_pid", "stage1_cpu_ticks", "stage1_rss_kb"),
            ("Stage 2", "stage2_pid", "stage2_cpu_ticks", "stage2_rss_kb"),
        ):
            pids = {s[pid_f] for s in system_samples if s.get(pid_f)}
            if not pids:
                print(f"  {label}: never sampled (service not running, or unit name mismatch)")
                continue
            if len(pids) > 1:
                print(f"  {label}: restarted during the session (pids {', '.join(sorted(pids))})")
            rss_values = [int(s[rss_f]) for s in system_samples if s.get(rss_f)]
            if rss_values:
                print(f"  {label}: peak RSS {max(rss_values) / 1024:.1f} MB, "
                      f"{len(system_samples)} samples over the session")

    total_traffic = traffic_delta(traffic_samples, windows[0][1], windows[-1][2])
    if total_traffic:
        backend, counts = total_traffic
        if backend == "pcap":
            dropped = counts["parse_failed"] + counts["non_ip"] + counts["truncated"]
            print(f"  Capture (pcap), whole session: {counts['raw_captured']} captured, "
                  f"{dropped} dropped, {counts['timeouts']} read timeouts")
        else:
            print(f"  Capture (kernel), whole session: {counts['ingress']} ingress packets, "
                  f"{counts['egress']} egress packets, {counts['errors']} map drain errors")

    print("\nNote: these counts are not a like-for-like comparison against")
    print("scripts/benchmark_fixed_threshold.py's own numbers. That script scores")
    print("every post-warmup CSV row; this report only sees windows Stage 1 chose")
    print("to forward to Stage 2 (anomaly-or-heartbeat), a narrower, real-world")
    print("view of the same system, not an equivalent denominator.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/analyze_live_benchmark.py <output-dir>")
        sys.exit(1)
    analyze(sys.argv[1])
