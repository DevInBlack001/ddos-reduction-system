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

import os
import re
import sys

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
    # A benchmark run can cross midnight (Normal starting one day, Mixed
    # finishing the next), and a single fixed date silently drops every line
    # after the rollover from every phase window, this was caught by running
    # the script for real, not by inspection.
    m = TS_RE.match(line)
    if not m:
        return None
    month_name, day, time_part = m.groups()
    month = MONTHS.get(month_name)
    if month is None:
        return None
    return f"{year_hint}-{month}-{int(day):02d} {time_part}"


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
        if total_anomaly > 0:
            rate = class2_count / total_anomaly
            label = "escalation rate" if name in ("attacker", "mixed") else "false-positive rate (of anomaly-flagged windows)"
            print(f"  {label}: {rate:.1%}")
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
