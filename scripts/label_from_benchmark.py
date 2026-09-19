#!/usr/bin/env python3
"""
label_from_benchmark.py: turn captured windows into labeled training rows
using what a live benchmark was sending at the time.

The benchmark records which traffic classes ran in every phase
(traffic_variants.tsv) and when each phase began (phase_boundaries.tsv). A
capture row whose timestamp falls inside a phase can therefore be labeled
from the known ground truth, with no model opinion involved:

  attack traffic in the phase        -> 2 (DDoS)
  Flash Crowd but no attack          -> 1 (Flash Crowd)
  only Normal traffic                -> 0 (Normal)

Rows near a phase boundary are skipped, since traffic is still ramping up or
draining there. Phases with no recorded traffic (gaps) are skipped.

Usage:
  label_from_benchmark.py --run RUN_DIR [--run RUN_DIR ...] \\
      --capture ddos_capture.csv --capture anomalous_capture.csv \\
      --out benchmark_labeled.csv [--labels 0,1] [--margin 15]

By default only labels 0 and 1 are written: the captures hold windows the
models called DDoS or doubted, so Normal and Flash Crowd rows in them are
the ones the models got wrong. --labels 0,1,2 adds the DDoS rows too.
"""

import argparse
import csv
import datetime
import os
import sys

BASE_CSV_HEADER = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "source_port_entropy", "ttl_variance",
    "fingerprint_diversity", "timestamp", "label",
]
TIMESTAMP_COL = BASE_CSV_HEADER.index("timestamp")
LABEL_COL = BASE_CSV_HEADER.index("label")
DEFAULT_MARGIN_SECS = 15.0


def parse_boundary_time(text):
    """Phase times are gateway UTC, written as YYYY-MM-DD HH:MM:SS[.ffffff]."""
    parsed = datetime.datetime.strptime(text.strip()[:19], "%Y-%m-%d %H:%M:%S")
    return parsed.replace(tzinfo=datetime.timezone.utc).timestamp()


def phase_label(classes):
    """Ground-truth label for a phase from the traffic classes it ran, or
    None when nothing ran."""
    if "attack" in classes:
        return 2
    if "flashcrowd" in classes:
        return 1
    if "normal" in classes:
        return 0
    return None


def load_phases(run_dir, margin_secs):
    """Returns [(start, end, label, name)] for one benchmark run directory,
    with the margin trimmed off both ends of every phase."""
    boundaries = []
    with open(os.path.join(run_dir, "phase_boundaries.tsv")) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[0]:
                boundaries.append((parts[0], parse_boundary_time(parts[1])))
    classes = {}
    variants_path = os.path.join(run_dir, "traffic_variants.tsv")
    if os.path.exists(variants_path):
        with open(variants_path) as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2:
                    classes.setdefault(parts[0], set()).add(parts[1])
    phases = []
    for (name, start), (_, end) in zip(boundaries, boundaries[1:]):
        label = phase_label(classes.get(name, set()))
        if label is None:
            continue
        if end - start <= 2 * margin_secs:
            continue
        phases.append((start + margin_secs, end - margin_secs, label, name))
    return phases


def read_capture_rows(path):
    """Base-column rows from a capture CSV. Rows whose column count differs
    from the header (torn writes) or whose timestamp is not a number are
    skipped."""
    rows = []
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header is None:
            return rows
        for row in reader:
            if len(row) != len(header):
                continue
            try:
                float(row[TIMESTAMP_COL])
            except (ValueError, IndexError):
                continue
            rows.append(row[:len(BASE_CSV_HEADER)])
    return rows


def label_rows(rows, phases, wanted_labels):
    """Returns (labeled_rows, counts_by_phase). Duplicate rows, which appear
    when a window is in both capture files, are written once."""
    labeled, counts, seen = [], {}, set()
    for row in rows:
        ts = float(row[TIMESTAMP_COL])
        for start, end, label, name in phases:
            if start <= ts < end:
                if label in wanted_labels:
                    key = tuple(row[:TIMESTAMP_COL + 1])
                    if key not in seen:
                        seen.add(key)
                        out = list(row)
                        out[LABEL_COL] = str(label)
                        labeled.append(out)
                        counts[name] = counts.get(name, 0) + 1
                break
    return labeled, counts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--run", action="append", required=True,
                        help="benchmark run directory (has phase_boundaries.tsv)")
    parser.add_argument("--capture", action="append", required=True,
                        help="capture CSV copied from the gateway")
    parser.add_argument("--out", required=True)
    parser.add_argument("--labels", default="0,1",
                        help="comma separated labels to write (default 0,1)")
    parser.add_argument("--margin", type=float, default=DEFAULT_MARGIN_SECS,
                        help="seconds skipped after a phase begins and before it ends")
    args = parser.parse_args(argv)

    wanted = {int(x) for x in args.labels.split(",") if x.strip()}
    if not wanted <= {0, 1, 2}:
        parser.error("--labels takes 0, 1, and 2 only")

    phases = []
    for run_dir in args.run:
        phases.extend(load_phases(run_dir, args.margin))
    rows = []
    for path in args.capture:
        rows.extend(read_capture_rows(path))
    labeled, counts = label_rows(rows, phases, wanted)

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(BASE_CSV_HEADER)
        w.writerows(labeled)
    by_label = {}
    for row in labeled:
        by_label[row[LABEL_COL]] = by_label.get(row[LABEL_COL], 0) + 1
    print(f"Wrote {len(labeled)} labeled row(s) to {args.out}: {dict(sorted(by_label.items()))}")
    for name, count in sorted(counts.items()):
        print(f"  {name}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
