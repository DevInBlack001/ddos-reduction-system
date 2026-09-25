#!/usr/bin/env python3
"""
trim_ddos_class.py: caps the DDoS (label 2) row count in a training CSV
at the smaller of the Normal (label 0) and Flash Crowd (label 1) row
counts, so DDoS can never outnumber either other class.

Why this exists: the confidence gated auto-label pipeline
(docs/training.md#confidence-gated-automatic-labeling) captures DDoS
unconditionally into ddos_capture.csv, but only captures Normal and
Flash Crowd candidates when the Isolation Forest also flags them
anomalous, a narrow, comparatively rare condition. A merge from that
queue is DDoS-heavy by construction, not by any fault in the data
itself, and left unchecked across enough merges the training set's
own class balance drifts further DDoS-heavy each time.

Run this once, right after every merge into the training CSV (the
dashboard's Merge button, or a manual append), before the next
retrain. It is not run automatically as part of the merge itself,
deliberately: this project's own convention is that training data
changes are deliberate, operator-run steps, never a hidden side
effect (see docs/training.md's own reasoning for why an Anomalous
flag does not retrain anything by itself).

Whole DDoS *sessions* are dropped, never individual rows picked at
random out of a session. train.py derives a session from timestamp
gaps over 30 seconds or a label change, computed on the raw sorted
rows; deleting scattered rows from the middle of one real capture run
opens up a fake >30s gap where none existed, splitting one session
into two and corrupting the row count LOSO evaluation depends on
(train.py's own comment on this exact failure mode is what this
script's session detection is copied from, kept in sync deliberately
rather than imported, since train.py's own detection runs on a
pandas DataFrame this script has no reason to depend on).

Sessions are shuffled (a fixed --seed by default, for a reproducible
result) before dropping, not dropped biggest-first, so trimming does
not systematically remove only the largest DDoS sessions and leave a
skewed mix of small ones behind.

Usage:
    trim_ddos_class.py <path/to/training.csv> [--seed 42] [--dry-run]

Writes the trimmed result back to the same file (in place) unless
--dry-run is given, in which case nothing is written and only the
before/after counts are reported.
"""

import argparse
import csv
import random
import sys

LABEL_COL = "label"
TIMESTAMP_COL = "timestamp"
NORMAL, FLASH_CROWD, DDOS = "0", "1", "2"
SESSION_GAP_SECONDS = 30.0


def assign_sessions(rows):
    """Mirrors train.py's own session detection exactly: sorted by
    timestamp, a new session starts whenever the gap since the previous
    row exceeds SESSION_GAP_SECONDS or the label changes. Returns rows
    in that sorted order, each annotated with its session_id."""
    rows = sorted(rows, key=lambda r: float(r[TIMESTAMP_COL]))
    session_id = 0
    prev_ts = None
    prev_label = None
    for row in rows:
        ts = float(row[TIMESTAMP_COL])
        label = row[LABEL_COL]
        is_new = prev_ts is None or (ts - prev_ts) > SESSION_GAP_SECONDS or label != prev_label
        if is_new:
            session_id += 1
        row["_session_id"] = session_id
        prev_ts = ts
        prev_label = label
    return rows


def trim_ddos_sessions(rows, seed):
    """Returns (kept_rows, dropped_row_count, cap). Drops whole DDoS
    sessions, shuffled with `seed`, until the retained DDoS row count is
    at or under the cap (the smaller of the Normal and Flash Crowd row
    counts). Every Normal and Flash Crowd row, and every row of a DDoS
    session not dropped, is returned unchanged and in its original
    sorted order."""
    rows = assign_sessions(rows)

    counts = {NORMAL: 0, FLASH_CROWD: 0, DDOS: 0}
    for row in rows:
        counts[row[LABEL_COL]] = counts.get(row[LABEL_COL], 0) + 1
    cap = min(counts.get(NORMAL, 0), counts.get(FLASH_CROWD, 0))

    if counts.get(DDOS, 0) <= cap:
        return rows, 0, cap

    ddos_sessions = {}
    for row in rows:
        if row[LABEL_COL] == DDOS:
            ddos_sessions.setdefault(row["_session_id"], []).append(row)

    session_ids = list(ddos_sessions.keys())
    random.Random(seed).shuffle(session_ids)

    kept_ddos_session_ids = set()
    kept_ddos_row_count = 0
    for sid in session_ids:
        session_size = len(ddos_sessions[sid])
        if kept_ddos_row_count + session_size <= cap:
            kept_ddos_session_ids.add(sid)
            kept_ddos_row_count += session_size
    # A session is only ever kept whole or dropped whole, so the total
    # can land under the cap (never over it) when no remaining session
    # fits the gap exactly; this is expected, not a bug, per the "not
    # more than them" requirement rather than "exactly as much as them."

    dropped = counts[DDOS] - kept_ddos_row_count
    result = [
        row for row in rows
        if row[LABEL_COL] != DDOS or row["_session_id"] in kept_ddos_session_ids
    ]
    return result, dropped, cap


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("csv_path", help="Training CSV to trim in place.")
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for which DDoS sessions to drop (default 42, for a reproducible result).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report the before/after counts without writing the file.",
    )
    args = parser.parse_args()

    with open(args.csv_path, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    if not fieldnames or LABEL_COL not in fieldnames or TIMESTAMP_COL not in fieldnames:
        print(f"[-] {args.csv_path} has no '{LABEL_COL}'/'{TIMESTAMP_COL}' columns, refusing to touch it.", file=sys.stderr)
        sys.exit(1)

    before = {NORMAL: 0, FLASH_CROWD: 0, DDOS: 0}
    for row in rows:
        before[row.get(LABEL_COL, "")] = before.get(row.get(LABEL_COL, ""), 0) + 1
    print(f"[+] Before: Normal={before.get(NORMAL, 0)} Flash Crowd={before.get(FLASH_CROWD, 0)} DDoS={before.get(DDOS, 0)}")

    trimmed, dropped, cap = trim_ddos_sessions(rows, args.seed)

    if dropped == 0:
        print(f"[+] DDoS ({before.get(DDOS, 0)}) already at or under the cap ({cap}), nothing to trim.")
        return

    after = {NORMAL: 0, FLASH_CROWD: 0, DDOS: 0}
    for row in trimmed:
        after[row.get(LABEL_COL, "")] = after.get(row.get(LABEL_COL, ""), 0) + 1
    print(f"[+] DDoS cap is {cap} (the smaller of Normal/Flash Crowd). Dropping {dropped} DDoS row(s) as whole sessions (seed={args.seed}).")
    print(f"[+] After: Normal={after.get(NORMAL, 0)} Flash Crowd={after.get(FLASH_CROWD, 0)} DDoS={after.get(DDOS, 0)}")

    if args.dry_run:
        print("[+] --dry-run: not writing changes.")
        return

    with open(args.csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in trimmed:
            writer.writerow({k: row[k] for k in fieldnames})
    print(f"[+] Wrote trimmed CSV back to {args.csv_path}.")


if __name__ == "__main__":
    main()
