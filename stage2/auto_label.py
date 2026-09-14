#!/usr/bin/env python3
"""
auto_label.py: Stage 2, V8's confidence gated automatic labeling.

Run periodically by a systemd timer (ddos-stage2-auto-label.timer), not a
background thread inside stage2.py: this reads and rewrites CSV files on
disk, the same "runs occasionally against accumulated state" shape as
scripts/calibrate.py, not something that belongs sharing the long-running
service's own concurrency.

Re-scores rows in config.PRETRAINING_CSV_PATH (cold-start windows) and
config.ANOMALOUS_CSV_PATH (Isolation-Forest-flagged windows) against the
RandomForest and a second, independently trained model. A row is only
auto-labeled when both models agree on the class, both clear the
confidence threshold, and both were trained after the row was captured.
See docs/specs/2026-09-13-confidence-gated-labeling-design.md for why:
re-running the same RF against a row it already has a blind spot for
would just reproduce that blind spot with new-found confidence.

Confidently labeled rows are staged in config.AUTO_LABELED_CSV_PATH, not
written into training_data.csv directly, so nothing enters the
authoritative training set without an operator's own deliberate merge.
"""

import os
import csv
import time
import logging

import joblib
import numpy as np
import pandas as pd

import config

FEATURE_COLS = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "delta_rate", "delta_entropy",
    "dominant_rate", "source_port_entropy", "ttl_variance", "fingerprint_diversity",
]
BASE_CSV_HEADER = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "source_port_entropy", "ttl_variance",
    "fingerprint_diversity", "timestamp", "label",
]
# Index of the timestamp column within a BASE_CSV_HEADER row.
TIMESTAMP_COL = 11


def is_row_eligible(row_timestamp, model_mtimes, delay_hours, now=None):
    """A captured row is eligible for automatic labeling only once it is
    older than delay_hours, and only if every model that will score it was
    trained after it was captured. The freshness half of this check is the
    core safeguard: a model that has not changed since a row was captured
    cannot be trusted to auto-label its own blind spot."""
    now = time.time() if now is None else now
    age_hours = (now - row_timestamp) / 3600.0
    if age_hours < delay_hours:
        return False
    return all(mtime > row_timestamp for mtime in model_mtimes)


def decide_label(rf_proba, second_proba, confidence_threshold):
    """Returns the agreed class (0, 1, or 2) if both models pick the same
    top class and both clear confidence_threshold on it, else None.
    Agreement is what makes this a real signal rather than a rubber
    stamp: two differently built models making the same mistake on a
    genuinely novel row is far less likely than one model rehashing its
    own opinion."""
    rf_top = int(np.argmax(rf_proba))
    second_top = int(np.argmax(second_proba))
    if rf_top != second_top:
        return None
    if rf_proba[rf_top] < confidence_threshold or second_proba[second_top] < confidence_threshold:
        return None
    return rf_top


def trim_csv_rows(rows, max_rows):
    """Keeps the newest max_rows rows by their timestamp column, dropping
    the oldest first. rows is a list of plain string lists as returned by
    csv.reader, header not included. Returns (kept_rows, dropped_count).
    Without this cap, a fresh deployment left running with no model, or a
    long configured delay under heavy traffic, would grow an unbounded
    file."""
    if len(rows) <= max_rows:
        return rows, 0
    sorted_rows = sorted(rows, key=lambda r: float(r[TIMESTAMP_COL]))
    dropped = len(sorted_rows) - max_rows
    return sorted_rows[dropped:], dropped


def _read_rows(path):
    """Returns (header, rows) for a capture CSV, or (None, []) if the file
    does not exist yet, which is the normal state for a fresh deployment
    that has not captured anything of this kind."""
    if not os.path.exists(path):
        return None, []
    with open(path, newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)
    if not rows:
        return None, []
    return rows[0], rows[1:]


def _rewrite_csv(path, header, rows):
    """Atomic replace: write to a temp file in the same directory, then
    rename over the target, so a reader never sees a partially rewritten
    file and a crash mid-write leaves the previous complete file in place."""
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    os.replace(tmp, path)


def _row_to_features(row, header):
    """Builds the derived-feature row (matching FEATURE_COLS' order) a
    model's predict_proba expects, from one BASE_CSV_HEADER row."""
    by_name = dict(zip(header, row))
    entropy, ewma_rate = float(by_name["entropy"]), float(by_name["ewma_rate"])
    mean_h, mean_r = float(by_name["mean_h"]), float(by_name["mean_r"])
    sigma_h, sigma_r = float(by_name["sigma_h"]), float(by_name["sigma_r"])
    proto_ratio = float(by_name["proto_ratio"])
    dominant_ip_ratio = float(by_name["dominant_ip_ratio"])
    return {
        "entropy": entropy, "ewma_rate": ewma_rate, "mean_h": mean_h, "mean_r": mean_r,
        "sigma_h": sigma_h, "sigma_r": sigma_r, "proto_ratio": proto_ratio,
        "dominant_ip_ratio": dominant_ip_ratio,
        "delta_rate": ewma_rate - mean_r, "delta_entropy": entropy - mean_h,
        "dominant_rate": ewma_rate * dominant_ip_ratio,
        "source_port_entropy": float(by_name["source_port_entropy"]),
        "ttl_variance": float(by_name["ttl_variance"]),
        "fingerprint_diversity": float(by_name["fingerprint_diversity"]),
    }


def _process_capture_file(path, clf, second_clf, model_mtimes, labeled_out):
    """Trims path to config.AUTO_LABEL_MAX_QUEUE_ROWS, then scores every
    remaining row: eligible and confidently agreed rows are appended to
    labeled_out and removed here; everything else stays for the next run
    or for a human, exactly as it does today. Returns the number of rows
    auto-labeled."""
    header, rows = _read_rows(path)
    if header is None:
        logging.info(f"[+] {path} does not exist or is empty, nothing to process.")
        return 0

    rows, dropped = trim_csv_rows(rows, config.AUTO_LABEL_MAX_QUEUE_ROWS)
    if dropped:
        logging.warning(f"[!] {path} exceeded {config.AUTO_LABEL_MAX_QUEUE_ROWS} rows, "
                         f"dropped {dropped} oldest.")

    kept_rows = []
    labeled_count = 0
    for row in rows:
        row_timestamp = float(row[TIMESTAMP_COL])
        if not is_row_eligible(row_timestamp, model_mtimes, config.AUTO_LABEL_DELAY_HOURS):
            kept_rows.append(row)
            continue

        features = _row_to_features(row, BASE_CSV_HEADER)
        features_df = pd.DataFrame([[features[c] for c in FEATURE_COLS]], columns=FEATURE_COLS)
        rf_proba = clf.predict_proba(features_df)[0]
        second_proba = second_clf.predict_proba(features_df)[0]
        label = decide_label(rf_proba, second_proba, config.AUTO_LABEL_CONFIDENCE_THRESHOLD)

        if label is None:
            kept_rows.append(row)
            continue

        labeled_row = list(row)
        labeled_row[BASE_CSV_HEADER.index("label")] = str(label)
        _append_labeled_row(labeled_out, labeled_row)
        labeled_count += 1

    _rewrite_csv(path, header, kept_rows)
    return labeled_count


def _append_labeled_row(path, row):
    write_header = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(BASE_CSV_HEADER)
        w.writerow(row)


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if not os.path.exists(config.MODEL_PATH) or not os.path.exists(config.SECOND_MODEL_PATH):
        logging.info("[+] RandomForest and/or second model not present yet, "
                      "agreement cannot be checked with only one model. Nothing to do.")
        return

    clf = joblib.load(config.MODEL_PATH)
    clf.n_jobs = 1
    second_clf = joblib.load(config.SECOND_MODEL_PATH)
    model_mtimes = [os.path.getmtime(config.MODEL_PATH), os.path.getmtime(config.SECOND_MODEL_PATH)]

    total_labeled = 0
    for path in (config.PRETRAINING_CSV_PATH, config.ANOMALOUS_CSV_PATH):
        total_labeled += _process_capture_file(path, clf, second_clf, model_mtimes, config.AUTO_LABELED_CSV_PATH)

    logging.info(f"[+] Auto-labeled {total_labeled} row(s) into {config.AUTO_LABELED_CSV_PATH}.")


if __name__ == "__main__":
    main()
