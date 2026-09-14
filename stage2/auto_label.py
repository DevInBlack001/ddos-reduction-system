#!/usr/bin/env python3
"""
auto_label.py: Stage 2, V8's confidence gated automatic labeling.

Re-scores rows in config.PRETRAINING_CSV_PATH and config.ANOMALOUS_CSV_PATH
against the RandomForest and a second, independently trained model, staging
a row into config.AUTO_LABELED_CSV_PATH when both agree and both are
confident. Both models must also have been trained after the row was
captured, so a stale, unretrained model can never auto-label its own blind
spot. See docs/specs/2026-09-13-confidence-gated-labeling-design.md.
"""

import os
# Constrain the second model's threading before importing anything that pulls
# in OpenMP (joblib, numpy, pandas). Environment variables read at import time
# by those libraries don't take effect if set later.
os.environ.setdefault("OMP_NUM_THREADS", "1")

import csv
import time
import logging
import fcntl
from collections import deque

import joblib
import numpy as np
import pandas as pd

import config
from storage import _atomic_write

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


def decide_label(rf_proba, rf_classes, second_proba, second_classes, confidence_threshold):
    """Returns the agreed class (0, 1, or 2) if both models pick the same
    top class and both clear confidence_threshold on it, else None.
    Agreement is what makes this a real signal rather than a rubber
    stamp: two differently built models making the same mistake on a
    genuinely novel row is far less likely than one model rehashing its
    own opinion.

    rf_proba/second_proba are indexed by each model's own classes_ array,
    not by class label directly: a training CSV missing a label entirely
    (balance_classes skips empty classes) yields a classes_ like [0, 2],
    where proba index 1 means class 2, not class 1. rf_classes/second_classes
    must match exactly, order included, or index agreement would not imply
    class agreement, so a mismatch refuses the row rather than guessing."""
    if list(rf_classes) != list(second_classes):
        return None
    rf_top_idx = int(np.argmax(rf_proba))
    second_top_idx = int(np.argmax(second_proba))
    if rf_top_idx != second_top_idx:
        return None
    if rf_proba[rf_top_idx] < confidence_threshold or second_proba[second_top_idx] < confidence_threshold:
        return None
    return int(rf_classes[rf_top_idx])


def _sort_key(row):
    """Safe sort key for trim_csv_rows: returns the timestamp as a float,
    or float("-inf") for a malformed row (non-numeric timestamp or missing
    column). Malformed rows sort oldest, get dropped first if the file is
    over the cap."""
    try:
        return float(row[TIMESTAMP_COL])
    except (ValueError, IndexError):
        return float("-inf")


def trim_csv_rows(rows, max_rows):
    """Keeps the newest max_rows rows by their timestamp column, dropping
    the oldest first. rows is a list of plain string lists as returned by
    csv.reader, header not included. Returns (kept_rows, dropped_count).
    Without this cap, a fresh deployment left running with no model, or a
    long configured delay under heavy traffic, would grow an unbounded
    file. Malformed rows (non-numeric or missing timestamp) sort oldest and
    are dropped first, without raising an exception."""
    if len(rows) <= max_rows:
        return rows, 0
    sorted_rows = sorted(rows, key=_sort_key)
    dropped = len(sorted_rows) - max_rows
    return sorted_rows[dropped:], dropped


def _read_rows(path):
    """Returns (header, rows, was_bounded) for a capture CSV, or (None, [], False)
    if the file does not exist. Bounds memory during the read by keeping only the
    newest config.AUTO_LABEL_MAX_QUEUE_ROWS data rows via a deque, so peak memory
    is capped by the row limit even if the file is larger than that. Header is
    read first with next() to prevent it from being evicted. Returns was_bounded=True
    if the deque had to drop rows (file was over cap), False otherwise."""
    if not os.path.exists(path):
        return None, [], False
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header is None:
            return None, [], False
        # Track how many rows we see to know if the deque bounded them
        rows_deque = deque(reader, maxlen=config.AUTO_LABEL_MAX_QUEUE_ROWS)
        rows = list(rows_deque)
    # The deque dropped rows (file was over cap) if it's at max capacity and
    # hit that capacity (would need another iteration to fill it, which wouldn't
    # happen if file had fewer rows). Simple heuristic: if rows == maxlen, the
    # deque probably filled and started dropping. More precisely, we'd need to
    # know the actual file line count, but that requires a separate pass.
    was_bounded = len(rows) == config.AUTO_LABEL_MAX_QUEUE_ROWS
    return header, rows, was_bounded


def _rewrite_csv(path, header, rows):
    """Atomic replace via storage._atomic_write, so a reader never sees a
    partially rewritten file, a crash mid-write leaves the previous complete
    file in place, and a symlink planted at the temp path is refused rather
    than followed."""
    def write_fn(f):
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    _atomic_write(path, write_fn)


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
    auto-labeled. Holds an exclusive lock on <path>.lock for the entire
    read-score-rewrite sequence to prevent ipc_receiver.py's appends from
    landing on the old inode and being silently lost."""
    lockfile_path = f"{path}.lock"
    lock_fd = os.open(lockfile_path, os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            header, rows, was_bounded = _read_rows(path)
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
                # A single malformed row (bad timestamp, missing column) must not
                # abort the rest of the file: log it, leave it exactly where it is
                # for a human, and keep scoring everything else.
                try:
                    row_timestamp = float(row[TIMESTAMP_COL])
                    if not is_row_eligible(row_timestamp, model_mtimes, config.AUTO_LABEL_DELAY_HOURS):
                        kept_rows.append(row)
                        continue

                    features = _row_to_features(row, header)
                    features_df = pd.DataFrame([[features[c] for c in FEATURE_COLS]], columns=FEATURE_COLS)
                    rf_proba = clf.predict_proba(features_df)[0]
                    second_proba = second_clf.predict_proba(features_df)[0]
                    label = decide_label(
                        rf_proba, clf.classes_, second_proba, second_clf.classes_,
                        config.AUTO_LABEL_CONFIDENCE_THRESHOLD,
                    )
                except (ValueError, IndexError, KeyError) as e:
                    logging.warning(f"[!] Skipping malformed row in {path}: {row!r} ({e})")
                    kept_rows.append(row)
                    continue

                if label is None:
                    kept_rows.append(row)
                    continue

                # row may carry anomalous_capture.csv's extra 3 context columns;
                # the staging file is always the 13-column BASE_CSV_HEADER.
                labeled_row = list(row[:len(BASE_CSV_HEADER)])
                labeled_row[BASE_CSV_HEADER.index("label")] = str(label)
                _append_labeled_row(labeled_out, labeled_row)
                labeled_count += 1

            if dropped or labeled_count:
                _rewrite_csv(path, header, kept_rows)
            return labeled_count
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def _append_labeled_row(path, row):
    write_header = not os.path.exists(path)
    try:
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(BASE_CSV_HEADER)
            w.writerow(row)
    except OSError as e:
        logging.error(f"[-] Failed to write {path}: {e}")


def _trim_capture_file_only(path):
    """Trim one capture file to config.AUTO_LABEL_MAX_QUEUE_ROWS without
    scoring, used when no models are present yet. Returns the number of
    rows dropped by trim_csv_rows (not including rows dropped by the deque
    during read if the file was already over cap)."""
    header, rows, was_bounded = _read_rows(path)
    if header is None:
        logging.info(f"[+] {path} does not exist or is empty, nothing to process.")
        return 0

    rows, dropped = trim_csv_rows(rows, config.AUTO_LABEL_MAX_QUEUE_ROWS)
    # Rewrite if trim_csv_rows dropped rows, OR if the deque bounded the rows
    # (meaning the original file had more rows than what we read back)
    if dropped or was_bounded:
        if dropped:
            logging.warning(f"[!] {path} exceeded {config.AUTO_LABEL_MAX_QUEUE_ROWS} rows, "
                             f"dropped {dropped} oldest.")
        _rewrite_csv(path, header, rows)
    return dropped


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Load models, both optional for scoring but trimming always runs.
    clf = None
    second_clf = None
    model_mtimes = []
    if os.path.exists(config.MODEL_PATH) and os.path.exists(config.SECOND_MODEL_PATH):
        try:
            clf = joblib.load(config.MODEL_PATH)
            clf.n_jobs = 1
            second_clf = joblib.load(config.SECOND_MODEL_PATH)
            model_mtimes = [os.path.getmtime(config.MODEL_PATH), os.path.getmtime(config.SECOND_MODEL_PATH)]
        except Exception as e:
            logging.error(f"[-] Failed to load models: {e}. Trimming only.")
            clf = None
            second_clf = None

    total_labeled = 0
    for path in (config.PRETRAINING_CSV_PATH, config.ANOMALOUS_CSV_PATH):
        try:
            if clf is not None and second_clf is not None:
                # Both models present: score and label.
                total_labeled += _process_capture_file(path, clf, second_clf, model_mtimes, config.AUTO_LABELED_CSV_PATH)
            else:
                # No models yet: trim only.
                _trim_capture_file_only(path)
        except Exception as e:
            logging.error(f"[-] Error processing {path}: {e}. Continuing to next file.")

    logging.info(f"[+] Auto-labeled {total_labeled} row(s) into {config.AUTO_LABELED_CSV_PATH}.")


if __name__ == "__main__":
    main()
