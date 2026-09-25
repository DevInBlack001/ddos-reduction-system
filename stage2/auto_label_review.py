"""
auto_label_review.py: the dashboard's review queue for auto_label.py's
staged output.

Nothing here writes into the real training CSV on its own; every run of
auto_label.py only stages rows into config.AUTO_LABELED_CSV_PATH, same as
before this file existed. This adds the last step, an operator reviewing
and either merging that staged file into config.TRAINING_CSV_PATH or
discarding it, from the dashboard instead of the terminal.
"""

import csv
import logging
import os
import time

from fastapi import APIRouter, HTTPException

import config
import db
from auto_label import BASE_CSV_HEADER, _read_rows, _rewrite_csv
from storage import _atomic_write
from training_balance import trim_ddos_sessions

router = APIRouter()

# Bounds how many staged rows the review page loads into memory and
# renders at once. The queue itself is already bounded by
# config.AUTO_LABEL_MAX_QUEUE_ROWS; this is a second, independent cap on
# what one review request returns, so a very large queue still gives a
# fast, boundable response.
REVIEW_ROW_LIMIT = 500


@router.get("/api/auto-label/runs")
def list_pending_runs():
    """Unresolved auto_label.py runs, newest first, for the dashboard's
    alert list. All resolve together on the next merge or discard, since
    they all point at the same shared staging file."""
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT id, timestamp, rows_labeled FROM auto_label_runs"
            " WHERE resolved = 0 ORDER BY timestamp DESC"
        ).fetchall()
    finally:
        conn.close()
    return {
        "runs": [{"id": r[0], "timestamp": r[1], "rows_labeled": r[2]} for r in rows],
        "training_csv_configured": bool(config.TRAINING_CSV_PATH),
    }


@router.get("/api/auto-label/review")
def review_staged_rows(offset: int = 0, limit: int = REVIEW_ROW_LIMIT):
    """One page of the staged file, at most REVIEW_ROW_LIMIT rows. Every
    unresolved run in auto_label_runs points at this same file, so there
    is nothing to distinguish per-run; reviewing any one alert means
    reviewing all of it."""
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must not be negative.")
    limit = max(1, min(limit, REVIEW_ROW_LIMIT))

    header, rows, _ = _read_rows(config.AUTO_LABELED_CSV_PATH)
    if header is None:
        return {
            "header": BASE_CSV_HEADER, "rows": [], "total_rows": 0, "offset": 0,
            "limit": limit, "has_prev": False, "has_next": False, "truncated": False,
        }

    total = len(rows)
    page = rows[offset:offset + limit]
    return {
        "header": header,
        "rows": page,
        "total_rows": total,
        "offset": offset,
        "limit": limit,
        "has_prev": offset > 0,
        "has_next": offset + len(page) < total,
        "truncated": total > len(page),
    }


@router.post("/api/auto-label/merge")
def merge_staged_rows():
    """Append every staged row into config.TRAINING_CSV_PATH, then clear
    the staged file and resolve every pending run. All or nothing: if the
    append fails, the staged file is left untouched rather than partially
    cleared."""
    if not config.TRAINING_CSV_PATH:
        raise HTTPException(
            status_code=400,
            detail="TRAINING_CSV_PATH is not configured. Set it (the same "
                   "--training-csv value install.sh/update.sh take for the "
                   "retrain timer) before merging from the dashboard.",
        )

    header, staged_rows, _ = _read_rows(config.AUTO_LABELED_CSV_PATH)
    if header is None or not staged_rows:
        raise HTTPException(status_code=400, detail="Nothing staged to merge.")

    target_header, target_rows, _ = _read_rows(config.TRAINING_CSV_PATH)
    if target_header is None:
        target_header = BASE_CSV_HEADER
        target_rows = []

    merged_count = len(staged_rows)
    _atomic_write(
        config.TRAINING_CSV_PATH,
        lambda f: _write_csv(f, target_header, target_rows + staged_rows),
    )
    _rewrite_csv(config.AUTO_LABELED_CSV_PATH, BASE_CSV_HEADER, [])
    _resolve_all_runs()

    logging.warning(
        f"[+] Dashboard merge: {merged_count} row(s) appended into "
        f"{config.TRAINING_CSV_PATH} from {config.AUTO_LABELED_CSV_PATH}."
    )
    return {"merged": merged_count}


@router.post("/api/auto-label/discard")
def discard_staged_rows():
    """Clear the staged file without merging, and resolve every pending
    run. The rows are not backed up anywhere by this endpoint; discard
    means discard."""
    header, staged_rows, _ = _read_rows(config.AUTO_LABELED_CSV_PATH)
    if header is None or not staged_rows:
        raise HTTPException(status_code=400, detail="Nothing staged to discard.")

    discarded_count = len(staged_rows)
    _rewrite_csv(config.AUTO_LABELED_CSV_PATH, BASE_CSV_HEADER, [])
    _resolve_all_runs()

    logging.warning(
        f"[+] Dashboard discard: {discarded_count} staged row(s) cleared "
        f"from {config.AUTO_LABELED_CSV_PATH} without merging."
    )
    return {"discarded": discarded_count}


@router.post("/api/auto-label/trim-ddos")
def trim_ddos_class():
    """Caps config.TRAINING_CSV_PATH's DDoS (label 2) row count at the
    smaller of its Normal and Flash Crowd row counts, dropping whole
    DDoS sessions (never individual rows out of one, see
    training_balance.py). A deliberate, operator-clicked action, the
    same as Merge itself, never run automatically as part of a merge:
    this project's own convention is that training data changes are
    deliberate steps, not a hidden side effect."""
    if not config.TRAINING_CSV_PATH:
        raise HTTPException(
            status_code=400,
            detail="TRAINING_CSV_PATH is not configured. Set it (the same "
                   "--training-csv value install.sh/update.sh take for the "
                   "retrain timer) before trimming from the dashboard.",
        )

    header, rows, _ = _read_rows(config.TRAINING_CSV_PATH)
    if header is None or not rows:
        raise HTTPException(status_code=400, detail="Training CSV is empty or missing, nothing to trim.")

    trimmed, dropped, cap = trim_ddos_sessions(rows)
    if dropped == 0:
        return {"dropped": 0, "cap": cap, "message": "DDoS is already at or under the cap, nothing trimmed."}

    _rewrite_csv(config.TRAINING_CSV_PATH, header, trimmed)
    logging.warning(
        f"[+] Dashboard trim: {dropped} DDoS row(s) dropped as whole sessions from "
        f"{config.TRAINING_CSV_PATH}, capped at {cap} (the smaller of Normal/Flash Crowd)."
    )
    return {"dropped": dropped, "cap": cap, "remaining_rows": len(trimmed)}


def _write_csv(f, header, rows):
    w = csv.writer(f)
    w.writerow(header)
    w.writerows(rows)


def _resolve_all_runs():
    conn = db.connect()
    try:
        conn.execute("UPDATE auto_label_runs SET resolved = 1 WHERE resolved = 0")
        conn.commit()
    finally:
        conn.close()
