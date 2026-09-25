"""
training_balance.py: caps the DDoS (label 2) row count in the training CSV
at the smaller of the Normal (label 0) and Flash Crowd (label 1) row
counts.

Same reasoning and the same session-aware trimming as
scripts/trim_ddos_class.py (kept as a separate, stdlib-only
implementation there deliberately, matching this project's own
scripts/ vs stage2/ boundary: scripts/ tools run standalone on a host
that may not have Stage 2's venv, stage2/ modules run inside it). This
module exists specifically so the dashboard's Auto Label page can
offer the same trim as a deliberate button click, not just a terminal
command, without duplicating call sites for csv reading that already
exist in auto_label.py.

The confidence gated auto-label pipeline (docs/training.md#confidence-gated-automatic-labeling)
captures DDoS unconditionally into ddos_capture.csv, but only captures
Normal/Flash Crowd candidates when the Isolation Forest also flags
them anomalous, a narrow, comparatively rare condition. A merge from
that queue is DDoS-heavy by construction, and left unchecked across
enough merges the training set's own class balance drifts further
DDoS-heavy each time.

Whole DDoS *sessions* are dropped, never individual rows picked out of
a session. train.py derives a session from timestamp gaps over 30
seconds or a label change; deleting scattered rows from the middle of
one real capture run opens a fake >30s gap where none existed,
fragmenting one session into two and corrupting the row count LOSO
depends on. Session detection here mirrors train.py's own exactly, on
the same 13 column, index based rows _read_rows() already returns
elsewhere in this file's callers.
"""

import random

from auto_label import BASE_CSV_HEADER, TIMESTAMP_COL

LABEL_COL = BASE_CSV_HEADER.index("label")
NORMAL, FLASH_CROWD, DDOS = "0", "1", "2"
SESSION_GAP_SECONDS = 30.0


def _assign_sessions(rows):
    """Returns a new list of (row, session_id) pairs, rows sorted by
    timestamp, mirroring train.py's own session detection exactly."""
    rows = sorted(rows, key=lambda r: float(r[TIMESTAMP_COL]))
    session_id = 0
    prev_ts = None
    prev_label = None
    tagged = []
    for row in rows:
        ts = float(row[TIMESTAMP_COL])
        label = row[LABEL_COL]
        is_new = prev_ts is None or (ts - prev_ts) > SESSION_GAP_SECONDS or label != prev_label
        if is_new:
            session_id += 1
        tagged.append((row, session_id))
        prev_ts = ts
        prev_label = label
    return tagged


def trim_ddos_sessions(rows, seed=42):
    """rows: a list of BASE_CSV_HEADER-shaped rows (lists), the same
    shape _read_rows() returns. Returns (kept_rows, dropped_count, cap).
    cap is the smaller of the Normal and Flash Crowd row counts; DDoS
    sessions are shuffled with `seed` and dropped whole, one at a time,
    until the retained DDoS row count is at or under cap (never dropped
    biggest-first, so trimming doesn't systematically strip only large
    DDoS sessions and leave a skewed mix of small ones behind)."""
    counts = {NORMAL: 0, FLASH_CROWD: 0, DDOS: 0}
    for row in rows:
        counts[row[LABEL_COL]] = counts.get(row[LABEL_COL], 0) + 1
    cap = min(counts.get(NORMAL, 0), counts.get(FLASH_CROWD, 0))

    if counts.get(DDOS, 0) <= cap:
        return rows, 0, cap

    tagged = _assign_sessions(rows)
    ddos_sessions = {}
    for row, sid in tagged:
        if row[LABEL_COL] == DDOS:
            ddos_sessions.setdefault(sid, []).append(row)

    session_ids = list(ddos_sessions.keys())
    random.Random(seed).shuffle(session_ids)

    kept_ddos_session_ids = set()
    kept_ddos_row_count = 0
    for sid in session_ids:
        session_size = len(ddos_sessions[sid])
        if kept_ddos_row_count + session_size <= cap:
            kept_ddos_session_ids.add(sid)
            kept_ddos_row_count += session_size

    dropped = counts[DDOS] - kept_ddos_row_count
    result = [
        row for row, sid in tagged
        if row[LABEL_COL] != DDOS or sid in kept_ddos_session_ids
    ]
    return result, dropped, cap
