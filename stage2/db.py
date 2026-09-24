"""
db.py: SQLite audit-log writers (the `logs` and `metrics_history` tables).

Deliberately does not depend on enforcement.py: every caller resolves
victim_ip before calling in here, so this module only needs config, avoiding
a cycle (enforcement.py depends on this module for log_incident).

Writes go through one shared connection guarded by a lock, so a slow writer
blocks other writers rather than each opening its own connection and queuing
behind the busy timeout.
"""

import sqlite3
import logging
import threading
import time

import config


# Keep the newest N rows of metrics_history, and check no more often than
# the interval. The purge used to run on every window, which held a write
# lock for long enough to starve incident writes.
METRICS_RETENTION_ROWS = 1000
PURGE_INTERVAL_SECONDS = 60.0

_lock = threading.Lock()
_conn = None
_conn_path = None
_last_purge = None


def _open():
    """The shared write connection, reopened if the configured path changed.

    WAL lets the dashboard read while a window is being written; under the
    default journal those two block each other.
    """
    global _conn, _conn_path

    if _conn is not None and _conn_path == config.DB_PATH:
        return _conn

    _close()
    conn = sqlite3.connect(config.DB_PATH, timeout=30.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    _conn, _conn_path = conn, config.DB_PATH
    return conn


def _close():
    """Drop the cached connection. Called on error so a broken handle is not
    reused, and by close() at shutdown."""
    global _conn, _conn_path

    if _conn is not None:
        try:
            _conn.close()
        except Exception:
            pass
    _conn, _conn_path = None, None


def close():
    with _lock:
        _close()


def connect() -> sqlite3.Connection:
    """A connection for callers that only read.

    Not the shared writer connection or its lock: WAL already lets reads run
    alongside a write. Matches its busy timeout, though, so a read does not
    surface as a 5 second default-timeout failure while the periodic purge
    holds the write lock.
    """
    return sqlite3.connect(config.DB_PATH, timeout=30.0)


def log_incident(timestamp, src_ip, classification, victim_ip="Unknown", src_rate=None,
                 entropy=None):
    """Record one enforcement action.

    `src_rate` is that source's own packet rate, not the victim's aggregate
    rate for the window: sources actioned in the same window would otherwise
    all be logged with the flood's entire volume.

    `entropy` stays a window-level value on purpose: it describes the source
    distribution the decision was made against, not anything per-source. It
    must come from the window that drove this action. It used to be read from
    the most recent window across every protected host, which stamped an
    action for one host with another host's measurement.

    None means the value is genuinely unknown, e.g. an operator blocking an
    address by hand, and is stored as NULL. Zero is not a substitute for
    either column: a zero rate reads as a source that sent nothing, and zero
    entropy reads as maximally concentrated traffic, which is the signature
    of the single-source flood that is least likely to be unmeasured.
    """
    with _lock:
        try:
            conn = _open()
            conn.execute(
                "INSERT INTO logs (timestamp, src_ip, dst_ip, proto, rate, entropy, classification) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (timestamp, src_ip, victim_ip, "MIXED", src_rate, entropy, classification)
            )
            conn.commit()
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to write incident to SQLite: {e}")


def record_auto_label_run(timestamp, rows_labeled):
    """Record one auto_label.py run that staged rows, for the dashboard's
    review alert. Called from auto_label.py, a separate one-shot process
    from the running service, so it uses its own short-lived connection
    (connect() above) rather than the service's shared writer lock, and
    applies the schema defensively in case this ever runs before the
    service has started once."""
    import schema
    conn = connect()
    try:
        schema.apply(conn)
        conn.execute(
            "INSERT INTO auto_label_runs (timestamp, rows_labeled) VALUES (?, ?)",
            (timestamp, rows_labeled)
        )
        conn.commit()
    except Exception as e:
        logging.error(f"[-] Failed to record auto-label run: {e}")
    finally:
        conn.close()


def log_metrics_history(timestamp, rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k, victim_ip):
    with _lock:
        try:
            conn = _open()
            conn.execute(
                "INSERT INTO metrics_history (timestamp, ewma_rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k_multiplier, victim_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (timestamp, rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k, victim_ip)
            )
            _purge_metrics_history(conn)
            conn.commit()
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to save metrics history: {e}")


def _purge_metrics_history(conn, force=False):
    """Trim metrics_history to the newest rows, at most once per interval.

    Deletes by id range so the rowid index does the work. The previous
    `id NOT IN (SELECT ... ORDER BY id DESC LIMIT 1000)` rescanned the whole
    table on every window.
    """
    global _last_purge

    now = time.monotonic()
    if not force and _last_purge is not None and now - _last_purge < PURGE_INTERVAL_SECONDS:
        return
    _last_purge = now

    conn.execute(
        "DELETE FROM metrics_history WHERE id <= (SELECT MAX(id) FROM metrics_history) - ?",
        (METRICS_RETENTION_ROWS,)
    )


def purge_metrics_history():
    """Trim metrics_history now, ignoring the interval."""
    with _lock:
        try:
            conn = _open()
            _purge_metrics_history(conn, force=True)
            conn.commit()
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to purge metrics history: {e}")


# V10: playbooks. Reads use their own short-lived connect() (dashboard
# routes), writes go through the shared writer lock like everything above,
# since the live service's window-processing loop is the other writer.


def get_enabled_playbooks_for_host(victim_ip):
    """Playbooks whose target_scope matches this host: an exact host match,
    or scope_type 'all'. 'subnet' scope is stored but not matched here yet,
    left for the dashboard's editing surface to validate; evaluating a CIDR
    membership check against every window is deferred until a playbook
    actually uses that scope type."""
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT id, definition FROM playbooks WHERE enabled = 1 AND "
            "(target_scope_type = 'all' OR "
            " (target_scope_type = 'host' AND target_scope_value = ?))",
            (victim_ip,)
        ).fetchall()
        return [(row[0], row[1]) for row in rows]
    finally:
        conn.close()


def get_active_playbook_run(playbook_id, target_host):
    """The `running` row for this (playbook, host) pair, or None. Checked
    before starting a new run so a still-firing trigger doesn't spawn
    duplicate runs."""
    conn = connect()
    try:
        row = conn.execute(
            "SELECT id, current_stage_index, target_source, started_at FROM playbook_runs "
            "WHERE playbook_id = ? AND target_host = ? AND status = 'running'",
            (playbook_id, target_host)
        ).fetchone()
        return row
    finally:
        conn.close()


def start_playbook_run(playbook_id, target_host, target_source, trigger_reason, now):
    with _lock:
        try:
            conn = _open()
            cur = conn.execute(
                "INSERT INTO playbook_runs "
                "(playbook_id, target_host, target_source, current_stage_index, status, "
                " trigger_reason, started_at, updated_at) "
                "VALUES (?, ?, ?, 0, 'running', ?, ?, ?)",
                (playbook_id, target_host, target_source, trigger_reason, now, now)
            )
            conn.commit()
            return cur.lastrowid
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to start playbook run: {e}")
            return None


def get_running_playbook_runs():
    """Every `running` row, for the once-per-window stage advancement pass
    across all active runs, regardless of which host's window is currently
    being processed."""
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT id, playbook_id, target_host, target_source, current_stage_index, "
            "started_at, updated_at FROM playbook_runs WHERE status = 'running'"
        ).fetchall()
        return rows
    finally:
        conn.close()


def get_playbook_definition(playbook_id):
    conn = connect()
    try:
        row = conn.execute("SELECT definition FROM playbooks WHERE id = ?", (playbook_id,)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def record_playbook_event(run_id, stage_index, stage_type, target_source, detail, now):
    with _lock:
        try:
            conn = _open()
            conn.execute(
                "INSERT INTO playbook_events (run_id, stage_index, stage_type, fired_at, "
                "target_source, detail) VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, stage_index, stage_type, now, target_source, detail)
            )
            conn.commit()
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to record playbook event: {e}")


def advance_playbook_run(run_id, next_stage_index, now):
    """Advance to the next stage, or mark the run completed when
    `next_stage_index` is None (the stage list is exhausted)."""
    with _lock:
        try:
            conn = _open()
            if next_stage_index is None:
                conn.execute(
                    "UPDATE playbook_runs SET status = 'completed', updated_at = ? WHERE id = ?",
                    (now, run_id)
                )
            else:
                conn.execute(
                    "UPDATE playbook_runs SET current_stage_index = ?, updated_at = ? WHERE id = ?",
                    (next_stage_index, now, run_id)
                )
            conn.commit()
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to advance playbook run: {e}")


# V10: the two editing surfaces (form builder, JSON/YAML text editor) both
# go through these. Writes take the shared lock like every other write in
# this file; reads use the dashboard's short-lived connect(), same split
# as the trigger-evaluation functions above.


def get_all_playbooks():
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT id, name, target_scope_type, target_scope_value, enabled, "
            "definition, created_at, updated_at FROM playbooks ORDER BY id"
        ).fetchall()
        return rows
    finally:
        conn.close()


def get_playbook(playbook_id):
    conn = connect()
    try:
        return conn.execute(
            "SELECT id, name, target_scope_type, target_scope_value, enabled, "
            "definition, created_at, updated_at FROM playbooks WHERE id = ?",
            (playbook_id,)
        ).fetchone()
    finally:
        conn.close()


def create_playbook(name, target_scope_type, target_scope_value, enabled, definition_json, now):
    with _lock:
        try:
            conn = _open()
            cur = conn.execute(
                "INSERT INTO playbooks (name, target_scope_type, target_scope_value, "
                "enabled, definition, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, target_scope_type, target_scope_value, int(enabled), definition_json, now, now)
            )
            conn.commit()
            return cur.lastrowid
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to create playbook: {e}")
            return None


def update_playbook(playbook_id, name, target_scope_type, target_scope_value, enabled, definition_json, now):
    with _lock:
        try:
            conn = _open()
            cur = conn.execute(
                "UPDATE playbooks SET name = ?, target_scope_type = ?, target_scope_value = ?, "
                "enabled = ?, definition = ?, updated_at = ? WHERE id = ?",
                (name, target_scope_type, target_scope_value, int(enabled), definition_json, now, playbook_id)
            )
            conn.commit()
            return cur.rowcount > 0
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to update playbook {playbook_id}: {e}")
            return False


def set_playbook_enabled(playbook_id, enabled, now):
    with _lock:
        try:
            conn = _open()
            cur = conn.execute(
                "UPDATE playbooks SET enabled = ?, updated_at = ? WHERE id = ?",
                (int(enabled), now, playbook_id)
            )
            conn.commit()
            return cur.rowcount > 0
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to toggle playbook {playbook_id}: {e}")
            return False


def delete_playbook(playbook_id):
    """Deletes the playbook definition itself, plus its own run and event
    history: once the definition is gone there is nothing left for those
    rows to describe, and keeping them around would let a future playbook
    reusing the same id inherit another playbook's history."""
    with _lock:
        try:
            conn = _open()
            run_ids = [r[0] for r in conn.execute(
                "SELECT id FROM playbook_runs WHERE playbook_id = ?", (playbook_id,)
            ).fetchall()]
            if run_ids:
                placeholders = ",".join("?" * len(run_ids))
                conn.execute(f"DELETE FROM playbook_events WHERE run_id IN ({placeholders})", run_ids)
            conn.execute("DELETE FROM playbook_runs WHERE playbook_id = ?", (playbook_id,))
            cur = conn.execute("DELETE FROM playbooks WHERE id = ?", (playbook_id,))
            conn.commit()
            return cur.rowcount > 0
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to delete playbook {playbook_id}: {e}")
            return False


def get_recent_playbook_runs(limit=50):
    """Every run, newest first, regardless of status, for the dashboard's
    run history view. Bounded so a long-lived deployment's full history
    doesn't all load into one response."""
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT r.id, r.playbook_id, p.name, r.target_host, r.target_source, "
            "r.current_stage_index, r.status, r.trigger_reason, r.started_at, r.updated_at "
            "FROM playbook_runs r JOIN playbooks p ON p.id = r.playbook_id "
            "ORDER BY r.started_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return rows
    finally:
        conn.close()


def get_playbook_events(run_id):
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT stage_index, stage_type, fired_at, target_source, detail "
            "FROM playbook_events WHERE run_id = ? ORDER BY stage_index",
            (run_id,)
        ).fetchall()
        return rows
    finally:
        conn.close()


def get_playbook_events_between(start_ts, end_ts):
    """Every playbook_events row in [start_ts, end_ts], joined back to its
    run and playbook, for the incident report's timeline section."""
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT e.fired_at, e.stage_type, e.target_source, e.detail, "
            "r.target_host, p.name "
            "FROM playbook_events e "
            "JOIN playbook_runs r ON r.id = e.run_id "
            "JOIN playbooks p ON p.id = r.playbook_id "
            "WHERE e.fired_at >= ? AND e.fired_at <= ? "
            "ORDER BY e.fired_at",
            (start_ts, end_ts)
        ).fetchall()
        return rows
    finally:
        conn.close()
