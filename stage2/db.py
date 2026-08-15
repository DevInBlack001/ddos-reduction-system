"""
db.py: SQLite audit-log writers (the `logs` and `metrics_history` tables).

Deliberately does not depend on enforcement.py: every caller resolves
victim_ip before calling in here, so this module only needs config + state,
avoiding a cycle (enforcement.py depends on this module for log_incident).

Writes go through one shared connection guarded by a lock, so a slow writer
blocks other writers rather than each opening its own connection and queuing
behind the busy timeout.
"""

import sqlite3
import logging
import threading
import time

import config
import state


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


def log_incident(timestamp, src_ip, classification, victim_ip="Unknown", src_rate=None):
    """Record one enforcement action.

    `src_rate` is that source's own packet rate, not the victim's aggregate
    rate for the window: sources actioned in the same window would otherwise
    all be logged with the flood's entire volume.

    Entropy stays a window-level value on purpose: it describes the source
    distribution the decision was made against, not anything per-source.

    None means the rate is genuinely unknown, e.g. an operator blocking an
    address by hand, and is stored as NULL rather than a misleading number.
    """
    with _lock:
        try:
            conn = _open()
            conn.execute(
                "INSERT INTO logs (timestamp, src_ip, dst_ip, proto, rate, entropy, classification) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (timestamp, src_ip, victim_ip, "MIXED", src_rate, state.last_metrics.get("entropy", 0.0), classification)
            )
            conn.commit()
        except Exception as e:
            _close()
            logging.error(f"[-] Failed to write incident to SQLite: {e}")


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
