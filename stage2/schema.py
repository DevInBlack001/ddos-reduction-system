"""
schema.py: the database layout, defined once.

Every table is created here, via apply(), rather than by each caller with its
own CREATE TABLE statement: two definitions of the same table with different
constraints lets whichever runs first decide the real layout.
"""

import logging
import sqlite3


# rate is nullable on purpose: an operator blocking an address by hand has no
# measured rate, and storing 0.0 would read as "this source sent nothing".
TABLES = {
    "users": """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT
        )""",
    "logs": """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT,
            proto TEXT,
            rate REAL,
            entropy REAL,
            classification TEXT NOT NULL
        )""",
    "metrics_history": """
        CREATE TABLE IF NOT EXISTS metrics_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            ewma_rate REAL,
            entropy REAL,
            mean_h REAL,
            mean_r REAL,
            sigma_h REAL,
            sigma_r REAL,
            k_multiplier REAL,
            victim_ip TEXT
        )""",
    # One row per auto_label.py run that actually staged rows. resolved
    # flips to 1 the moment an operator merges or discards the staged
    # file, which always resolves every pending run at once: the
    # underlying CSV is one shared queue, not partitioned per run.
    "auto_label_runs": """
        CREATE TABLE IF NOT EXISTS auto_label_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            rows_labeled INTEGER NOT NULL,
            resolved INTEGER NOT NULL DEFAULT 0
        )""",
    # V10. definition is the single JSON document both editing surfaces
    # (form builder, hand-edited JSON/YAML) read and write; see
    # docs/specs/2026-09-13-playbooks-design.md for its shape. Storing it as
    # one column rather than normalized trigger/stage tables is deliberate:
    # a playbook is authored and edited as one document by one operator, not
    # queried or joined against by anything else in the system.
    "playbooks": """
        CREATE TABLE IF NOT EXISTS playbooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_scope_type TEXT NOT NULL,
            target_scope_value TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            definition TEXT NOT NULL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )""",
    # At most one running row per (playbook_id, target_host), enforced by
    # the caller checking before insert rather than a partial unique index,
    # since SQLite's partial index syntax on a non-constant WHERE clause
    # (status = 'running') still permits duplicates a caller could race
    # into; the engine only ever runs one advancement pass at a time so
    # this is not a concurrency gap in practice.
    "playbook_runs": """
        CREATE TABLE IF NOT EXISTS playbook_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id INTEGER NOT NULL,
            target_host TEXT NOT NULL,
            target_source TEXT,
            current_stage_index INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'running',
            trigger_reason TEXT,
            started_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )""",
    "playbook_events": """
        CREATE TABLE IF NOT EXISTS playbook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            stage_index INTEGER NOT NULL,
            stage_type TEXT NOT NULL,
            fired_at REAL NOT NULL,
            target_source TEXT,
            detail TEXT
        )""",
}

LOGS_COLUMNS = "timestamp, src_ip, dst_ip, proto, rate, entropy, classification"

# Every window logs a row per target, so most of the table is "Normal" and a
# scan for enforcement actions walks past all of it. The dashboard reads the
# most recent ones on every poll.
INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_logs_classification_id ON logs (classification, id)",
    "CREATE INDEX IF NOT EXISTS idx_auto_label_runs_resolved ON auto_label_runs (resolved, id)",
    "CREATE INDEX IF NOT EXISTS idx_playbook_runs_status ON playbook_runs (playbook_id, target_host, status)",
    "CREATE INDEX IF NOT EXISTS idx_playbook_events_run_id ON playbook_events (run_id, stage_index)",
)


def apply(conn):
    """Create anything missing, then bring an existing database up to date."""
    for statement in TABLES.values():
        conn.execute(statement)
    _add_victim_ip(conn)
    _relax_logs_rate(conn)
    # After the migrations: _relax_logs_rate rebuilds logs, which drops any
    # index that was on it.
    for statement in INDEXES:
        conn.execute(statement)
    conn.commit()


def _columns(conn, table):
    """Column name to its NOT NULL flag."""
    return {row[1]: bool(row[3]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_victim_ip(conn):
    if "victim_ip" in _columns(conn, "metrics_history"):
        return
    logging.info("[*] Migrating database: adding victim_ip to metrics_history")
    try:
        conn.execute("ALTER TABLE metrics_history ADD COLUMN victim_ip TEXT DEFAULT ''")
    except sqlite3.Error as e:
        logging.error(f"[-] Migration failed: {e}")


def _relax_logs_rate(conn):
    """Drop the NOT NULL constraint on logs.rate.

    SQLite cannot alter a column constraint in place, so the table is rebuilt
    and the rows copied across.
    """
    if not _columns(conn, "logs").get("rate"):
        return

    logging.info("[*] Migrating database: allowing logs.rate to be unset")
    try:
        conn.execute("ALTER TABLE logs RENAME TO logs_pre_migration")
        conn.execute(TABLES["logs"])
        conn.execute(
            f"INSERT INTO logs (id, {LOGS_COLUMNS})"
            f" SELECT id, {LOGS_COLUMNS} FROM logs_pre_migration"
        )
        conn.execute("DROP TABLE logs_pre_migration")
        conn.commit()
        logging.info("[+] Migration complete: existing incident records preserved")
    except sqlite3.Error as e:
        conn.rollback()
        logging.error(f"[-] Migration failed, leaving the table as it was: {e}")
