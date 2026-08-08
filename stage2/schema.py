"""
schema.py: the database layout, defined once.

stage2.py and setup_admin.py both used to create these tables with their own
CREATE TABLE statements, and the two disagreed: setup_admin.py declared
logs.rate NOT NULL while stage2.py left it nullable. Since both used
CREATE TABLE IF NOT EXISTS, whichever ran first decided the real layout, and
the installer runs setup_admin.py first. Every incident with no measured rate
then failed to write.

Both callers now use apply(), so there is one definition and one place to
change it.
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
}

LOGS_COLUMNS = "timestamp, src_ip, dst_ip, proto, rate, entropy, classification"


def apply(conn):
    """Create anything missing, then bring an existing database up to date."""
    for statement in TABLES.values():
        conn.execute(statement)
    _add_victim_ip(conn)
    _relax_logs_rate(conn)
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
