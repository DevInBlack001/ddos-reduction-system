"""Tests for schema.py: the table definitions and the migrations.

setup_admin.py and stage2.py each used to declare these tables themselves and
disagreed on whether logs.rate could be unset. Both use this module now, so
the tests here are what stops them drifting apart again.
"""

import sqlite3
import unittest

import _support
from _support import temp_path, unlink

import schema


# The layout setup_admin.py created before the schema was centralised.
LEGACY_LOGS = """
    CREATE TABLE logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT,
        proto TEXT,
        rate REAL NOT NULL,
        entropy REAL NOT NULL,
        classification TEXT NOT NULL
    )"""

LEGACY_METRICS = """
    CREATE TABLE metrics_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        ewma_rate REAL NOT NULL,
        entropy REAL NOT NULL,
        mean_h REAL NOT NULL,
        mean_r REAL NOT NULL,
        sigma_h REAL NOT NULL,
        sigma_r REAL NOT NULL,
        k_multiplier REAL NOT NULL
    )"""


class SchemaTestCase(unittest.TestCase):
    def setUp(self):
        self.path = temp_path(".db")
        self.conn = sqlite3.connect(self.path)

    def tearDown(self):
        self.conn.close()
        unlink(self.path)

    def notnull(self, table, column):
        for row in self.conn.execute(f"PRAGMA table_info({table})"):
            if row[1] == column:
                return bool(row[3])
        self.fail(f"{table}.{column} does not exist")

    def columns(self, table):
        return [row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")]

    def tables(self):
        return [r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]

    def log_row(self, rate=None):
        self.conn.execute(
            "INSERT INTO logs (timestamp, src_ip, dst_ip, proto, rate, entropy, classification)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (1.0, "198.51.100.9", "192.0.2.3", "MIXED", rate, 0.9, "Blocked"),
        )


class FreshDatabaseTests(SchemaTestCase):
    def setUp(self):
        super().setUp()
        schema.apply(self.conn)

    def test_creates_every_table(self):
        for table in ("users", "logs", "metrics_history"):
            self.assertIn(table, self.tables())

    def test_rate_is_nullable(self):
        # An operator blocking an address by hand has no measured rate, and
        # 0.0 would read as an observation that the source sent nothing.
        self.assertFalse(self.notnull("logs", "rate"))

    def test_a_null_rate_is_accepted(self):
        self.log_row(rate=None)

    def test_a_real_rate_is_accepted(self):
        self.log_row(rate=42.0)
        self.assertEqual(self.conn.execute("SELECT rate FROM logs").fetchone()[0], 42.0)

    def test_the_classification_is_still_required(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO logs (timestamp, src_ip) VALUES (1.0, '198.51.100.9')")

    def test_the_source_is_still_required(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO logs (timestamp, classification) VALUES (1.0, 'Blocked')")

    def test_metrics_history_has_victim_ip(self):
        self.assertIn("victim_ip", self.columns("metrics_history"))

    def test_a_password_hash_is_required(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO users (username) VALUES ('admin')")

    def test_applying_twice_is_harmless(self):
        self.log_row(rate=1.0)
        self.conn.commit()
        schema.apply(self.conn)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0], 1)


class LegacyDatabaseTests(SchemaTestCase):
    """A database created before the schema was centralised."""

    def setUp(self):
        super().setUp()
        self.conn.execute(LEGACY_LOGS)
        self.conn.execute(LEGACY_METRICS)
        self.conn.execute(
            "INSERT INTO logs (timestamp, src_ip, dst_ip, proto, rate, entropy, classification)"
            " VALUES (1.0, '198.51.100.9', '192.0.2.3', 'MIXED', 42.0, 0.9, 'Blocked')"
        )
        self.conn.commit()

    def test_the_legacy_layout_really_did_reject_a_null_rate(self):
        # Without this the migration tests could pass against a table that
        # never had the constraint.
        with self.assertRaises(sqlite3.IntegrityError):
            self.log_row(rate=None)

    def test_migration_drops_the_not_null_constraint(self):
        schema.apply(self.conn)
        self.assertFalse(self.notnull("logs", "rate"))

    def test_a_null_rate_is_accepted_after_migration(self):
        schema.apply(self.conn)
        self.log_row(rate=None)

    def test_existing_rows_survive(self):
        schema.apply(self.conn)
        self.assertEqual(
            self.conn.execute("SELECT src_ip, rate, classification FROM logs").fetchall(),
            [("198.51.100.9", 42.0, "Blocked")],
        )

    def test_row_ids_are_preserved(self):
        original = self.conn.execute("SELECT id FROM logs").fetchone()[0]
        schema.apply(self.conn)
        self.assertEqual(self.conn.execute("SELECT id FROM logs").fetchone()[0], original)

    def test_the_rebuild_leaves_no_temporary_table(self):
        schema.apply(self.conn)
        self.assertEqual([t for t in self.tables() if t.startswith("logs")], ["logs"])

    def test_victim_ip_is_added_to_metrics_history(self):
        self.assertNotIn("victim_ip", self.columns("metrics_history"))
        schema.apply(self.conn)
        self.assertIn("victim_ip", self.columns("metrics_history"))

    def test_migrating_twice_does_not_duplicate_rows(self):
        schema.apply(self.conn)
        schema.apply(self.conn)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0], 1)

    def test_new_and_old_rows_coexist(self):
        schema.apply(self.conn)
        self.log_row(rate=None)
        self.conn.commit()
        rates = [r[0] for r in self.conn.execute("SELECT rate FROM logs ORDER BY id")]
        self.assertEqual(rates, [42.0, None])


class WriterAgreementTests(SchemaTestCase):
    """db.log_incident has to work against the schema as shipped."""

    def setUp(self):
        super().setUp()
        schema.apply(self.conn)
        self.conn.close()

        import config
        import db

        self.db = db
        self._saved = config.DB_PATH
        config.DB_PATH = self.path
        _support.reset_db_module()
        self.conn = sqlite3.connect(self.path)

    def tearDown(self):
        import config

        _support.reset_db_module()
        config.DB_PATH = self._saved
        super().tearDown()

    def rows(self):
        return self.conn.execute("SELECT src_ip, rate, classification FROM logs ORDER BY id").fetchall()

    def test_an_incident_with_a_rate_is_written(self):
        self.db.log_incident(1.0, "198.51.100.9", "Blocked", "192.0.2.3", 37.5)
        self.assertEqual(self.rows(), [("198.51.100.9", 37.5, "Blocked")])

    def test_an_incident_without_a_rate_is_written(self):
        # This is the write that failed in production: a released or manually
        # actioned address has no measured rate.
        self.db.log_incident(1.0, "198.51.100.9", "Released", "192.0.2.3")
        self.assertEqual(self.rows(), [("198.51.100.9", None, "Released")])

    def test_a_classification_only_record_is_written(self):
        self.db.log_incident(1.0, "198.51.100.9", "Normal", "192.0.2.3")
        self.assertEqual(len(self.rows()), 1)

    def test_metrics_history_accepts_a_window(self):
        self.db.log_metrics_history(1.0, 10.0, 0.9, 0.9, 10.0, 0.01, 1.0, 3.0, "192.0.2.3")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM metrics_history").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
