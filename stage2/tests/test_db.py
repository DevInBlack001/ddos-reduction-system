"""Tests for db.py, the SQLite audit-log writers."""

import sqlite3
import unittest

import _support
from _support import make_logs_db, unlink

import config
import db
import state


class LogIncidentTests(unittest.TestCase):
    def setUp(self):
        self._db = config.DB_PATH
        self.path = make_logs_db()
        config.DB_PATH = self.path
        self._metrics = dict(state.last_metrics)
        state.last_metrics["entropy"] = 0.42
        state.last_metrics["ewma_rate"] = 9999.0

    def tearDown(self):
        config.DB_PATH = self._db
        state.last_metrics.clear()
        state.last_metrics.update(self._metrics)
        unlink(self.path)

    def rows(self):
        conn = sqlite3.connect(self.path)
        rows = conn.execute(
            "SELECT timestamp, src_ip, dst_ip, proto, rate, entropy, classification"
            " FROM logs ORDER BY id"
        ).fetchall()
        conn.close()
        return rows

    def test_writes_one_row(self):
        db.log_incident(100.0, "198.51.100.9", "Blocked")
        self.assertEqual(len(self.rows()), 1)

    def test_stores_the_source_ip(self):
        db.log_incident(100.0, "198.51.100.9", "Blocked")
        self.assertEqual(self.rows()[0][1], "198.51.100.9")

    def test_stores_the_victim_as_the_destination(self):
        db.log_incident(100.0, "198.51.100.9", "Blocked", victim_ip="192.0.2.3")
        self.assertEqual(self.rows()[0][2], "192.0.2.3")

    def test_stores_the_classification(self):
        db.log_incident(100.0, "198.51.100.9", "Rate Limited")
        self.assertEqual(self.rows()[0][6], "Rate Limited")

    def test_stores_the_per_source_rate_it_was_given(self):
        db.log_incident(100.0, "198.51.100.9", "Blocked", src_rate=37.5)
        self.assertEqual(self.rows()[0][4], 37.5)

    def test_does_not_substitute_the_window_aggregate_rate(self):
        # Every source actioned in one window used to be logged with
        # state.last_metrics["ewma_rate"], the victim's whole-window volume.
        db.log_incident(100.0, "198.51.100.9", "Blocked", src_rate=12.0)
        self.assertNotEqual(self.rows()[0][4], state.last_metrics["ewma_rate"])

    def test_sources_in_one_window_keep_distinct_rates(self):
        db.log_incident(100.0, "198.51.100.9", "Rate Limited", src_rate=12.0)
        db.log_incident(100.0, "198.51.100.10", "Rate Limited", src_rate=4.0)
        db.log_incident(100.0, "198.51.100.11", "Rate Limited", src_rate=61.0)
        self.assertEqual([r[4] for r in self.rows()], [12.0, 4.0, 61.0])

    def test_an_unknown_rate_is_stored_as_null(self):
        # A manual block has no measured rate; a zero would read as an
        # observation that the source sent nothing.
        db.log_incident(100.0, "198.51.100.9", "Released")
        self.assertIsNone(self.rows()[0][4])

    def test_a_genuine_zero_rate_is_not_turned_into_null(self):
        db.log_incident(100.0, "198.51.100.9", "Blocked", src_rate=0.0)
        self.assertEqual(self.rows()[0][4], 0.0)

    def test_entropy_stays_the_window_level_value(self):
        # Entropy describes the source distribution the decision was made
        # against, so it is not per-source and is read from shared state.
        db.log_incident(100.0, "198.51.100.9", "Blocked", src_rate=1.0)
        self.assertEqual(self.rows()[0][5], 0.42)

    def test_entropy_defaults_to_zero_when_absent(self):
        state.last_metrics.pop("entropy", None)
        db.log_incident(100.0, "198.51.100.9", "Blocked")
        self.assertEqual(self.rows()[0][5], 0.0)

    def test_victim_defaults_to_unknown(self):
        db.log_incident(100.0, "198.51.100.9", "Blocked")
        self.assertEqual(self.rows()[0][2], "Unknown")

    def test_a_write_failure_does_not_raise(self):
        # Called from the enforcement path; a failed audit write must not
        # take down mitigation.
        config.DB_PATH = "/proc/definitely/not/a/database.db"
        db.log_incident(100.0, "198.51.100.9", "Blocked")

    def test_a_missing_table_does_not_raise(self):
        conn = sqlite3.connect(self.path)
        conn.execute("DROP TABLE logs")
        conn.commit()
        conn.close()
        db.log_incident(100.0, "198.51.100.9", "Blocked")


class LogMetricsHistoryTests(unittest.TestCase):
    def setUp(self):
        self._db = config.DB_PATH
        self.path = make_logs_db()
        config.DB_PATH = self.path

    def tearDown(self):
        config.DB_PATH = self._db
        unlink(self.path)

    def write(self, n, victim="192.0.2.3"):
        for i in range(n):
            db.log_metrics_history(float(i), 10.0, 0.9, 0.9, 10.0, 0.01, 1.0, 3.0, victim)

    def count(self):
        conn = sqlite3.connect(self.path)
        n = conn.execute("SELECT COUNT(*) FROM metrics_history").fetchone()[0]
        conn.close()
        return n

    def test_writes_one_row(self):
        self.write(1)
        self.assertEqual(self.count(), 1)

    def test_stores_every_metric_column(self):
        db.log_metrics_history(1.0, 20.0, 0.8, 0.85, 15.0, 0.05, 2.0, 3.0, "192.0.2.4")
        conn = sqlite3.connect(self.path)
        row = conn.execute(
            "SELECT timestamp, ewma_rate, entropy, mean_h, mean_r, sigma_h,"
            " sigma_r, k_multiplier, victim_ip FROM metrics_history"
        ).fetchone()
        conn.close()
        self.assertEqual(row, (1.0, 20.0, 0.8, 0.85, 15.0, 0.05, 2.0, 3.0, "192.0.2.4"))

    def test_keeps_rows_below_the_retention_limit(self):
        self.write(50)
        self.assertEqual(self.count(), 50)

    def test_retention_caps_the_table_at_1000_rows(self):
        self.write(1005)
        self.assertEqual(self.count(), 1000)

    def test_retention_keeps_the_newest_rows(self):
        self.write(1005)
        conn = sqlite3.connect(self.path)
        oldest = conn.execute("SELECT MIN(timestamp) FROM metrics_history").fetchone()[0]
        conn.close()
        self.assertEqual(oldest, 5.0)

    def test_retention_is_global_not_per_victim(self):
        # The purge orders by id across the whole table, so a second victim
        # does not get its own 1000-row allowance.
        self.write(600, victim="192.0.2.3")
        self.write(600, victim="192.0.2.4")
        self.assertEqual(self.count(), 1000)

    def test_a_write_failure_does_not_raise(self):
        config.DB_PATH = "/proc/definitely/not/a/database.db"
        db.log_metrics_history(1.0, 10.0, 0.9, 0.9, 10.0, 0.01, 1.0, 3.0, "192.0.2.3")


if __name__ == "__main__":
    unittest.main()
