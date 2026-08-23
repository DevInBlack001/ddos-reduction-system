"""Tests for report_data.py, the PDF incident report's data aggregation."""

import time
import unittest

import _support
from _support import RecordingRun, make_logs_db, reset_db_module, unlink

import config
import db
import enforcement
import report_data
import state


class BucketSecondsTests(unittest.TestCase):
    def test_uses_one_minute_buckets_for_a_short_window(self):
        self.assertEqual(report_data._pick_bucket_seconds(1.0), 60)

    def test_widens_the_bucket_for_a_much_longer_window(self):
        self.assertGreater(report_data._pick_bucket_seconds(168.0), 60)

    def test_never_returns_more_than_the_configured_ceiling(self):
        self.assertLessEqual(report_data._pick_bucket_seconds(168.0), report_data.BUCKET_STEPS_SECONDS[-1])


class NiceCeilingTests(unittest.TestCase):
    def test_rounds_a_value_up_rather_than_down(self):
        self.assertGreaterEqual(report_data._nice_ceiling(437), 437)

    def test_a_value_already_at_a_clean_number_stays_there(self):
        self.assertEqual(report_data._nice_ceiling(200), 200)

    def test_zero_still_returns_a_positive_axis_maximum(self):
        self.assertGreater(report_data._nice_ceiling(0), 0)


class BuildContextTests(unittest.TestCase):
    """Exercises build_context() against a real, throwaway schema-backed
    database, the same way db.py's own tests do, since the aggregation
    logic is one SQL query away from db.log_incident's own writes."""

    def setUp(self):
        self._db = config.DB_PATH
        self.path = make_logs_db()
        config.DB_PATH = self.path
        reset_db_module()

        self._metrics = dict(state.last_metrics)
        state.last_metrics.update({
            "mean_r": 5.0, "sigma_r": 2.0, "mean_h": 0.9, "sigma_h": 0.05, "k_multiplier": 2.0,
        })

        self._real_run = enforcement.subprocess.run
        enforcement.subprocess.run = RecordingRun(returncode=1)

    def tearDown(self):
        reset_db_module()
        config.DB_PATH = self._db
        state.last_metrics.clear()
        state.last_metrics.update(self._metrics)
        enforcement.subprocess.run = self._real_run
        unlink(self.path)

    def test_an_empty_window_has_no_columns(self):
        ctx = report_data.build_context(1.0)
        self.assertEqual(ctx["cols"], [])

    def test_counts_every_record_logged_in_the_window(self):
        now = time.time()
        db.log_incident(now - 120, "198.51.100.9", "Normal", victim_ip="192.0.2.3")
        db.log_incident(now - 60, "198.51.100.10", "Blocked", victim_ip="192.0.2.3")
        ctx = report_data.build_context(1.0)
        self.assertEqual(ctx["total_records"], "2")

    def test_released_events_are_not_counted_as_traffic(self):
        db.log_incident(time.time() - 60, "198.51.100.9", "Released", victim_ip="192.0.2.3")
        ctx = report_data.build_context(1.0)
        self.assertEqual(ctx["total_records"], "0")

    def test_flags_the_unattributed_source_placeholder(self):
        now = time.time()
        for _ in range(3):
            db.log_incident(now - 60, "0.0.0.0", "Blocked", victim_ip="192.0.2.3")
        ctx = report_data.build_context(1.0)
        self.assertTrue(ctx["unattributed_source"])
        self.assertEqual(ctx["unattributed_source"]["ip"], "0.0.0.0")

    def test_a_named_source_is_not_flagged_as_unattributed(self):
        db.log_incident(time.time() - 60, "198.51.100.9", "Normal", victim_ip="192.0.2.3")
        ctx = report_data.build_context(1.0)
        self.assertIsNone(ctx["unattributed_source"])

    def test_a_bar_with_no_learned_baseline_yet_is_not_painted_as_anomalous(self):
        # sigma_r/mean_r are both 0.0 until a baseline has been learned, so
        # the threshold is 0: there is nothing yet to call anomalous.
        state.last_metrics.update({"mean_r": 0.0, "sigma_r": 0.0})
        db.log_incident(time.time() - 60, "198.51.100.9", "Normal", victim_ip="192.0.2.3", src_rate=50.0)
        ctx = report_data.build_context(1.0)
        self.assertEqual(ctx["cols"][-1]["rate_color"], report_data.COLORS["Normal"])

    def test_a_short_severe_phase_is_kept_over_a_longer_quiet_one(self):
        # Eight quiet minutes, then one minute of a hard block: the block
        # matters more to a reader than the seven-minute head start it
        # loses on raw duration, so phase selection must not just pick the
        # longest runs.
        base = time.time() - 9 * 60
        for minute in range(8):
            db.log_incident(base + minute * 60, "198.51.100.9", "Normal", victim_ip="192.0.2.3")
        db.log_incident(base + 8 * 60, "198.51.100.20", "Blocked", victim_ip="192.0.2.3", src_rate=999.0)

        ctx = report_data.build_context(1.0)
        titles = [p["title"] for p in ctx["phases"]]
        self.assertIn("Blocked", titles)


if __name__ == "__main__":
    unittest.main()
