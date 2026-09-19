import re
import unittest

import _support  # noqa: F401
import latency
from latency import LatencyStats


class LatencyStatsTests(unittest.TestCase):
    def test_a_fresh_instance_reports_no_samples(self):
        self.assertFalse(LatencyStats().has_samples())

    def test_recording_a_sample_marks_the_instance_as_having_samples(self):
        stats = LatencyStats()
        stats.record("inference", 2.0)
        self.assertTrue(stats.has_samples())

    def test_an_unknown_kind_is_rejected(self):
        with self.assertRaises(KeyError):
            LatencyStats().record("unknown", 1.0)

    def test_the_summary_line_reports_count_mean_p95_and_max_per_kind(self):
        stats = LatencyStats()
        for value in range(1, 101):
            stats.record("inference", float(value))
        line = stats.summary_line(30)
        self.assertIn("interval_secs=30", line)
        self.assertIn("inference_n=100", line)
        self.assertIn("inference_mean_ms=50.500", line)
        self.assertIn("inference_p95_ms=95.000", line)
        self.assertIn("inference_max_ms=100.000", line)

    def test_a_kind_with_no_samples_reports_a_zero_count_only(self):
        stats = LatencyStats()
        stats.record("handoff", 1.0)
        line = stats.summary_line(30)
        self.assertIn("enforcement_n=0", line)
        self.assertNotIn("enforcement_mean_ms", line)

    def test_the_summary_line_is_parseable_as_key_value_pairs(self):
        stats = LatencyStats()
        stats.record("window_to_rule", 12.5)
        line = stats.summary_line(30)
        found = dict(re.findall(r"(\w+)=([\d.]+)", line))
        self.assertEqual(found["window_to_rule_n"], "1")
        self.assertEqual(found["window_to_rule_max_ms"], "12.500")

    def test_the_time_spent_handling_a_window_is_summarized_with_the_other_kinds(self):
        stats = LatencyStats()
        stats.record("busy", 2400.0)
        line = stats.summary_line(30)
        self.assertIn("busy_n=1", line)
        self.assertIn("busy_max_ms=2400.000", line)

    def test_producing_a_summary_starts_a_new_interval(self):
        stats = LatencyStats()
        stats.record("handoff", 1.0)
        stats.summary_line(30)
        self.assertFalse(stats.has_samples())

    def test_samples_beyond_the_cap_are_counted_but_not_stored(self):
        stats = LatencyStats()
        for _ in range(latency.MAX_SAMPLES_PER_KIND + 5):
            stats.record("handoff", 1.0)
        line = stats.summary_line(30)
        self.assertIn(f"handoff_n={latency.MAX_SAMPLES_PER_KIND + 5}", line)


if __name__ == "__main__":
    unittest.main()
