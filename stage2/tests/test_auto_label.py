"""Tests for auto_label.py's labeling decision logic: the freshness
safeguard, model agreement, and the capture-file row cap. See
docs/specs/2026-09-13-confidence-gated-labeling-design.md."""

import csv
import os
import unittest

import _support
from _support import temp_path, unlink

import config
import auto_label


class IsRowEligibleTests(unittest.TestCase):
    """A row is eligible only once it clears the configured delay AND every
    model scoring it was trained after the row was captured. The freshness
    half exists so a stale, unretrained model can never auto-label its own
    blind spot, even with a second opinion agreeing."""

    def test_ineligible_when_younger_than_the_delay(self):
        now = 1_000_000.0
        row_timestamp = now - 3600.0  # one hour old
        self.assertFalse(auto_label.is_row_eligible(
            row_timestamp, model_mtimes=[now - 10], delay_hours=24.0, now=now,
        ))

    def test_eligible_once_older_than_the_delay_with_a_fresh_model(self):
        now = 1_000_000.0
        row_timestamp = now - (25 * 3600.0)  # 25 hours old
        self.assertTrue(auto_label.is_row_eligible(
            row_timestamp, model_mtimes=[now - 10], delay_hours=24.0, now=now,
        ))

    def test_ineligible_if_any_model_predates_the_row(self):
        now = 1_000_000.0
        row_timestamp = now - (25 * 3600.0)
        stale_model_mtime = row_timestamp - 10.0  # trained before this row was even captured
        fresh_model_mtime = now - 10.0
        self.assertFalse(auto_label.is_row_eligible(
            row_timestamp, model_mtimes=[fresh_model_mtime, stale_model_mtime], delay_hours=24.0, now=now,
        ))

    def test_eligible_only_when_every_model_postdates_the_row(self):
        now = 1_000_000.0
        row_timestamp = now - (25 * 3600.0)
        self.assertTrue(auto_label.is_row_eligible(
            row_timestamp, model_mtimes=[now - 5, now - 1], delay_hours=24.0, now=now,
        ))


class DecideLabelTests(unittest.TestCase):
    """A label is only ever produced when both models agree on the class
    and both individually clear the confidence threshold. Agreement is
    the safeguard: two differently built models making the same mistake
    on a genuinely novel row is far less likely than one model
    rehashing its own opinion."""

    def test_agreement_above_threshold_returns_the_agreed_class(self):
        rf_proba = [0.02, 0.03, 0.95]
        second_proba = [0.05, 0.05, 0.90]
        self.assertEqual(auto_label.decide_label(rf_proba, second_proba, confidence_threshold=0.90), 2)

    def test_disagreement_returns_none_even_if_both_are_confident(self):
        rf_proba = [0.02, 0.03, 0.95]      # top class 2
        second_proba = [0.95, 0.03, 0.02]  # top class 0
        self.assertIsNone(auto_label.decide_label(rf_proba, second_proba, confidence_threshold=0.90))

    def test_agreement_below_threshold_on_the_random_forest_returns_none(self):
        rf_proba = [0.15, 0.15, 0.70]      # agrees, but below 0.90
        second_proba = [0.05, 0.05, 0.90]
        self.assertIsNone(auto_label.decide_label(rf_proba, second_proba, confidence_threshold=0.90))

    def test_agreement_below_threshold_on_the_second_model_returns_none(self):
        rf_proba = [0.02, 0.03, 0.95]
        second_proba = [0.20, 0.20, 0.60]  # agrees, but below 0.90
        self.assertIsNone(auto_label.decide_label(rf_proba, second_proba, confidence_threshold=0.90))


class TrimCsvRowsTests(unittest.TestCase):
    """Without a cap, a fresh deployment left running with no model, or a
    long configured delay under heavy traffic, would grow an unbounded
    capture file. Timestamp is column index 11 in the 13-column base
    format both capture files share."""

    def _row(self, timestamp):
        return ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                "0.9", "0.1", "0.1", str(timestamp), ""]

    def test_rows_at_or_under_the_cap_are_left_untouched(self):
        rows = [self._row(t) for t in (1.0, 2.0, 3.0)]
        kept, dropped = auto_label.trim_csv_rows(rows, max_rows=3)
        self.assertEqual(len(kept), 3)
        self.assertEqual(dropped, 0)

    def test_over_the_cap_drops_the_oldest_rows_by_timestamp(self):
        rows = [self._row(t) for t in (3.0, 1.0, 2.0)]  # deliberately out of order
        kept, dropped = auto_label.trim_csv_rows(rows, max_rows=2)
        self.assertEqual(dropped, 1)
        self.assertEqual(sorted(float(r[11]) for r in kept), [2.0, 3.0])


class MainLeavesCapturedRowsUntouchedWithoutBothModelsTests(unittest.TestCase):
    """main() cannot check agreement with only one model, or with neither.
    A captured row must stay exactly where it is, not be guessed at, until
    both models exist."""

    def setUp(self):
        self.pretraining_path = temp_path(".csv")
        os.unlink(self.pretraining_path)
        self.original_pretraining_path = config.PRETRAINING_CSV_PATH
        config.PRETRAINING_CSV_PATH = self.pretraining_path
        self.original_model_path = config.MODEL_PATH
        self.original_second_model_path = config.SECOND_MODEL_PATH
        config.MODEL_PATH = self.pretraining_path + ".no-such-model"
        config.SECOND_MODEL_PATH = self.pretraining_path + ".no-such-second-model"
        with open(self.pretraining_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(auto_label.BASE_CSV_HEADER)
            w.writerow(["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                        "0.9", "0.1", "0.1", "1000.0", ""])

    def tearDown(self):
        config.PRETRAINING_CSV_PATH = self.original_pretraining_path
        config.MODEL_PATH = self.original_model_path
        config.SECOND_MODEL_PATH = self.original_second_model_path
        unlink(self.pretraining_path)

    def test_the_captured_row_is_left_untouched_when_neither_model_exists(self):
        auto_label.main()
        with open(self.pretraining_path, newline="") as f:
            rows = list(csv.reader(f))
        self.assertEqual(len(rows), 2)  # header + the one row, unchanged


if __name__ == "__main__":
    unittest.main()
