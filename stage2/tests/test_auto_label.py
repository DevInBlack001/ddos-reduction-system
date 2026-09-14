"""Tests for auto_label.py's labeling decision logic: the freshness
safeguard, model agreement, and the capture-file row cap. See
docs/specs/2026-09-13-confidence-gated-labeling-design.md."""

import csv
import os
import time
import unittest
import fcntl

import numpy as np

import _support
from _support import temp_path, unlink

import config
import auto_label
import ipc_receiver


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
        self.assertEqual(
            auto_label.decide_label(rf_proba, [0, 1, 2], second_proba, [0, 1, 2], confidence_threshold=0.90),
            2,
        )

    def test_disagreement_returns_none_even_if_both_are_confident(self):
        rf_proba = [0.02, 0.03, 0.95]      # top class 2
        second_proba = [0.95, 0.03, 0.02]  # top class 0
        self.assertIsNone(
            auto_label.decide_label(rf_proba, [0, 1, 2], second_proba, [0, 1, 2], confidence_threshold=0.90)
        )

    def test_agreement_below_threshold_on_the_random_forest_returns_none(self):
        rf_proba = [0.15, 0.15, 0.70]      # agrees, but below 0.90
        second_proba = [0.05, 0.05, 0.90]
        self.assertIsNone(
            auto_label.decide_label(rf_proba, [0, 1, 2], second_proba, [0, 1, 2], confidence_threshold=0.90)
        )

    def test_agreement_below_threshold_on_the_second_model_returns_none(self):
        rf_proba = [0.02, 0.03, 0.95]
        second_proba = [0.20, 0.20, 0.60]  # agrees, but below 0.90
        self.assertIsNone(
            auto_label.decide_label(rf_proba, [0, 1, 2], second_proba, [0, 1, 2], confidence_threshold=0.90)
        )

    def test_mismatched_classes_returns_none_even_when_the_shared_class_agrees(self):
        # RF has never dropped a class; the second model's training CSV had
        # no rows for class 1 (Flash Crowd), so its classes_ is [0, 2] and
        # its proba index 1 actually means class 2, not class 1. Both top
        # picks land on "index 1" but that means different classes for each
        # model, so this must not be read as agreement.
        rf_proba = [0.02, 0.95, 0.03]        # classes_ [0, 1, 2]: top is class 1
        second_proba = [0.03, 0.97]          # classes_ [0, 2]: top is class 2
        self.assertIsNone(
            auto_label.decide_label(rf_proba, [0, 1, 2], second_proba, [0, 2], confidence_threshold=0.90)
        )


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


class ProcessCaptureFileSkipsMalformedRowsTests(unittest.TestCase):
    """A single corrupted row (a non-numeric timestamp here) must not abort
    the whole file: the valid rows around it are still scored normally, and
    the bad row is left in place for a human to look at, not silently
    dropped or allowed to crash the run."""

    class _FakeConfidentModel:
        """Always confidently agrees on class 2. Standing in for a real
        joblib model so this test does not need one: only the malformed
        row handling in _process_capture_file is under test here."""

        classes_ = np.array([0, 1, 2])

        def predict_proba(self, features_df):
            return np.array([[0.01, 0.02, 0.97]])

    def setUp(self):
        self.capture_path = temp_path(".csv")
        os.unlink(self.capture_path)
        self.labeled_path = temp_path(".csv")
        os.unlink(self.labeled_path)
        old_timestamp = "1000000.0"  # unambiguously older than the delay and every model mtime
        valid_row = ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                     "0.9", "0.1", "0.1", old_timestamp, ""]
        malformed_row = ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                          "0.9", "0.1", "0.1", "not-a-timestamp", ""]
        with open(self.capture_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(auto_label.BASE_CSV_HEADER)
            w.writerow(valid_row)
            w.writerow(malformed_row)
            w.writerow(valid_row)

    def tearDown(self):
        unlink(self.capture_path, self.labeled_path)

    def test_the_malformed_row_is_skipped_and_the_valid_rows_are_still_labeled(self):
        model_mtimes = [time.time(), time.time()]
        labeled_count = auto_label._process_capture_file(
            self.capture_path, self._FakeConfidentModel(), self._FakeConfidentModel(),
            model_mtimes, self.labeled_path,
        )
        self.assertEqual(labeled_count, 2)  # both valid rows, the malformed one does not count

        with open(self.capture_path, newline="") as f:
            remaining_rows = list(csv.reader(f))
        # header + the one malformed row, left exactly where it was
        self.assertEqual(len(remaining_rows), 2)
        self.assertEqual(remaining_rows[1][auto_label.TIMESTAMP_COL], "not-a-timestamp")

        with open(self.labeled_path, newline="") as f:
            labeled_rows = list(csv.reader(f))
        self.assertEqual(len(labeled_rows), 3)  # header + the two labeled rows


class ProcessCaptureFileStagesSixteenColumnRowsCorrectlyTests(unittest.TestCase):
    """anomalous_capture.csv rows carry 3 extra context columns (victim_ip,
    if_score, rf_verdict) beyond the 13-column BASE_CSV_HEADER every other
    capture file uses. A labeled row must be truncated to the 13-column
    staging layout, not written as-is: writing all 16 columns under a
    13-column header shifts every field pandas later reads back (timestamp
    reads as the old if_score, label as the old rf_verdict string)."""

    class _FakeConfidentModel:
        classes_ = np.array([0, 1, 2])

        def predict_proba(self, features_df):
            return np.array([[0.01, 0.02, 0.97]])

    # Matches ipc_receiver.ANOMALOUS_CSV_HEADER: BASE_CSV_HEADER's 13 columns
    # plus victim_ip, if_score, rf_verdict.
    ANOMALOUS_CSV_HEADER = auto_label.BASE_CSV_HEADER + ["victim_ip", "if_score", "rf_verdict"]

    def setUp(self):
        self.capture_path = temp_path(".csv")
        os.unlink(self.capture_path)
        self.labeled_path = temp_path(".csv")
        os.unlink(self.labeled_path)
        old_timestamp = "1000000.0"  # unambiguously older than the delay and every model mtime
        anomalous_row = ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                          "0.9", "0.1", "0.1", old_timestamp, "",
                          "198.51.100.7", "0.87", "Normal"]  # victim_ip, if_score, rf_verdict
        with open(self.capture_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(self.ANOMALOUS_CSV_HEADER)
            w.writerow(anomalous_row)

    def tearDown(self):
        unlink(self.capture_path, self.labeled_path)

    def test_a_labeled_sixteen_column_row_is_staged_with_exactly_thirteen_columns(self):
        model_mtimes = [time.time(), time.time()]
        labeled_count = auto_label._process_capture_file(
            self.capture_path, self._FakeConfidentModel(), self._FakeConfidentModel(),
            model_mtimes, self.labeled_path,
        )
        self.assertEqual(labeled_count, 1)

        with open(self.labeled_path, newline="") as f:
            labeled_rows = list(csv.reader(f))
        self.assertEqual(labeled_rows[0], auto_label.BASE_CSV_HEADER)
        self.assertEqual(len(labeled_rows[1]), len(auto_label.BASE_CSV_HEADER))
        self.assertEqual(labeled_rows[1][auto_label.TIMESTAMP_COL], "1000000.0")
        self.assertEqual(labeled_rows[1][auto_label.BASE_CSV_HEADER.index("label")], "2")


class TrimCsvRowsMalformedHandlingTests(unittest.TestCase):
    """Malformed rows (non-numeric or missing timestamp) must not crash
    trim_csv_rows: they should sort oldest and get dropped first if the
    file is over the row cap."""

    def _row(self, timestamp_str):
        return ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                "0.9", "0.1", "0.1", timestamp_str, ""]

    def test_malformed_timestamp_sorts_oldest_without_raising(self):
        rows = [self._row("3.0"), self._row("not-a-timestamp"), self._row("2.0"), self._row("1.0")]
        # Over the cap by one row; the malformed one should be dropped first
        kept, dropped = auto_label.trim_csv_rows(rows, max_rows=3)
        self.assertEqual(dropped, 1)
        # Kept rows are 1.0, 2.0, 3.0 in timestamp order; malformed one gone
        self.assertEqual(len(kept), 3)
        self.assertNotIn("not-a-timestamp", [r[auto_label.TIMESTAMP_COL] for r in kept])

    def test_missing_timestamp_column_sorts_oldest_without_raising(self):
        good_row = self._row("2.0")
        short_row = ["0.9", "20.0", "0.9"]  # missing timestamp column entirely
        rows = [good_row, short_row, self._row("1.0")]
        kept, dropped = auto_label.trim_csv_rows(rows, max_rows=2)
        self.assertEqual(dropped, 1)
        self.assertEqual(len(kept), 2)
        # The short row should be gone
        self.assertNotEqual(len(kept[0]), len(short_row))


class TrimCaptureFileWithoutModelsTests(unittest.TestCase):
    """_trim_capture_file_only runs even when no models exist, bounding
    unbounded growth of cold-start capture files during the pre-training
    period."""

    def _row(self, timestamp):
        return ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                "0.9", "0.1", "0.1", str(timestamp), ""]

    def setUp(self):
        self.capture_path = temp_path(".csv")
        os.unlink(self.capture_path)

    def tearDown(self):
        unlink(self.capture_path)

    def test_trim_without_models_succeeds_on_valid_csv(self):
        # When no models exist, _trim_capture_file_only still runs to keep
        # files bounded. It reads with _read_rows (which uses a deque to
        # bound peak memory) and trims if needed. The test verifies the
        # function succeeds and produces a valid CSV even on a file over the cap.
        with open(self.capture_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(auto_label.BASE_CSV_HEADER)
            for t in (1.0, 2.0, 3.0, 4.0, 5.0):
                w.writerow(self._row(t))

        original_max_rows = config.AUTO_LABEL_MAX_QUEUE_ROWS
        config.AUTO_LABEL_MAX_QUEUE_ROWS = 3
        try:
            # _trim_capture_file_only should succeed and not crash
            dropped = auto_label._trim_capture_file_only(self.capture_path)
            # Returns the number of rows trim_csv_rows dropped after the deque read

            with open(self.capture_path, newline="") as f:
                rows = list(csv.reader(f))
            # CSV should still be valid with a proper header
            self.assertEqual(rows[0], auto_label.BASE_CSV_HEADER)
            # Verify data rows still have proper timestamp structure
            for data_row in rows[1:]:
                self.assertGreaterEqual(len(data_row), auto_label.TIMESTAMP_COL + 1)
                # Timestamp column should be numeric
                float(data_row[auto_label.TIMESTAMP_COL])
        finally:
            config.AUTO_LABEL_MAX_QUEUE_ROWS = original_max_rows


class DequeHeaderEvictionRegressionTests(unittest.TestCase):
    """Regression test for a bug where the deque's maxlen window included
    the header row, causing it to be evicted when the file had more data rows
    than the cap. This broke both trimming (trim_csv_rows saw no excess rows
    to drop because the evicted header exactly balanced the excess) and scoring
    (the corrupted header caused KeyError when _row_to_features tried to map
    field names)."""

    def _row(self, timestamp):
        return ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                "0.9", "0.1", "0.1", str(timestamp), ""]

    def setUp(self):
        self.capture_path = temp_path(".csv")
        os.unlink(self.capture_path)

    def tearDown(self):
        unlink(self.capture_path)

    def test_read_rows_preserves_header_even_when_file_exceeds_cap(self):
        # Write a file with more data rows than the cap
        with open(self.capture_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(auto_label.BASE_CSV_HEADER)
            for t in range(1, 11):  # 10 data rows
                w.writerow(self._row(float(t)))

        original_max_rows = config.AUTO_LABEL_MAX_QUEUE_ROWS
        config.AUTO_LABEL_MAX_QUEUE_ROWS = 3  # cap < 10 rows
        try:
            # Read should return the real header, not a data row
            header, rows, was_bounded = auto_label._read_rows(self.capture_path)
            self.assertEqual(header, auto_label.BASE_CSV_HEADER)
            # Deque bounds to 3 data rows, so we should have at most 3 rows
            self.assertLessEqual(len(rows), 3)
            # was_bounded should be True since file exceeded cap
            self.assertTrue(was_bounded, "File with 10 rows should be bounded at cap of 3")
            # All returned rows should be valid data rows, not the header
            for row in rows:
                # If this were a header, it would equal BASE_CSV_HEADER
                self.assertNotEqual(row, auto_label.BASE_CSV_HEADER)
        finally:
            config.AUTO_LABEL_MAX_QUEUE_ROWS = original_max_rows

    def test_trim_without_models_actually_trims_overflow_file(self):
        # Write a file significantly over the cap
        with open(self.capture_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(auto_label.BASE_CSV_HEADER)
            for t in range(1, 21):  # 20 data rows
                w.writerow(self._row(float(t)))

        original_max_rows = config.AUTO_LABEL_MAX_QUEUE_ROWS
        config.AUTO_LABEL_MAX_QUEUE_ROWS = 5  # cap << 20 rows
        try:
            # Trim the file
            dropped = auto_label._trim_capture_file_only(self.capture_path)

            # Read it back: should have header + at most 5 data rows
            with open(self.capture_path, newline="") as f:
                all_rows = list(csv.reader(f))

            # Verify header is real header
            self.assertEqual(all_rows[0], auto_label.BASE_CSV_HEADER)

            # Verify file was actually trimmed (not all 20 rows still there)
            # The deque would have bounded the read to 5 rows, was_bounded=True,
            # so _trim_capture_file_only should have rewritten the file.
            # Should have header + at most 5 data rows = at most 6 total
            self.assertLessEqual(len(all_rows), 6, "File should have been trimmed to cap")

            # Verify the kept rows are the newest ones (highest timestamps)
            data_rows = all_rows[1:]
            if len(data_rows) > 0:
                timestamps = [float(r[auto_label.TIMESTAMP_COL]) for r in data_rows]
                # The newest rows should have the highest timestamp values
                # (deque keeps the last N items read)
                self.assertGreater(min(timestamps), 15, "Should keep newest rows")
        finally:
            config.AUTO_LABEL_MAX_QUEUE_ROWS = original_max_rows


class ProcessCaptureFileTrimsOvercapWhenNoRowsLabelTests(unittest.TestCase):
    """Regression test: _process_capture_file must trim oversized files even when
    labeled_count == 0 (no row clears the delay/confidence gates). Previously,
    was_bounded was unpacked but not used in the rewrite condition."""

    class _FakeConfidentModel:
        """Model that always returns Normal, so no rows get labeled."""
        classes_ = np.array([0, 1, 2])

        def predict_proba(self, features_df):
            # Highest confidence on Normal (class 0), so all rows are labeled "Normal"
            return np.array([[0.95, 0.03, 0.02]])

    def _row(self, timestamp):
        return ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                "0.9", "0.1", "0.1", str(timestamp), ""]

    def setUp(self):
        self.capture_path = temp_path(".csv")
        os.unlink(self.capture_path)
        self.labeled_path = temp_path(".csv")
        os.unlink(self.labeled_path)

    def tearDown(self):
        unlink(self.capture_path, self.labeled_path)

    def test_process_capture_file_trims_overcap_file_even_with_zero_labeled_count(self):
        # Write a file significantly over the cap, with recent timestamps so no row clears the delay
        original_max_rows = config.AUTO_LABEL_MAX_QUEUE_ROWS
        config.AUTO_LABEL_MAX_QUEUE_ROWS = 5
        # Use a recent timestamp (just now) so it fails the delay check (< 24 hours old)
        now = time.time()
        recent_timestamp = str(now)
        try:
            with open(self.capture_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(auto_label.BASE_CSV_HEADER)
                for t in range(1, 21):  # 20 data rows
                    w.writerow(self._row(recent_timestamp))

            # Verify file is oversized before
            with open(self.capture_path) as f:
                lines_before = len(list(csv.reader(f)))
            self.assertGreater(lines_before, 6)  # header + > 5 data rows

            # Call _process_capture_file with models that return Normal for everything
            # Rows won't be eligible (too young for the delay) so labeled_count will be 0,
            # but was_bounded=True should still trigger rewrite
            model_mtimes = [now, now]
            labeled_count = auto_label._process_capture_file(
                self.capture_path, self._FakeConfidentModel(), self._FakeConfidentModel(),
                model_mtimes, self.labeled_path,
            )

            # No rows should have been labeled (all are ineligible due to delay)
            self.assertEqual(labeled_count, 0)

            # But the file on disk should have been trimmed anyway (was_bounded check)
            with open(self.capture_path) as f:
                lines_after = len(list(csv.reader(f)))

            # Should be trimmed to header + at most 5 data rows = at most 6 lines
            self.assertLessEqual(lines_after, 6,
                               f"File should be trimmed to cap even with labeled_count=0: "
                               f"{lines_before} lines before, {lines_after} after, cap={original_max_rows}")
        finally:
            config.AUTO_LABEL_MAX_QUEUE_ROWS = original_max_rows


class ReadRowsWasBoundedHeuristicTests(unittest.TestCase):
    """Verify was_bounded correctly distinguishes 'exactly at cap' from 'over cap'."""

    def _row(self, timestamp):
        return ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                "0.9", "0.1", "0.1", str(timestamp), ""]

    def setUp(self):
        self.capture_path = temp_path(".csv")
        os.unlink(self.capture_path)

    def tearDown(self):
        unlink(self.capture_path)

    def test_exactly_at_cap_rows_returns_was_bounded_false(self):
        # Write a file with exactly the cap's worth of rows
        original_max_rows = config.AUTO_LABEL_MAX_QUEUE_ROWS
        config.AUTO_LABEL_MAX_QUEUE_ROWS = 5
        try:
            with open(self.capture_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(auto_label.BASE_CSV_HEADER)
                for t in range(1, 6):  # exactly 5 data rows = exactly cap
                    w.writerow(self._row(float(t)))

            header, rows, was_bounded = auto_label._read_rows(self.capture_path)
            self.assertEqual(len(rows), 5)
            self.assertFalse(was_bounded, "File at exactly cap should not be marked as bounded")
        finally:
            config.AUTO_LABEL_MAX_QUEUE_ROWS = original_max_rows

    def test_one_over_cap_rows_returns_was_bounded_true(self):
        # Write a file with one more than the cap's worth of rows
        original_max_rows = config.AUTO_LABEL_MAX_QUEUE_ROWS
        config.AUTO_LABEL_MAX_QUEUE_ROWS = 5
        try:
            with open(self.capture_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(auto_label.BASE_CSV_HEADER)
                for t in range(1, 7):  # 6 data rows = cap + 1
                    w.writerow(self._row(float(t)))

            header, rows, was_bounded = auto_label._read_rows(self.capture_path)
            # Deque keeps at most 5 rows
            self.assertLessEqual(len(rows), 5)
            self.assertTrue(was_bounded, "File over cap should be marked as bounded")
        finally:
            config.AUTO_LABEL_MAX_QUEUE_ROWS = original_max_rows


class FileLockingTests(unittest.TestCase):
    """Test that file locking is actually acquired in critical sections."""

    def test_process_capture_file_acquires_lock(self):
        """Verify fcntl.flock is called with LOCK_EX in _process_capture_file."""
        import unittest.mock as mock

        # Create a minimal fake model
        class FakeModel:
            classes_ = [0, 1, 2]
            n_jobs = 1
            def predict_proba(self, df):
                return [[0.01, 0.02, 0.97]]

        capture_path = temp_path(".csv")
        os.unlink(capture_path)
        labeled_path = temp_path(".csv")
        os.unlink(labeled_path)

        try:
            # Write a valid capture file
            with open(capture_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(auto_label.BASE_CSV_HEADER)
                w.writerow(["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                           "0.9", "0.1", "0.1", "1000000.0", ""])

            with mock.patch("fcntl.flock") as mock_flock:
                # Call _process_capture_file with fake models
                auto_label._process_capture_file(
                    capture_path, FakeModel(), FakeModel(),
                    [time.time(), time.time()], labeled_path,
                )

                # Verify fcntl.flock was called with LOCK_EX
                lock_calls = [c for c in mock_flock.call_args_list
                             if len(c[0]) >= 2 and c[0][1] == fcntl.LOCK_EX]
                self.assertGreater(len(lock_calls), 0,
                                 "fcntl.flock should be called with LOCK_EX")
        finally:
            unlink(capture_path, labeled_path)

    def test_append_csv_row_acquires_lock(self):
        """Verify fcntl.flock is called with LOCK_EX in _append_csv_row."""
        import unittest.mock as mock

        capture_path = temp_path(".csv")
        os.unlink(capture_path)

        try:
            with mock.patch("fcntl.flock") as mock_flock:
                # Call _append_csv_row
                ipc_receiver._append_csv_row(
                    capture_path, ipc_receiver.PRETRAINING_CSV_HEADER,
                    ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                     "0.9", "0.1", "0.1", "1000000.0", ""],
                )

                # Verify fcntl.flock was called with LOCK_EX
                lock_calls = [c for c in mock_flock.call_args_list
                             if len(c[0]) >= 2 and c[0][1] == fcntl.LOCK_EX]
                self.assertGreater(len(lock_calls), 0,
                                 "fcntl.flock should be called with LOCK_EX")
        finally:
            unlink(capture_path)


if __name__ == "__main__":
    unittest.main()
