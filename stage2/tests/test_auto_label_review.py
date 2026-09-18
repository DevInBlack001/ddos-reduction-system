"""Tests for auto_label_review.py, the dashboard's review queue for
auto_label.py's staged output."""

import csv
import sqlite3
import unittest

from fastapi import HTTPException

import _support
from _support import make_logs_db, reset_db_module, temp_path, unlink

import config
import db
import auto_label
import auto_label_review


def _write_csv(path, header, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _read_csv(path):
    with open(path, newline="") as f:
        r = csv.reader(f)
        header = next(r)
        return header, list(r)


class AutoLabelReviewTestCase(unittest.TestCase):
    """Shared fixture: a real schema-applied database and swapped config
    paths so nothing here touches a real deployment's files."""

    def setUp(self):
        self._db_path = config.DB_PATH
        self._staged_path = config.AUTO_LABELED_CSV_PATH
        self._training_path = config.TRAINING_CSV_PATH

        self.db_path = make_logs_db()
        config.DB_PATH = self.db_path
        reset_db_module()

        self.staged_path = temp_path(".csv")
        unlink(self.staged_path)
        config.AUTO_LABELED_CSV_PATH = self.staged_path

        self.training_path = temp_path(".csv")
        unlink(self.training_path)
        config.TRAINING_CSV_PATH = ""

    def tearDown(self):
        reset_db_module()
        config.DB_PATH = self._db_path
        config.AUTO_LABELED_CSV_PATH = self._staged_path
        config.TRAINING_CSV_PATH = self._training_path
        unlink(self.db_path, self.staged_path, self.training_path)

    def _stage_rows(self, rows):
        _write_csv(self.staged_path, auto_label.BASE_CSV_HEADER, rows)

    def _row(self, timestamp="1000000.0", label="0"):
        return ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                "0.9", "0.1", "0.1", timestamp, label]


class ListPendingRunsTests(AutoLabelReviewTestCase):
    def test_no_runs_yet(self):
        result = auto_label_review.list_pending_runs()
        self.assertEqual(result["runs"], [])
        self.assertFalse(result["training_csv_configured"])

    def test_lists_unresolved_runs_newest_first(self):
        db.record_auto_label_run(1000.0, 5)
        db.record_auto_label_run(2000.0, 9)
        result = auto_label_review.list_pending_runs()
        self.assertEqual([r["timestamp"] for r in result["runs"]], [2000.0, 1000.0])
        self.assertEqual([r["rows_labeled"] for r in result["runs"]], [9, 5])

    def test_resolved_runs_are_not_listed(self):
        db.record_auto_label_run(1000.0, 5)
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE auto_label_runs SET resolved = 1")
        conn.commit()
        conn.close()
        result = auto_label_review.list_pending_runs()
        self.assertEqual(result["runs"], [])

    def test_reports_whether_the_training_csv_is_configured(self):
        config.TRAINING_CSV_PATH = self.training_path
        result = auto_label_review.list_pending_runs()
        self.assertTrue(result["training_csv_configured"])


class ReviewStagedRowsTests(AutoLabelReviewTestCase):
    def test_nothing_staged(self):
        result = auto_label_review.review_staged_rows()
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["total_rows"], 0)
        self.assertFalse(result["truncated"])

    def test_returns_staged_rows_and_header(self):
        self._stage_rows([self._row(), self._row(timestamp="2000000.0")])
        result = auto_label_review.review_staged_rows()
        self.assertEqual(result["header"], auto_label.BASE_CSV_HEADER)
        self.assertEqual(len(result["rows"]), 2)
        self.assertEqual(result["total_rows"], 2)
        self.assertFalse(result["truncated"])

    def test_bounds_the_response_and_reports_truncation(self):
        rows = [self._row(timestamp=str(1000000.0 + i)) for i in range(auto_label_review.REVIEW_ROW_LIMIT + 5)]
        self._stage_rows(rows)
        result = auto_label_review.review_staged_rows()
        self.assertEqual(len(result["rows"]), auto_label_review.REVIEW_ROW_LIMIT)
        self.assertEqual(result["total_rows"], len(rows))
        self.assertTrue(result["truncated"])


class MergeStagedRowsTests(AutoLabelReviewTestCase):
    def test_refuses_when_no_training_csv_is_configured(self):
        self._stage_rows([self._row()])
        with self.assertRaises(HTTPException) as ctx:
            auto_label_review.merge_staged_rows()
        self.assertEqual(ctx.exception.status_code, 400)

    def test_refuses_when_nothing_is_staged(self):
        config.TRAINING_CSV_PATH = self.training_path
        with self.assertRaises(HTTPException) as ctx:
            auto_label_review.merge_staged_rows()
        self.assertEqual(ctx.exception.status_code, 400)

    def test_appends_staged_rows_into_a_new_training_csv(self):
        config.TRAINING_CSV_PATH = self.training_path
        self._stage_rows([self._row(), self._row(timestamp="2000000.0")])
        result = auto_label_review.merge_staged_rows()
        self.assertEqual(result["merged"], 2)
        header, rows = _read_csv(self.training_path)
        self.assertEqual(header, auto_label.BASE_CSV_HEADER)
        self.assertEqual(len(rows), 2)

    def test_appends_after_existing_rows_in_a_real_training_csv(self):
        config.TRAINING_CSV_PATH = self.training_path
        _write_csv(self.training_path, auto_label.BASE_CSV_HEADER, [self._row(timestamp="1.0")])
        self._stage_rows([self._row(timestamp="2000000.0")])
        auto_label_review.merge_staged_rows()
        header, rows = _read_csv(self.training_path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][auto_label.TIMESTAMP_COL], "1.0")
        self.assertEqual(rows[1][auto_label.TIMESTAMP_COL], "2000000.0")

    def test_clears_the_staged_file_after_a_merge(self):
        config.TRAINING_CSV_PATH = self.training_path
        self._stage_rows([self._row()])
        auto_label_review.merge_staged_rows()
        header, rows = _read_csv(self.staged_path)
        self.assertEqual(rows, [])

    def test_resolves_pending_runs_after_a_merge(self):
        config.TRAINING_CSV_PATH = self.training_path
        self._stage_rows([self._row()])
        db.record_auto_label_run(1000.0, 1)
        auto_label_review.merge_staged_rows()
        self.assertEqual(auto_label_review.list_pending_runs()["runs"], [])


class DiscardStagedRowsTests(AutoLabelReviewTestCase):
    def test_refuses_when_nothing_is_staged(self):
        with self.assertRaises(HTTPException) as ctx:
            auto_label_review.discard_staged_rows()
        self.assertEqual(ctx.exception.status_code, 400)

    def test_clears_the_staged_file_without_touching_training_data(self):
        config.TRAINING_CSV_PATH = self.training_path
        _write_csv(self.training_path, auto_label.BASE_CSV_HEADER, [self._row(timestamp="1.0")])
        self._stage_rows([self._row(timestamp="2000000.0")])

        result = auto_label_review.discard_staged_rows()

        self.assertEqual(result["discarded"], 1)
        _, staged_rows = _read_csv(self.staged_path)
        self.assertEqual(staged_rows, [])
        _, training_rows = _read_csv(self.training_path)
        self.assertEqual(len(training_rows), 1)
        self.assertEqual(training_rows[0][auto_label.TIMESTAMP_COL], "1.0")

    def test_resolves_pending_runs_after_a_discard(self):
        self._stage_rows([self._row()])
        db.record_auto_label_run(1000.0, 1)
        auto_label_review.discard_staged_rows()
        self.assertEqual(auto_label_review.list_pending_runs()["runs"], [])


if __name__ == "__main__":
    unittest.main()
