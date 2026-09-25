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


class ReviewStagedRowsPaginationTests(AutoLabelReviewTestCase):
    def _stage_numbered(self, count):
        rows = [self._row(timestamp=str(1000000.0 + i)) for i in range(count)]
        self._stage_rows(rows)
        return rows

    def test_the_first_page_has_no_previous_and_a_next_when_more_remain(self):
        limit = auto_label_review.REVIEW_ROW_LIMIT
        self._stage_numbered(limit + 5)
        result = auto_label_review.review_staged_rows()
        self.assertEqual(result["offset"], 0)
        self.assertFalse(result["has_prev"])
        self.assertTrue(result["has_next"])

    def test_the_second_page_returns_the_remaining_rows(self):
        limit = auto_label_review.REVIEW_ROW_LIMIT
        rows = self._stage_numbered(limit + 5)
        result = auto_label_review.review_staged_rows(offset=limit)
        self.assertEqual(len(result["rows"]), 5)
        self.assertEqual(result["rows"][0][11], rows[limit][11])
        self.assertTrue(result["has_prev"])
        self.assertFalse(result["has_next"])
        self.assertEqual(result["total_rows"], limit + 5)

    def test_pages_do_not_overlap_or_skip_rows(self):
        rows = self._stage_numbered(25)
        seen = []
        offset = 0
        while True:
            page = auto_label_review.review_staged_rows(offset=offset, limit=10)
            seen.extend(r[11] for r in page["rows"])
            if not page["has_next"]:
                break
            offset += 10
        self.assertEqual(seen, [r[11] for r in rows])

    def test_an_offset_past_the_end_returns_no_rows_but_the_real_total(self):
        self._stage_numbered(3)
        result = auto_label_review.review_staged_rows(offset=50)
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["total_rows"], 3)
        self.assertFalse(result["has_next"])

    def test_a_negative_offset_is_refused(self):
        self._stage_numbered(3)
        with self.assertRaises(HTTPException) as ctx:
            auto_label_review.review_staged_rows(offset=-1)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_a_limit_above_the_cap_is_clamped_to_it(self):
        limit = auto_label_review.REVIEW_ROW_LIMIT
        self._stage_numbered(limit + 5)
        result = auto_label_review.review_staged_rows(limit=limit * 10)
        self.assertEqual(len(result["rows"]), limit)
        self.assertEqual(result["limit"], limit)

    def test_a_limit_below_one_is_raised_to_one(self):
        self._stage_numbered(3)
        result = auto_label_review.review_staged_rows(limit=0)
        self.assertEqual(len(result["rows"]), 1)


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


class TrimDdosClassTests(AutoLabelReviewTestCase):
    def test_refuses_when_no_training_csv_is_configured(self):
        with self.assertRaises(HTTPException) as ctx:
            auto_label_review.trim_ddos_class()
        self.assertEqual(ctx.exception.status_code, 400)

    def test_refuses_when_the_training_csv_is_empty(self):
        config.TRAINING_CSV_PATH = self.training_path
        with self.assertRaises(HTTPException) as ctx:
            auto_label_review.trim_ddos_class()
        self.assertEqual(ctx.exception.status_code, 400)

    def test_drops_ddos_rows_down_to_the_smaller_of_the_other_two_classes(self):
        config.TRAINING_CSV_PATH = self.training_path
        # Five separate DDoS sessions (each gap between groups > the 30s
        # session boundary), sized 2/3/2/1/3, so a cap of 3 can be met
        # by keeping one whole session rather than being forced to drop
        # every DDoS row because it's all one undivided session.
        ddos_rows = []
        for group_start, size in [(3000, 2), (3100, 3), (3200, 2), (3300, 1), (3400, 3)]:
            for i in range(size):
                ddos_rows.append(self._row(timestamp=str(group_start + i), label="2"))
        rows = (
            [self._row(timestamp=str(1000 + i), label="0") for i in range(5)]
            + [self._row(timestamp=str(2000 + i), label="1") for i in range(3)]
            + ddos_rows
        )
        _write_csv(self.training_path, auto_label.BASE_CSV_HEADER, rows)

        result = auto_label_review.trim_ddos_class()

        self.assertEqual(result["cap"], 3)
        self.assertGreater(result["dropped"], 0)
        _, kept = _read_csv(self.training_path)
        label_idx = auto_label.BASE_CSV_HEADER.index("label")
        by_label = {}
        for row in kept:
            by_label[row[label_idx]] = by_label.get(row[label_idx], 0) + 1
        self.assertEqual(by_label.get("0"), 5)
        self.assertEqual(by_label.get("1"), 3)
        self.assertGreater(by_label.get("2", 0), 0)
        self.assertLessEqual(by_label.get("2", 0), 3)

    def test_never_fragments_a_ddos_session_it_keeps(self):
        # A kept session's rows must all survive together; this asserts
        # that directly rather than only checking the total count, since
        # a bug that dropped scattered rows from within a session could
        # still land under the row-count cap by coincidence.
        config.TRAINING_CSV_PATH = self.training_path
        ddos_rows = [
            self._row(timestamp="3000", label="2"),
            self._row(timestamp="3001", label="2"),
            self._row(timestamp="3100", label="2"),
        ]
        rows = (
            [self._row(timestamp=str(1000 + i), label="0") for i in range(2)]
            + [self._row(timestamp=str(2000 + i), label="1") for i in range(2)]
            + ddos_rows
        )
        _write_csv(self.training_path, auto_label.BASE_CSV_HEADER, rows)

        auto_label_review.trim_ddos_class()

        _, kept = _read_csv(self.training_path)
        kept_ts = {row[auto_label.TIMESTAMP_COL] for row in kept if row[auto_label.BASE_CSV_HEADER.index("label")] == "2"}
        # The 2-row session (3000, 3001) is either entirely present or
        # entirely absent, never just one of the two.
        self.assertEqual("3000" in kept_ts, "3001" in kept_ts)

    def test_reports_nothing_dropped_when_already_under_the_cap(self):
        config.TRAINING_CSV_PATH = self.training_path
        rows = (
            [self._row(timestamp=str(1000 + i), label="0") for i in range(5)]
            + [self._row(timestamp=str(2000 + i), label="1") for i in range(5)]
            + [self._row(timestamp=str(3000 + i), label="2") for i in range(2)]
        )
        _write_csv(self.training_path, auto_label.BASE_CSV_HEADER, rows)

        result = auto_label_review.trim_ddos_class()

        self.assertEqual(result["dropped"], 0)
        _, kept = _read_csv(self.training_path)
        self.assertEqual(len(kept), 12)


if __name__ == "__main__":
    unittest.main()
