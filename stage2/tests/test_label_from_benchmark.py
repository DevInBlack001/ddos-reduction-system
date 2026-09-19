import csv
import os
import shutil
import sys
import tempfile
import unittest

import _support  # noqa: F401

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))
import label_from_benchmark as lfb  # noqa: E402

START = lfb.parse_boundary_time("2026-09-19 12:00:00")


def row(ts, entropy="0.9"):
    return [entropy, "100.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.2",
            "0.9", "0.0", "0.0", f"{ts:.3f}", ""]


class PhaseLabelTests(unittest.TestCase):
    def test_attack_traffic_makes_the_phase_ddos_even_with_legitimate_traffic(self):
        self.assertEqual(lfb.phase_label({"normal", "flashcrowd", "attack"}), 2)

    def test_flash_crowd_without_attack_is_flash_crowd(self):
        self.assertEqual(lfb.phase_label({"normal", "flashcrowd"}), 1)

    def test_normal_alone_is_normal(self):
        self.assertEqual(lfb.phase_label({"normal"}), 0)

    def test_no_traffic_gives_no_label(self):
        self.assertIsNone(lfb.phase_label(set()))


class RunDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "phase_boundaries.tsv"), "w") as f:
            f.write("session_start\t2026-09-19 12:00:00.000000\n")
            f.write("normal\t2026-09-19 12:00:00.000000\n")
            f.write("hot_crowd\t2026-09-19 12:03:00.000000\n")
            f.write("gap\t2026-09-19 12:06:00.000000\n")
            f.write("session_end\t2026-09-19 12:06:30.000000\n")
        with open(os.path.join(self.dir, "traffic_variants.tsv"), "w") as f:
            f.write("normal\tnormal\tbaseline\tSmooth browsing\n")
            f.write("hot_crowd\tnormal\tbursty\tBursty polling\n")
            f.write("hot_crowd\tflashcrowd\thot\tOne source far above the rest\n")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_each_traffic_phase_gets_its_label_and_a_gap_is_skipped(self):
        phases = lfb.load_phases(self.dir, margin_secs=15)
        self.assertEqual([(p[3], p[2]) for p in phases], [("normal", 0), ("hot_crowd", 1)])

    def test_the_margin_is_trimmed_from_both_ends(self):
        start, end, _, _ = lfb.load_phases(self.dir, margin_secs=15)[0]
        self.assertEqual(start, START + 15)
        self.assertEqual(end, START + 180 - 15)

    def test_a_phase_shorter_than_twice_the_margin_is_dropped(self):
        self.assertEqual(lfb.load_phases(self.dir, margin_secs=100), [])


class LabelRowsTests(unittest.TestCase):
    def setUp(self):
        self.phases = [
            (START + 15, START + 165, 0, "normal"),
            (START + 195, START + 345, 1, "hot_crowd"),
            (START + 375, START + 525, 2, "attacker"),
        ]

    def test_rows_take_the_label_of_the_phase_they_fall_in(self):
        rows = [row(START + 20), row(START + 200)]
        labeled, counts = lfb.label_rows(rows, self.phases, {0, 1, 2})
        self.assertEqual([r[lfb.LABEL_COL] for r in labeled], ["0", "1"])
        self.assertEqual(counts, {"normal": 1, "hot_crowd": 1})

    def test_rows_in_the_margin_or_between_phases_are_left_out(self):
        rows = [row(START + 5), row(START + 170), row(START + 360)]
        labeled, _ = lfb.label_rows(rows, self.phases, {0, 1, 2})
        self.assertEqual(labeled, [])

    def test_ddos_rows_are_only_written_when_asked_for(self):
        rows = [row(START + 400)]
        self.assertEqual(lfb.label_rows(rows, self.phases, {0, 1})[0], [])
        self.assertEqual(len(lfb.label_rows(rows, self.phases, {0, 1, 2})[0]), 1)

    def test_a_window_present_in_two_captures_is_written_once(self):
        rows = [row(START + 200), row(START + 200)]
        labeled, _ = lfb.label_rows(rows, self.phases, {1})
        self.assertEqual(len(labeled), 1)


class ReadCaptureRowsTests(unittest.TestCase):
    def test_sixteen_column_rows_are_cut_to_the_base_columns_and_torn_rows_skipped(self):
        path = tempfile.mktemp(suffix=".csv")
        header = lfb.BASE_CSV_HEADER + ["victim_ip", "if_score", "rf_verdict"]
        good = row(START + 20) + ["192.0.2.10", "-0.01", "Normal"]
        torn = row(START + 21) + row(START + 22)
        bad_time = row(START + 23)
        bad_time[lfb.TIMESTAMP_COL] = "soon"
        bad_time += ["192.0.2.10", "-0.01", "Normal"]
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows([good, torn, bad_time])
        try:
            rows = lfb.read_capture_rows(path)
        finally:
            os.unlink(path)
        self.assertEqual(rows, [row(START + 20)])


if __name__ == "__main__":
    unittest.main()
