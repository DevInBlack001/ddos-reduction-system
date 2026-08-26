"""Tests for ipc_receiver.py's Anomalous capture writer."""

import csv
import os
import unittest

import _support
from _support import temp_path, unlink

import config
import ipc_receiver

FEATURES = dict(
    entropy=0.98, ewma_rate=24.5, mean_h=0.97, mean_r=20.1,
    sigma_h=0.09, sigma_r=7.5, proto_ratio=1.0,
    dominant_ip_ratio=0.15, source_port_entropy=0.99,
    ttl_variance=0.0, fingerprint_diversity=0.0,
    timestamp=1787740000.123,
)


class WriteAnomalousRowTests(unittest.TestCase):
    def setUp(self):
        self.path = temp_path(".csv")
        os.unlink(self.path)  # start from "file does not exist"
        self.original_path = config.ANOMALOUS_CSV_PATH
        config.ANOMALOUS_CSV_PATH = self.path

    def tearDown(self):
        config.ANOMALOUS_CSV_PATH = self.original_path
        unlink(self.path)

    def _rows(self):
        with open(self.path) as handle:
            return list(csv.reader(handle))

    def test_creates_the_file_on_the_first_flagged_window(self):
        ipc_receiver._write_anomalous_row("192.0.2.10", -0.05, "Normal", **FEATURES)
        self.assertTrue(os.path.exists(self.path))

    def test_the_first_thirteen_columns_match_trainingcsvs_own_order(self):
        ipc_receiver._write_anomalous_row("192.0.2.10", -0.05, "Normal", **FEATURES)
        header = self._rows()[0]
        self.assertEqual(header[:13], [
            "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
            "proto_ratio", "dominant_ip_ratio", "source_port_entropy",
            "ttl_variance", "fingerprint_diversity", "timestamp", "label",
        ])

    def test_the_label_column_is_left_blank_for_a_human_to_fill_in(self):
        ipc_receiver._write_anomalous_row("192.0.2.10", -0.05, "Normal", **FEATURES)
        row = self._rows()[1]
        self.assertEqual(row[12], "")

    def test_context_columns_carry_the_victim_score_and_rf_verdict(self):
        ipc_receiver._write_anomalous_row("192.0.2.10", -0.0421, "Flash Crowd", **FEATURES)
        row = self._rows()[1]
        self.assertEqual(row[13], "192.0.2.10")
        self.assertEqual(row[14], "-0.0421")
        self.assertEqual(row[15], "Flash Crowd")

    def test_the_header_is_written_once_not_on_every_row(self):
        ipc_receiver._write_anomalous_row("192.0.2.10", -0.05, "Normal", **FEATURES)
        ipc_receiver._write_anomalous_row("192.0.2.11", -0.06, "Flash Crowd", **FEATURES)
        rows = self._rows()
        self.assertEqual(len(rows), 3)  # header + two data rows
        self.assertNotEqual(rows[1][13], "entropy")

    def test_a_second_flagged_window_appends_rather_than_overwriting(self):
        ipc_receiver._write_anomalous_row("192.0.2.10", -0.05, "Normal", **FEATURES)
        ipc_receiver._write_anomalous_row("192.0.2.11", -0.06, "Flash Crowd", **FEATURES)
        rows = self._rows()
        self.assertEqual(rows[1][13], "192.0.2.10")
        self.assertEqual(rows[2][13], "192.0.2.11")


if __name__ == "__main__":
    unittest.main()
