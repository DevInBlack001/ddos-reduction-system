"""Tests for ipc_receiver.py's Anomalous capture writer."""

import csv
import os
import socket
import unittest

import _support
from _support import temp_path, unlink

import config
import ipc_receiver
from ipc_receiver import apply_safety_overrides

FEATURES = dict(
    entropy=0.98, ewma_rate=24.5, mean_h=0.97, mean_r=20.1,
    sigma_h=0.09, sigma_r=7.5, proto_ratio=1.0,
    dominant_ip_ratio=0.15, source_port_entropy=0.99,
    ttl_variance=0.0, fingerprint_diversity=0.0,
    timestamp=1787740000.123,
)

CFG = config.DEFAULT_ENFORCEMENT_CONFIG


class ApplySafetyOverridesTests(unittest.TestCase):
    """apply_safety_overrides must never be gated on is_warmup: it takes no
    such argument, by construction, so a caller cannot silently disable it
    the way the pre-fix inline block was accidentally disabled during
    Stage 1's warm-up period."""

    def test_ordinary_traffic_under_the_rate_boundary_stays_normal(self):
        result, _boundary = apply_safety_overrides(
            pred_class=0, ewma_rate=20.0, mean_r=20.0, sigma_r=7.1,
            mean_h=0.98, sigma_h=0.05, dominant_rate=3.0, entropy=0.98,
            dominant_ip_ratio=0.1, k_multiplier=2.0, cfg=CFG,
        )
        self.assertEqual(result, 0)

    def test_an_extreme_single_source_rate_forces_ddos_regardless_of_the_models_own_verdict(self):
        # Mirrors a real warm-up window: raw, unclamped, noisy sigma_r, the
        # exact shape of the data the pre-fix code stopped evaluating.
        result, _boundary = apply_safety_overrides(
            pred_class=0, ewma_rate=5000.0, mean_r=20.0, sigma_r=1.0,
            mean_h=0.5, sigma_h=0.05, dominant_rate=4800.0, entropy=0.9,
            dominant_ip_ratio=0.2, k_multiplier=2.0, cfg=CFG,
        )
        self.assertEqual(result, 2)

    def test_concentrated_traffic_above_the_rate_boundary_forces_ddos_on_entropy_alone(self):
        result, _boundary = apply_safety_overrides(
            pred_class=0, ewma_rate=500.0, mean_r=20.0, sigma_r=7.1,
            mean_h=0.98, sigma_h=0.05, dominant_rate=100.0, entropy=0.1,
            dominant_ip_ratio=0.3, k_multiplier=2.0, cfg=CFG,
        )
        self.assertEqual(result, 2)

    def test_a_diverse_surge_above_the_rate_boundary_is_flash_crowd_not_ddos(self):
        result, _boundary = apply_safety_overrides(
            pred_class=0, ewma_rate=500.0, mean_r=20.0, sigma_r=7.1,
            mean_h=0.98, sigma_h=0.05, dominant_rate=10.0, entropy=0.97,
            dominant_ip_ratio=0.05, k_multiplier=2.0, cfg=CFG,
        )
        self.assertEqual(result, 1)

    def test_the_returned_boundary_matches_tier_2s_own_block_bar_formula(self):
        # ipc_receiver.py's Tier 2 enforcement reuses this exact return
        # value as its per-source block_threshold, rather than
        # recomputing it, specifically so the two can never drift apart.
        # This pins the contract: a caller unpacking only the first value
        # (as a bare `pred_class = apply_safety_overrides(...)` once did)
        # is a regression this test catches, not just a runtime NameError
        # three hundred lines away the next time Tier 2 actually fires.
        mean_r, sigma_r = 20.0, 7.1
        _result, boundary = apply_safety_overrides(
            pred_class=0, ewma_rate=20.0, mean_r=mean_r, sigma_r=sigma_r,
            mean_h=0.98, sigma_h=0.05, dominant_rate=3.0, entropy=0.98,
            dominant_ip_ratio=0.1, k_multiplier=2.0, cfg=CFG,
        )
        expected = max(CFG["block_rate_floor_pps"], mean_r + CFG["block_sigma_multiplier"] * sigma_r)
        self.assertEqual(boundary, expected)

    def test_an_existing_ddos_verdict_from_the_model_is_left_untouched(self):
        # pred_class == 2 is excluded from the "in (0, 1)" gate on purpose:
        # an override cannot downgrade a verdict the model already escalated.
        result, _boundary = apply_safety_overrides(
            pred_class=2, ewma_rate=20.0, mean_r=20.0, sigma_r=7.1,
            mean_h=0.98, sigma_h=0.05, dominant_rate=3.0, entropy=0.98,
            dominant_ip_ratio=0.1, k_multiplier=2.0, cfg=CFG,
        )
        self.assertEqual(result, 2)


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


class PeerUidTests(unittest.TestCase):
    """The IPC socket's defence in depth against a connection from an
    unexpected local account: SO_PEERCRED reports the real, kernel
    verified UID of whoever is on the other end of the socket, not
    something a connecting process can spoof by claiming to be someone
    else."""

    def test_reports_this_processes_own_uid_over_a_real_socket_pair(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.assertEqual(ipc_receiver._peer_uid(a), os.getuid())
            self.assertEqual(ipc_receiver._peer_uid(b), os.getuid())
        finally:
            a.close()
            b.close()

    def test_returns_none_on_a_closed_socket_rather_than_raising(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        a.close()
        b.close()
        self.assertIsNone(ipc_receiver._peer_uid(a))


if __name__ == "__main__":
    unittest.main()
