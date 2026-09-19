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

    def test_a_zero_traffic_window_is_not_captured(self):
        idle = dict(FEATURES, entropy=0.0, proto_ratio=0.0, dominant_ip_ratio=0.0,
                    source_port_entropy=0.0, ttl_variance=0.0, fingerprint_diversity=0.0)
        ipc_receiver._write_anomalous_row("192.0.2.10", -0.05, "Normal", **idle)
        self.assertFalse(os.path.exists(self.path))

    def test_a_window_with_any_traffic_signal_is_still_captured(self):
        quiet = dict(FEATURES, entropy=0.0, proto_ratio=0.0, dominant_ip_ratio=0.0,
                     source_port_entropy=0.0, ttl_variance=0.0, fingerprint_diversity=0.0)
        quiet["proto_ratio"] = 1.0
        ipc_receiver._write_anomalous_row("192.0.2.10", -0.05, "Normal", **quiet)
        self.assertTrue(os.path.exists(self.path))

    def test_a_second_flagged_window_appends_rather_than_overwriting(self):
        ipc_receiver._write_anomalous_row("192.0.2.10", -0.05, "Normal", **FEATURES)
        ipc_receiver._write_anomalous_row("192.0.2.11", -0.06, "Flash Crowd", **FEATURES)
        rows = self._rows()
        self.assertEqual(rows[1][13], "192.0.2.10")
        self.assertEqual(rows[2][13], "192.0.2.11")


class WritePretrainingRowTests(unittest.TestCase):
    def setUp(self):
        self.path = temp_path(".csv")
        os.unlink(self.path)  # start from "file does not exist"
        self.original_path = config.PRETRAINING_CSV_PATH
        config.PRETRAINING_CSV_PATH = self.path

    def tearDown(self):
        config.PRETRAINING_CSV_PATH = self.original_path
        unlink(self.path)

    def _rows(self):
        with open(self.path) as handle:
            return list(csv.reader(handle))

    def test_creates_the_file_on_the_first_cold_start_window(self):
        ipc_receiver._write_pretraining_row(**FEATURES)
        self.assertTrue(os.path.exists(self.path))

    def test_the_thirteen_columns_match_trainingcsvs_own_order(self):
        ipc_receiver._write_pretraining_row(**FEATURES)
        header = self._rows()[0]
        self.assertEqual(header, [
            "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
            "proto_ratio", "dominant_ip_ratio", "source_port_entropy",
            "ttl_variance", "fingerprint_diversity", "timestamp", "label",
        ])

    def test_the_label_column_is_left_blank(self):
        ipc_receiver._write_pretraining_row(**FEATURES)
        row = self._rows()[1]
        self.assertEqual(row[12], "")

    def test_a_second_cold_start_window_appends_rather_than_overwriting(self):
        ipc_receiver._write_pretraining_row(**FEATURES)
        ipc_receiver._write_pretraining_row(**FEATURES)
        rows = self._rows()
        self.assertEqual(len(rows), 3)  # header + two data rows


class WriteDdosCaptureRowTests(unittest.TestCase):
    def setUp(self):
        self.path = temp_path(".csv")
        os.unlink(self.path)  # start from "file does not exist"
        self.original_path = config.DDOS_CAPTURE_CSV_PATH
        config.DDOS_CAPTURE_CSV_PATH = self.path

    def tearDown(self):
        config.DDOS_CAPTURE_CSV_PATH = self.original_path
        unlink(self.path)

    def _rows(self):
        with open(self.path) as handle:
            return list(csv.reader(handle))

    def test_creates_the_file_on_the_first_confident_ddos_window(self):
        ipc_receiver._write_ddos_capture_row(**FEATURES)
        self.assertTrue(os.path.exists(self.path))

    def test_the_thirteen_columns_match_trainingcsvs_own_order(self):
        ipc_receiver._write_ddos_capture_row(**FEATURES)
        header = self._rows()[0]
        self.assertEqual(header, [
            "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
            "proto_ratio", "dominant_ip_ratio", "source_port_entropy",
            "ttl_variance", "fingerprint_diversity", "timestamp", "label",
        ])

    def test_the_label_column_is_left_blank(self):
        ipc_receiver._write_ddos_capture_row(**FEATURES)
        row = self._rows()[1]
        self.assertEqual(row[12], "")

    def test_a_second_confident_ddos_window_appends_rather_than_overwriting(self):
        ipc_receiver._write_ddos_capture_row(**FEATURES)
        ipc_receiver._write_ddos_capture_row(**FEATURES)
        rows = self._rows()
        self.assertEqual(len(rows), 3)  # header + two data rows


class ShouldCapturePretrainingRowTests(unittest.TestCase):
    def test_true_when_no_random_forest_model_is_loaded_and_not_warming_up(self):
        self.assertTrue(ipc_receiver._should_capture_pretraining_row(clf=None, is_warmup=False))

    def test_false_during_warmup_even_with_no_model(self):
        self.assertFalse(ipc_receiver._should_capture_pretraining_row(clf=None, is_warmup=True))

    def test_false_once_a_random_forest_model_is_loaded(self):
        self.assertFalse(ipc_receiver._should_capture_pretraining_row(clf=object(), is_warmup=False))


class SharedCsvAppendHelperTests(unittest.TestCase):
    """The refactor must not change _write_anomalous_row's own behaviour;
    WriteAnomalousRowTests above already pins its output format, this
    class only pins that all three writers now share one low-level append,
    including the DDoS capture point added to close confidence gated
    automatic labeling's DDoS gap, so a fourth capture point still would
    not need its own copy of it."""

    def test_write_anomalous_row_and_write_pretraining_row_share_the_append_helper(self):
        self.assertIs(ipc_receiver._write_anomalous_row.__globals__["_append_csv_row"],
                       ipc_receiver._write_pretraining_row.__globals__["_append_csv_row"])

    def test_write_ddos_capture_row_shares_the_same_append_helper_too(self):
        self.assertIs(ipc_receiver._write_ddos_capture_row.__globals__["_append_csv_row"],
                       ipc_receiver._write_pretraining_row.__globals__["_append_csv_row"])


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


class AppendCsvRowSizeConstraintTests(unittest.TestCase):
    """_append_csv_row enforces PRETRAINING_MAX_BYTES: appends are skipped
    once the file reaches the cap, preventing unbounded growth of cold-start
    capture files."""

    def setUp(self):
        self.path = temp_path(".csv")
        os.unlink(self.path)
        self.original_max_bytes = config.PRETRAINING_MAX_BYTES
        # Use a tiny limit so we can hit it without creating megabyte files
        config.PRETRAINING_MAX_BYTES = 100

    def tearDown(self):
        config.PRETRAINING_MAX_BYTES = self.original_max_bytes
        unlink(self.path)

    def test_skips_append_when_file_is_at_the_size_cap(self):
        # Write a file that exactly matches the cap
        with open(self.path, "w") as f:
            f.write("x" * config.PRETRAINING_MAX_BYTES)

        row_count_before = os.path.getsize(self.path)
        ipc_receiver._append_csv_row(self.path, ipc_receiver.PRETRAINING_CSV_HEADER, ["field1", "field2"])
        row_count_after = os.path.getsize(self.path)

        # File size should not have changed
        self.assertEqual(row_count_before, row_count_after)

    def test_skips_append_when_file_exceeds_the_size_cap(self):
        # Write a file larger than the cap
        with open(self.path, "w") as f:
            f.write("x" * (config.PRETRAINING_MAX_BYTES + 50))

        row_count_before = os.path.getsize(self.path)
        ipc_receiver._append_csv_row(self.path, ipc_receiver.PRETRAINING_CSV_HEADER, ["field1", "field2"])
        row_count_after = os.path.getsize(self.path)

        # File size should not have changed
        self.assertEqual(row_count_before, row_count_after)

    def test_appends_normally_when_file_is_under_the_size_cap(self):
        # Write a small file
        with open(self.path, "w") as f:
            f.write("x" * 50)

        ipc_receiver._append_csv_row(self.path, ipc_receiver.PRETRAINING_CSV_HEADER, ["field1", "field2"])

        # File should have grown
        self.assertGreater(os.path.getsize(self.path), 50)


class LatencyLoggingTests(unittest.TestCase):
    def setUp(self):
        self._interval = config.LATENCY_LOG_INTERVAL_SECS
        self._last = ipc_receiver._latency_log_state["last"]
        ipc_receiver.latency_stats = ipc_receiver.LatencyStats()
        config.LATENCY_LOG_INTERVAL_SECS = 30.0
        ipc_receiver._latency_log_state["last"] = 1000.0

    def tearDown(self):
        config.LATENCY_LOG_INTERVAL_SECS = self._interval
        ipc_receiver._latency_log_state["last"] = self._last

    def test_a_timed_enforcement_call_returns_the_actions_result(self):
        result = ipc_receiver._timed_enforcement(1.0, lambda a, b=0: a + b, 2, b=3)
        self.assertEqual(result, 5)

    def test_a_timed_enforcement_call_records_both_latency_kinds(self):
        ipc_receiver._timed_enforcement(1.0, lambda: None)
        line = ipc_receiver.latency_stats.summary_line(30)
        self.assertIn("enforcement_n=1", line)
        self.assertIn("window_to_rule_n=1", line)

    def test_no_summary_is_logged_before_the_interval_has_passed(self):
        ipc_receiver.latency_stats.record("inference", 1.0)
        with self.assertNoLogs(level="INFO"):
            ipc_receiver._log_latency_if_due(now=1010.0)

    def test_a_summary_is_logged_once_the_interval_has_passed(self):
        ipc_receiver.latency_stats.record("inference", 1.0)
        with self.assertLogs(level="INFO") as captured:
            ipc_receiver._log_latency_if_due(now=1031.0)
        self.assertIn("Latency: summary", captured.output[0])

    def test_an_interval_with_no_windows_logs_nothing(self):
        with self.assertNoLogs(level="INFO"):
            ipc_receiver._log_latency_if_due(now=1031.0)

    def test_an_interval_of_zero_turns_the_summary_off(self):
        config.LATENCY_LOG_INTERVAL_SECS = 0.0
        ipc_receiver.latency_stats.record("inference", 1.0)
        with self.assertNoLogs(level="INFO"):
            ipc_receiver._log_latency_if_due(now=5000.0)


class LoadVictimFlowRatesTests(unittest.TestCase):
    """The flow snapshot covers every protected host and is rewritten about
    every 10 seconds, so enforcement must keep only flows to the window's
    victim and ignore a snapshot that is no longer current."""

    def setUp(self):
        self.path = temp_path(".json")
        self.old_path = config.FLOWS_PATH
        config.FLOWS_PATH = self.path
        self.now = 1_000_000.0

    def tearDown(self):
        config.FLOWS_PATH = self.old_path
        unlink(self.path)

    def _write(self, flows, timestamp):
        import json
        with open(self.path, "w") as f:
            json.dump({"timestamp": timestamp, "active_ips": flows}, f)

    def test_only_flows_to_the_victim_are_counted(self):
        self._write([
            {"ip": "198.51.100.7", "dst": "192.0.2.10", "port": 80, "proto": "TCP", "rate": 30.0},
            {"ip": "198.51.100.8", "dst": "192.0.2.11", "port": 80, "proto": "TCP", "rate": 90.0},
        ], self.now - 2)
        rates = ipc_receiver._load_victim_flow_rates("192.0.2.10", now=self.now)
        self.assertEqual(rates, {"198.51.100.7": 30.0})

    def test_a_source_with_several_flows_to_the_victim_is_summed(self):
        self._write([
            {"ip": "198.51.100.7", "dst": "192.0.2.10", "port": 80, "proto": "TCP", "rate": 30.0},
            {"ip": "198.51.100.7", "dst": "192.0.2.10", "port": 443, "proto": "TCP", "rate": 12.5},
        ], self.now - 2)
        rates = ipc_receiver._load_victim_flow_rates("192.0.2.10", now=self.now)
        self.assertEqual(rates, {"198.51.100.7": 42.5})

    def test_a_snapshot_older_than_the_limit_is_ignored(self):
        self._write([
            {"ip": "198.51.100.7", "dst": "192.0.2.10", "port": 80, "proto": "TCP", "rate": 30.0},
        ], self.now - config.FLOWS_MAX_AGE_SECS - 1)
        self.assertEqual(ipc_receiver._load_victim_flow_rates("192.0.2.10", now=self.now), {})

    def test_a_snapshot_without_a_timestamp_is_ignored(self):
        import json
        with open(self.path, "w") as f:
            json.dump({"active_ips": [
                {"ip": "198.51.100.7", "dst": "192.0.2.10", "port": 80, "proto": "TCP", "rate": 30.0},
            ]}, f)
        self.assertEqual(ipc_receiver._load_victim_flow_rates("192.0.2.10", now=self.now), {})

    def test_a_missing_or_unreadable_file_gives_no_flows(self):
        unlink(self.path)
        self.assertEqual(ipc_receiver._load_victim_flow_rates("192.0.2.10", now=self.now), {})
        with open(self.path, "w") as f:
            f.write("not json")
        self.assertEqual(ipc_receiver._load_victim_flow_rates("192.0.2.10", now=self.now), {})

    def test_placeholder_sources_are_left_out(self):
        self._write([
            {"ip": "0.0.0.0", "dst": "192.0.2.10", "port": 80, "proto": "TCP", "rate": 30.0},
        ], self.now - 2)
        self.assertEqual(ipc_receiver._load_victim_flow_rates("192.0.2.10", now=self.now), {})


if __name__ == "__main__":
    unittest.main()
