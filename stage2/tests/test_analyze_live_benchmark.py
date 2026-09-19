import os
import sys
import unittest

import _support  # noqa: F401

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "..", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))
import analyze_live_benchmark as bench  # noqa: E402


def sample(ts, **fields):
    return {"timestamp": ts, **{k: str(v) for k, v in fields.items()}}


class LineTimeTests(unittest.TestCase):
    def test_a_journal_line_without_fractional_seconds_gets_a_full_timestamp(self):
        line = "Sep 19 08:00:05 gw ddos_stage1[1]: text"
        self.assertEqual(bench.line_time(line, "2026"), "2026-09-19 08:00:05")

    def test_a_precise_journal_line_keeps_its_fractional_seconds(self):
        line = "Sep 19 08:00:05.250000 gw ddos_stage1[1]: text"
        self.assertEqual(bench.line_time(line, "2026"), "2026-09-19 08:00:05.250000")

    def test_a_line_without_a_timestamp_is_ignored(self):
        self.assertIsNone(bench.line_time("-- Boot --", "2026"))

    def test_seconds_between_handles_mixed_precision(self):
        self.assertAlmostEqual(
            bench.seconds_between("2026-09-19 08:00:00", "2026-09-19 08:00:02.500000"), 2.5)


class TrafficDeltaTests(unittest.TestCase):
    def test_kernel_status_lines_are_summed_because_each_one_covers_its_own_interval(self):
        counters = {"ingress": 100, "egress": 10, "flows": 1, "ports": 1, "ttls": 1,
                    "fingerprints": 1, "drains": 1, "errors": 0}
        samples = [("2026-09-19 08:00:01", "kernel", dict(counters)),
                   ("2026-09-19 08:00:06", "kernel", dict(counters))]
        backend, total = bench.traffic_delta(samples, "2026-09-19 08:00:00", "2026-09-19 08:01:00")
        self.assertEqual(backend, "kernel")
        self.assertEqual(total["ingress"], 200)

    def test_pcap_status_lines_are_cumulative_so_a_phase_is_the_difference(self):
        def counters(raw):
            return {"raw_captured": raw, "timeouts": 0, "parse_failed": 0,
                    "non_ip": 0, "truncated": 0, "forwarded": raw}
        samples = [("2026-09-19 08:00:00", "pcap", counters(1000)),
                   ("2026-09-19 08:00:30", "pcap", counters(1500)),
                   ("2026-09-19 08:01:00", "pcap", counters(4000))]
        backend, total = bench.traffic_delta(samples, "2026-09-19 08:00:30", "2026-09-19 08:01:00")
        self.assertEqual(backend, "pcap")
        self.assertEqual(total["raw_captured"], 2500)


class CounterMetricTests(unittest.TestCase):
    def test_a_rate_uses_the_span_between_the_first_and_last_sample(self):
        rows = [sample("2026-09-19 08:00:00", ingress_rx_packets=1000),
                sample("2026-09-19 08:00:10", ingress_rx_packets=6000)]
        self.assertAlmostEqual(
            bench.rate(rows, "2026-09-19 08:00:00", "2026-09-19 08:01:00", "ingress_rx_packets"), 500.0)

    def test_a_counter_that_goes_backwards_after_a_restart_gives_no_figure(self):
        rows = [sample("2026-09-19 08:00:00", ingress_rx_packets=6000),
                sample("2026-09-19 08:00:10", ingress_rx_packets=10)]
        self.assertIsNone(
            bench.rate(rows, "2026-09-19 08:00:00", "2026-09-19 08:01:00", "ingress_rx_packets"))

    def test_a_single_sample_gives_no_figure(self):
        rows = [sample("2026-09-19 08:00:00", ingress_rx_packets=6000)]
        self.assertIsNone(
            bench.rate(rows, "2026-09-19 08:00:00", "2026-09-19 08:01:00", "ingress_rx_packets"))

    def test_system_cpu_reports_busy_kernel_and_softirq_shares(self):
        def row(ts, user, system, idle, softirq):
            return sample(ts, sys_user=user, sys_nice=0, sys_system=system, sys_idle=idle,
                          sys_iowait=0, sys_irq=0, sys_softirq=softirq, sys_steal=0)
        rows = [row("2026-09-19 08:00:00", 0, 0, 0, 0), row("2026-09-19 08:00:10", 200, 100, 600, 100)]
        cpu = bench.system_cpu_metrics(rows, "2026-09-19 08:00:00", "2026-09-19 08:01:00")
        self.assertAlmostEqual(cpu["busy_pct"], 40.0)
        self.assertAlmostEqual(cpu["kernel_pct"], 20.0)
        self.assertAlmostEqual(cpu["softirq_pct"], 10.0)

    def test_a_service_restart_in_the_phase_skips_its_figures(self):
        rows = [sample("2026-09-19 08:00:00", stage1_pid=10, stage1_cpu_ticks=1),
                sample("2026-09-19 08:00:05", stage1_pid=11, stage1_cpu_ticks=1)]
        result = bench.process_metrics(rows, "2026-09-19 08:00:00", "2026-09-19 08:01:00", 100, "stage1")
        self.assertTrue(result["restarted"])

    def test_context_switches_per_second_add_voluntary_and_involuntary(self):
        rows = [sample("2026-09-19 08:00:00", stage1_pid=10, stage1_vol_ctxt=0, stage1_nonvol_ctxt=0),
                sample("2026-09-19 08:00:10", stage1_pid=10, stage1_vol_ctxt=900, stage1_nonvol_ctxt=100)]
        result = bench.process_metrics(rows, "2026-09-19 08:00:00", "2026-09-19 08:01:00", 100, "stage1")
        self.assertAlmostEqual(result["ctxt_per_sec"], 100.0)
        self.assertAlmostEqual(result["nonvol_ctxt_per_sec"], 10.0)


class LatencyMetricTests(unittest.TestCase):
    LINE = ("Sep 19 08:00:30 gw ddos_stage2[2]: Latency: summary | interval_secs=30 | "
            "handoff_n={n} handoff_mean_ms={mean} handoff_p95_ms={p95} handoff_max_ms=9.000 | "
            "inference_n=0 | enforcement_n=0 | window_to_rule_n=0")

    def events(self, *specs):
        return [("2026-09-19 08:00:30", self.LINE.format(n=n, mean=mean, p95=p95)) for n, mean, p95 in specs]

    def test_interval_means_are_weighted_by_their_sample_counts(self):
        merged = bench.latency_metrics(self.events((10, "1.000", "2.0"), (30, "3.000", "5.0")))
        self.assertEqual(merged["handoff"]["n"], 40)
        self.assertAlmostEqual(merged["handoff"]["mean_ms"], 2.5)

    def test_the_reported_p95_is_the_worst_interval(self):
        merged = bench.latency_metrics(self.events((10, "1.000", "2.0"), (30, "3.000", "5.0")))
        self.assertAlmostEqual(merged["handoff"]["p95_ms"], 5.0)

    def test_a_kind_with_no_samples_is_left_out(self):
        merged = bench.latency_metrics(self.events((10, "1.000", "2.0")))
        self.assertNotIn("inference", merged)

    def test_lines_that_are_not_latency_summaries_are_ignored(self):
        events = [("2026-09-19 08:00:30", "Sep 19 08:00:30 gw x: handoff_n=5 handoff_mean_ms=1.0")]
        self.assertEqual(bench.latency_metrics(events), {})


class ConsistencyTests(unittest.TestCase):
    START, END = "2026-09-19 08:00:00", "2026-09-19 08:01:00"

    def test_a_benign_phase_with_no_ddos_verdicts_is_fully_consistent(self):
        self.assertEqual(bench.bin_consistency([], self.START, self.END, expect_attack=False), 100.0)

    def test_a_benign_phase_loses_a_bin_for_each_bin_holding_a_verdict(self):
        times = ["2026-09-19 08:00:05", "2026-09-19 08:00:35"]
        result = bench.bin_consistency(times, self.START, self.END, expect_attack=False)
        self.assertAlmostEqual(result, 100.0 * 4 / 6)

    def test_an_attack_phase_with_no_verdicts_scores_zero(self):
        self.assertEqual(bench.bin_consistency([], self.START, self.END, expect_attack=True), 0.0)

    def test_an_attack_phase_is_measured_from_the_first_detection_bin(self):
        times = ["2026-09-19 08:00:25"] + [f"2026-09-19 08:00:{s}" for s in (35, 45, 55)]
        self.assertEqual(bench.bin_consistency(times, self.START, self.END, expect_attack=True), 100.0)

    def test_a_gap_after_the_first_detection_lowers_the_score(self):
        times = ["2026-09-19 08:00:05", "2026-09-19 08:00:15"]
        result = bench.bin_consistency(times, self.START, self.END, expect_attack=True)
        self.assertAlmostEqual(result, 100.0 * 2 / 6)

    def test_a_phase_shorter_than_one_bin_gives_no_figure(self):
        self.assertIsNone(bench.bin_consistency([], self.START, "2026-09-19 08:00:05", expect_attack=False))


class FirewallDropTests(unittest.TestCase):
    def row(self, phase, target, packets, set_name="ddos_blocklist"):
        return (phase, "2026-09-19 08:00:00", "INPUT", set_name, target, str(packets), "0")

    def test_a_phase_count_is_the_next_snapshot_minus_its_own(self):
        rows = [self.row("attacker", "DROP", 100), self.row("session_end", "DROP", 600)]
        result = bench.firewall_drops(rows, ["attacker", "session_end"])
        self.assertEqual(result["attacker"]["ddos_blocklist"], 500)

    def test_rules_that_do_not_drop_are_not_counted(self):
        rows = [self.row("attacker", "ACCEPT", 100), self.row("session_end", "ACCEPT", 600)]
        self.assertEqual(bench.firewall_drops(rows, ["attacker", "session_end"]), {})

    def test_chains_are_summed_per_set(self):
        rows = [self.row("a", "DROP", 10), ("a", "t", "FORWARD", "ddos_blocklist", "DROP", "5", "0"),
                self.row("b", "DROP", 30), ("b", "t", "FORWARD", "ddos_blocklist", "DROP", "25", "0")]
        self.assertEqual(bench.firewall_drops(rows, ["a", "b"])["a"]["ddos_blocklist"], 40)


class ModeSwitchFileTests(unittest.TestCase):
    def test_key_value_files_are_read_and_check_lines_are_skipped(self):
        path = _support.temp_path(".txt")
        with open(path, "w") as handle:
            handle.write("action=switch\nstop_secs=0.4\ncheck=stage1_active result=pass detail=active\n")
        try:
            values = bench.load_key_values(path)
        finally:
            _support.unlink(path)
        self.assertEqual(values, {"action": "switch", "stop_secs": "0.4"})

    def test_check_lines_are_parsed_into_name_result_and_detail(self):
        path = _support.temp_path(".txt")
        with open(path, "w") as handle:
            handle.write("check=capture_mode result=fail detail=expected=kernel actual=pcap\n")
        try:
            checks = bench.load_checks(path)
        finally:
            _support.unlink(path)
        self.assertEqual(checks, [("capture_mode", "fail", "expected=kernel actual=pcap")])

    def test_a_missing_file_reads_as_empty(self):
        self.assertEqual(bench.load_key_values("/nonexistent/none.txt"), {})


if __name__ == "__main__":
    unittest.main()
