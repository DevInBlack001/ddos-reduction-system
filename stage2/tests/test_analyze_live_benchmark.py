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


class PhaseInfoTests(unittest.TestCase):
    def test_a_standard_phase_is_known_and_reports_whether_it_holds_an_attack(self):
        self.assertEqual(bench.phase_info("normal"), (True, False, False, None))
        self.assertEqual(bench.phase_info("attacker"), (True, True, True, None))
        self.assertEqual(bench.phase_info("all_three"), (True, True, False, None))

    def test_a_sweep_phase_carries_its_attack_type(self):
        self.assertEqual(bench.phase_info("attacker_shapeb"), (True, True, True, "shapeb"))
        self.assertEqual(bench.phase_info("normal_attacker_single_mp"), (True, True, False, "single_mp"))

    def test_gap_and_unknown_phases_are_not_analyzed(self):
        self.assertFalse(bench.phase_info("gap_shapeb")[0])
        self.assertFalse(bench.phase_info("session_start")[0])
        self.assertFalse(bench.phase_info("flashcrowd_attacker_x")[0])


class AnomalySignalTests(unittest.TestCase):
    LINE = ("Sep 19 08:00:05 gw ddos_stage1[1]: ANOMALY window 7 [victim=192.0.2.10] | flags={flags} | "
            "r=900.0 (boundary=60.0) | h={h} (boundary=0.5000) | proto_ratio=0.500 | dom_ratio={dom} | "
            "dominant_ip=198.51.100.7")

    def events(self, *rows):
        return [("2026-09-19 08:00:05", self.LINE.format(flags=f, h=h, dom=d)) for f, h, d in rows]

    def test_windows_are_split_by_which_signal_flagged_them(self):
        stats = bench.anomaly_signal_stats(self.events(("0x01", "0.9", "0.1"), ("0x02", "0.2", "0.9"), ("0x03", "0.3", "0.8")))
        self.assertEqual((stats["flagged_rate_only"], stats["flagged_entropy_only"], stats["flagged_both"]), (1, 1, 1))

    def test_the_entropy_share_counts_entropy_only_and_both(self):
        stats = bench.anomaly_signal_stats(self.events(("0x01", "0.9", "0.1"), ("0x02", "0.2", "0.9"), ("0x03", "0.3", "0.8"), ("0x01", "0.9", "0.1")))
        self.assertAlmostEqual(stats["entropy_flag_pct"], 50.0)

    def test_the_means_cover_every_flagged_window(self):
        stats = bench.anomaly_signal_stats(self.events(("0x01", "0.8", "0.2"), ("0x01", "0.4", "0.6")))
        self.assertAlmostEqual(stats["mean_entropy"], 0.6)
        self.assertAlmostEqual(stats["mean_dominance"], 0.4)

    def test_no_anomaly_lines_gives_no_figures(self):
        self.assertEqual(bench.anomaly_signal_stats([("2026-09-19 08:00:05", "Sep 19 08:00:05 gw x: heartbeat")]), {})


class VariantFileTests(unittest.TestCase):
    def test_variants_are_grouped_by_phase_and_class(self):
        path = _support.temp_path(".tsv")
        with open(path, "w") as handle:
            handle.write("normal\tnormal\tbaseline\tSmooth browsing\n"
                         "attacker\tattack\tshapeb\tUDP heavy\nattacker\tnormal\tbursty\t\n")
        directory = os.path.dirname(path)
        target = os.path.join(directory, "traffic_variants.tsv")
        os.replace(path, target)
        try:
            result = bench.load_variants(directory)
        finally:
            _support.unlink(target)
        self.assertEqual(result["normal"]["normal"], ("baseline", "Smooth browsing"))
        self.assertEqual(result["attacker"]["attack"], ("shapeb", "UDP heavy"))
        self.assertEqual(result["attacker"]["normal"], ("bursty", ""))

    def test_a_missing_file_reads_as_empty(self):
        self.assertEqual(bench.load_variants("/nonexistent"), {})


class CalibrationLogTests(unittest.TestCase):
    LOG = ("collecting: 10.0.0.2 10/1000\r\n"
           "target              windows  flagged   mean pps   peak pps   rate flr   entr flr\n"
           "10.0.0.2                980     1.2%       25.1       60.3        7.8     0.2263\n"
           "10.0.0.3               1000     0.5%       22.0       55.0        7.1     0.2100\n"
           "warning: 10.0.0.2 has a long tail\n"
           "\nRecommended, covering every target:\n"
           "  --rate-sigma-floor 7.8 --entropy-sigma-floor 0.2263\n")

    def test_per_target_rows_are_read_from_the_table(self):
        targets, _, _ = bench.parse_calibration_log(self.LOG)
        self.assertEqual([t["target"] for t in targets], ["10.0.0.2", "10.0.0.3"])
        self.assertEqual(targets[0]["windows"], 980)
        self.assertAlmostEqual(targets[0]["mean_pps"], 25.1)
        self.assertAlmostEqual(targets[1]["entropy_floor"], 0.21)

    def test_warnings_and_notes_are_kept(self):
        _, notes, _ = bench.parse_calibration_log(self.LOG)
        self.assertEqual(notes, ["warning: 10.0.0.2 has a long tail"])

    def test_the_recommended_flags_line_is_found_after_its_heading(self):
        _, _, flags = bench.parse_calibration_log(self.LOG)
        self.assertEqual(flags, "--rate-sigma-floor 7.8 --entropy-sigma-floor 0.2263")

    def test_floors_are_read_out_of_the_flags(self):
        flags = "--rate-sigma-floor 7.8 --entropy-sigma-floor 0.2263 --entropy-sigma-ceiling 0.9"
        self.assertAlmostEqual(bench.floor_from_flags(flags, "rate-sigma-floor"), 7.8)
        self.assertAlmostEqual(bench.floor_from_flags(flags, "entropy-sigma-floor"), 0.2263)
        self.assertIsNone(bench.floor_from_flags("", "rate-sigma-floor"))

    def test_a_log_with_no_table_gives_empty_results(self):
        self.assertEqual(bench.parse_calibration_log("error: no per window samples\n"), ([], [], ""))

    def test_a_run_without_calibration_files_has_no_calibration(self):
        self.assertIsNone(bench.load_calibration("/nonexistent"))


class InterleavedInterfaceTests(unittest.TestCase):
    def status(self, iface, raw, second):
        return (f"2026-09-19 08:00:{second:02d}",
                f"Sep 19 08:00:{second:02d} gw ddos_stage1[1]: [x INFO  ddos_stage1::capture] Capture: status | "
                f"interface={iface} | raw_captured={raw} | timeouts=0 | parse_failed=0 | non_ip=0 | "
                f"truncated=0 | forwarded={raw}")

    def events(self):
        return [self.status("ens256", 3000, 5), self.status("ens192", 100, 5),
                self.status("ens256", 3500, 10), self.status("ens192", 250, 10)]

    def test_lines_are_kept_apart_by_interface(self):
        samples = bench.parse_traffic_samples(self.events(), "ens192")
        self.assertEqual([c["raw_captured"] for _, _, c in samples], [100, 250])

    def test_a_phase_delta_uses_one_interfaces_counters_only(self):
        samples = bench.parse_traffic_samples(self.events(), "ens192")
        backend, total = bench.traffic_delta(samples, "2026-09-19 08:00:07", "2026-09-19 08:00:12")
        self.assertEqual(total["raw_captured"], 150)

    def test_without_an_interface_every_line_is_read(self):
        self.assertEqual(len(bench.parse_traffic_samples(self.events())), 4)

    def test_the_first_status_line_names_the_default_interface(self):
        self.assertEqual(bench.first_capture_interface(self.events()), "ens256")


class StaleSampleTests(unittest.TestCase):
    def counters(self, raw):
        return {"raw_captured": raw, "timeouts": 0, "parse_failed": 0, "non_ip": 0, "truncated": 0, "forwarded": raw}

    def test_a_phase_after_a_quiet_gap_in_the_status_lines_gets_no_total(self):
        samples = [("2026-09-19 08:00:00", "pcap", self.counters(1000)),
                   ("2026-09-19 08:02:30", "pcap", self.counters(9000))]
        self.assertIsNone(bench.traffic_delta(samples, "2026-09-19 08:01:00", "2026-09-19 08:02:40"))

    def test_a_phase_with_fresh_boundary_samples_still_gets_its_total(self):
        samples = [("2026-09-19 08:00:55", "pcap", self.counters(1000)),
                   ("2026-09-19 08:02:35", "pcap", self.counters(1500))]
        backend, total = bench.traffic_delta(samples, "2026-09-19 08:01:00", "2026-09-19 08:02:40")
        self.assertEqual(total["raw_captured"], 500)


if __name__ == "__main__":
    unittest.main()
