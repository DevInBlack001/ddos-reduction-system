import os
import shutil
import stat
import subprocess
import tempfile
import unittest

import _support  # noqa: F401

LIVE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "benchmark_live.sh"))
HELPER = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "benchmark_mode_switch.sh"))

STUBS = {
    "systemctl": '#!/bin/sh\necho "systemctl $*" >> "$STUB_LOG"\ncase "$1" in is-active) echo active;; esac\n',
    "ipset": '#!/bin/sh\necho "ipset $*" >> "$STUB_LOG"\n',
    "journalctl": (
        '#!/bin/sh\nnow=$(date +%s.%N)\n'
        'echo "$now host u[1]: main: capture backend = pcap"\n'
        'echo "$now host u[1]: Kernel: XDP attached to x"\n'
        'echo "$now host u[1]: IPC socket listening on x"\n'
        'echo "$now host u[1]: Capture: status | x"\n'
    ),
}


class BenchmarkModeSwitchTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        bin_dir = os.path.join(self.dir, "bin")
        os.mkdir(bin_dir)
        for name, body in STUBS.items():
            path = os.path.join(bin_dir, name)
            with open(path, "w") as handle:
                handle.write(body)
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        self.log = os.path.join(self.dir, "calls.log")
        self.tuning = os.path.join(self.dir, "tuning.env")
        with open(self.tuning, "w") as handle:
            handle.write("FLOD_TUNING=--k 2\n")
        self.env = dict(os.environ, PATH=bin_dir + ":" + os.environ["PATH"], STUB_LOG=self.log,
                        FLOD_TUNING_FILE=self.tuning, READY_TIMEOUT_SECS="2")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_helper(self, *args):
        return subprocess.run(["bash", HELPER, *args], env=self.env, capture_output=True, text=True, timeout=30)

    def calls(self):
        if not os.path.exists(self.log):
            return ""
        with open(self.log) as handle:
            return handle.read()

    def out(self, name="out.txt"):
        return os.path.join(self.dir, name)

    def test_a_switch_writes_the_mode_and_baseline_into_the_tuning_line(self):
        result = self.run_helper("switch", "pcap", "/var/lib/x/flod_benchmark_pcap_run1.json",
                                 "ddos-stage1.service", self.out())
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.tuning) as handle:
            content = handle.read()
        self.assertIn("FLOD_TUNING=--k 2 --capture-mode pcap --baseline-path /var/lib/x/flod_benchmark_pcap_run1.json", content)

    def test_a_switch_removes_the_runs_baseline_left_by_an_earlier_session(self):
        baseline = os.path.join(self.dir, "flod_benchmark_kernel_run1.json")
        with open(baseline, "w") as handle:
            handle.write("{}")
        result = self.run_helper("switch", "kernel", baseline, "ddos-stage1.service", self.out())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(os.path.exists(baseline))

    def test_a_mode_other_than_pcap_or_kernel_is_refused_before_anything_runs(self):
        result = self.run_helper("switch", "pcap; touch /tmp/pwned", "/b.json", "s1.service", self.out())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), "")

    def test_a_baseline_path_with_a_space_is_refused_so_no_extra_sensor_flag_can_ride_along(self):
        result = self.run_helper("switch", "pcap", "/b.json --bpf-object /tmp/evil.o", "s1.service", self.out())
        self.assertEqual(result.returncode, 2)
        with open(self.tuning) as handle:
            self.assertEqual(handle.read(), "FLOD_TUNING=--k 2\n")
        self.assertEqual(self.calls(), "")

    def test_a_baseline_path_that_climbs_out_of_its_directory_is_refused(self):
        result = self.run_helper("switch", "pcap", "/var/lib/../../etc/passwd", "s1.service", self.out())
        self.assertEqual(result.returncode, 2)

    def test_a_unit_name_with_shell_characters_is_refused(self):
        result = self.run_helper("switch", "pcap", "/b.json", "s1.service;reboot", self.out())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), "")

    def test_an_ipset_name_with_shell_characters_is_refused(self):
        result = self.run_helper("switch", "pcap", "/b.json", "s1.service", self.out(), "s2.service", "bl;id", "rl")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), "")

    def test_an_output_path_that_is_a_symlink_is_refused(self):
        target = os.path.join(self.dir, "victim.txt")
        with open(target, "w") as handle:
            handle.write("keep")
        link = os.path.join(self.dir, "link.txt")
        os.symlink(target, link)
        result = self.run_helper("switch", "pcap", "/b.json", "s1.service", link)
        self.assertEqual(result.returncode, 2)
        with open(target) as handle:
            self.assertEqual(handle.read(), "keep")

    def test_a_rollback_restores_the_tuning_file_byte_for_byte(self):
        self.run_helper("switch", "pcap", "/b.json", "s1.service", self.out())
        result = self.run_helper("rollback", "s1.service", self.out("rb.txt"), "kernel")
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.tuning) as handle:
            self.assertEqual(handle.read(), "FLOD_TUNING=--k 2\n")

    def test_a_rollback_deletes_only_benchmark_baseline_files_in_the_named_directory(self):
        baselines = os.path.join(self.dir, "baselines")
        os.mkdir(baselines)
        for name in ("flod_benchmark_kernel_run1.json", "flod_benchmark_pcap_run1.json", "baselines.json", "notes.txt"):
            with open(os.path.join(baselines, name), "w") as handle:
                handle.write("x")
        self.run_helper("switch", "pcap", "/b.json", "s1.service", self.out())
        result = self.run_helper("rollback", "s1.service", self.out("rb.txt"), "", baselines)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(os.listdir(baselines)), ["baselines.json", "notes.txt"])

    def test_a_rollback_directory_with_a_wildcard_is_refused_and_deletes_nothing(self):
        keep = os.path.join(self.dir, "keep.json")
        with open(keep, "w") as handle:
            handle.write("x")
        result = self.run_helper("rollback", "s1.service", self.out("rb.txt"), "", self.dir + "/*")
        self.assertEqual(result.returncode, 2)
        self.assertTrue(os.path.exists(keep))

    def test_the_filesystem_root_is_refused_as_a_rollback_directory(self):
        result = self.run_helper("rollback", "s1.service", self.out("rb.txt"), "", "/")
        self.assertEqual(result.returncode, 2)

    def test_verify_refuses_an_interface_name_with_shell_characters(self):
        result = self.run_helper("verify", "s1.service", "s2.service", "eth0;id", "pcap", "bl", "rl")
        self.assertEqual(result.returncode, 2)

    def test_a_switch_empties_both_ipsets_and_restarts_stage_two_before_the_sensor_swap(self):
        self.run_helper("switch", "pcap", "/b.json", "s1.service", self.out(), "s2.service", "bl", "rl")
        calls = self.calls().splitlines()
        self.assertEqual(calls[0], "ipset flush bl")
        self.assertEqual(calls[1], "ipset flush rl")
        self.assertEqual(calls[2], "systemctl restart s2.service")
        self.assertLess(calls.index("systemctl restart s2.service"), calls.index("systemctl stop s1.service"))

    def test_applied_floors_are_added_after_the_switch_flags_and_survive_a_rollback_restore(self):
        self.run_helper("switch", "kernel", "/var/lib/x/flod_benchmark_kernel_run1.json", "s1.service", self.out())
        flags = "--rate-sigma-floor 7.8 --entropy-sigma-floor 0.4944 --entropy-sigma-ceiling 0.9"
        result = self.run_helper("apply-floors", flags, "s1.service", self.out("apply.txt"), "kernel")
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.tuning) as handle:
            line = handle.read().strip()
        self.assertTrue(line.startswith("FLOD_TUNING=--k 2 --capture-mode kernel --baseline-path /var/lib/x/flod_benchmark_kernel_run1.json"))
        self.assertTrue(line.endswith(flags))
        with open(self.out("apply.txt")) as handle:
            record = handle.read()
        self.assertIn("applied_flags=" + flags, record)
        self.assertIn("tuning_before=--k 2 --capture-mode kernel", record)
        self.run_helper("rollback", "s1.service", self.out("rb.txt"), "kernel")
        with open(self.tuning) as handle:
            self.assertEqual(handle.read(), "FLOD_TUNING=--k 2\n")

    def test_floors_with_extra_flags_are_refused_so_nothing_else_reaches_the_sensor(self):
        result = self.run_helper("apply-floors", "--rate-sigma-floor 7.8 --bpf-object /tmp/evil.o", "s1.service", self.out("a.txt"), "pcap")
        self.assertEqual(result.returncode, 2)
        result = self.run_helper("apply-floors", "--rate-sigma-floor 7.8; id", "s1.service", self.out("a.txt"), "pcap")
        self.assertEqual(result.returncode, 2)

    def test_floors_without_a_switch_first_are_refused(self):
        os.remove(self.tuning)
        result = self.run_helper("apply-floors", "--rate-sigma-floor 7.8", "s1.service", self.out("a.txt"), "pcap")
        self.assertEqual(result.returncode, 2)

    def test_a_rollback_removes_a_debug_dropin_that_appeared_during_the_benchmark(self):
        dropin = os.path.join(self.dir, "10-calibration-debug.conf")
        self.env["FLOD_DEBUG_DROPIN"] = dropin
        self.run_helper("switch", "pcap", "/b.json", "s1.service", self.out())
        with open(dropin, "w") as handle:
            handle.write("[Service]\n")
        self.run_helper("rollback", "s1.service", self.out("rb.txt"), "")
        self.assertFalse(os.path.exists(dropin))
        self.assertIn("daemon-reload", self.calls())

    def test_a_rollback_keeps_a_debug_dropin_that_was_there_before_the_benchmark(self):
        dropin = os.path.join(self.dir, "10-calibration-debug.conf")
        with open(dropin, "w") as handle:
            handle.write("[Service]\n")
        self.env["FLOD_DEBUG_DROPIN"] = dropin
        self.run_helper("switch", "pcap", "/b.json", "s1.service", self.out())
        self.run_helper("rollback", "s1.service", self.out("rb.txt"), "")
        self.assertTrue(os.path.exists(dropin))

    def test_a_tuning_file_that_is_a_symlink_is_refused(self):
        real = os.path.join(self.dir, "real.env")
        os.replace(self.tuning, real)
        os.symlink(real, self.tuning)
        result = self.run_helper("switch", "pcap", "/b.json", "s1.service", self.out())
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), "")

    def test_a_tuning_directory_open_to_group_or_others_is_refused(self):
        os.chmod(self.dir, 0o775)
        result = self.run_helper("switch", "pcap", "/b.json", "s1.service", self.out())
        os.chmod(self.dir, 0o700)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), "")

    def test_a_planted_symlink_at_the_backup_path_is_refused(self):
        target = os.path.join(self.dir, "victim.txt")
        with open(target, "w") as handle:
            handle.write("keep")
        os.symlink(target, self.tuning + ".flod-benchmark-backup")
        result = self.run_helper("switch", "pcap", "/b.json", "s1.service", self.out())
        self.assertEqual(result.returncode, 2)
        with open(target) as handle:
            self.assertEqual(handle.read(), "keep")


class BenchmarkLiveConfigTests(unittest.TestCase):
    BASE = (
        'GATEWAY_HOST="root@192.0.2.1"\nGATEWAY_SSH_KEY="/home/user/.ssh/key"\n'
        'TARGET_IPS="192.0.2.10,192.0.2.11"\n'
    )

    def run_live(self, extra):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        config = os.path.join(directory, "bench.env")
        with open(config, "w") as handle:
            handle.write(self.BASE + extra + 'OUTPUT_DIR="%s"\n' % os.path.join(directory, "out"))
        return subprocess.run(["bash", LIVE, config], capture_output=True, text=True, timeout=30)

    def test_a_config_value_with_shell_characters_is_rejected_before_any_connection(self):
        result = self.run_live('STAGE1_UNIT="ddos-stage1.service; reboot"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Config error: STAGE1_UNIT", result.stderr)

    def test_a_baseline_directory_with_a_wildcard_is_rejected(self):
        result = self.run_live('BASELINE_DIR="/var/lib/*"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Config error: BASELINE_DIR", result.stderr)

    def test_a_capture_mode_other_than_pcap_or_kernel_is_rejected(self):
        result = self.run_live('CAPTURE_MODES="kernel xdp"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("CAPTURE_MODES", result.stderr)

    def test_a_non_numeric_phase_duration_is_rejected(self):
        result = self.run_live('ATTACK_SECS="180; id"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Config error: ATTACK_SECS", result.stderr)

    def test_an_interface_name_with_shell_characters_is_rejected(self):
        result = self.run_live('INGRESS_IFACE="eth0 && id"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Config error: INGRESS_IFACE", result.stderr)

    def test_a_config_file_writable_by_everyone_is_rejected_before_it_is_sourced(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        marker = os.path.join(directory, "ran")
        config = os.path.join(directory, "bench.env")
        with open(config, "w") as handle:
            handle.write(self.BASE + 'touch "%s"\n' % marker)
        os.chmod(config, 0o666)
        result = subprocess.run(["bash", LIVE, config], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn("writable by everyone", result.stderr)
        self.assertFalse(os.path.exists(marker))

    def test_a_variant_name_with_shell_characters_is_rejected(self):
        result = self.run_live('ATTACK_VARIANTS="mixed shapeb;id"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("ATTACK_VARIANTS", result.stderr)

    def test_a_source_file_path_with_a_wildcard_is_rejected(self):
        result = self.run_live('ATTACK_SOURCE_FILE="/root/*"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Config error: ATTACK_SOURCE_FILE", result.stderr)

    LIMIT_OK = (
        'ATTACK_HOST="root@198.51.100.10"\nATTACK_SSH_KEY="/home/user/.ssh/key"\n'
        'LIMIT_STEPS_PPS="5000 20000 max"\n'
        'LIMIT_START_CMD="run @PPS@ @PAYLOAD@ @SECS@"\nLIMIT_STOP_CMD="stop"\n'
    )

    def test_a_probe_target_with_shell_characters_is_rejected(self):
        result = self.run_live('NORMAL_HOST="root@198.51.100.10"\nNORMAL_SSH_KEY="/k"\n'
                               'LATENCY_PROBE_TARGET="192.0.2.10; id"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Config error: LATENCY_PROBE_TARGET", result.stderr)

    def test_a_probe_without_a_host_to_run_on_is_rejected(self):
        result = self.run_live('LATENCY_PROBE_TARGET="192.0.2.10"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("LATENCY_PROBE_HOST", result.stderr)

    def test_a_limit_step_that_is_not_a_number_or_max_is_rejected(self):
        result = self.run_live(self.LIMIT_OK + 'LIMIT_STEPS_PPS="5000 fast"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Config error: LIMIT_STEPS_PPS", result.stderr)

    def test_a_limit_step_shorter_than_ten_seconds_is_rejected(self):
        result = self.run_live(self.LIMIT_OK + 'LIMIT_STEP_SECS=5\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("LIMIT_STEP_SECS must be at least 10", result.stderr)

    def test_a_limit_profile_without_a_payload_size_is_rejected(self):
        result = self.run_live(self.LIMIT_OK + 'LIMIT_PROFILES="small jumbo"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("LIMIT_PAYLOAD_jumbo is not set", result.stderr)

    def test_a_limit_payload_with_shell_characters_is_rejected(self):
        result = self.run_live(self.LIMIT_OK + 'LIMIT_PAYLOAD_large="1400; id"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("Config error: LIMIT_PAYLOAD_large", result.stderr)

    def test_a_ladder_without_generator_commands_is_rejected(self):
        result = self.run_live('ATTACK_HOST="root@198.51.100.10"\nATTACK_SSH_KEY="/k"\nLIMIT_STEPS_PPS="5000"\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn("LIMIT_START_CMD", result.stderr)

    def test_a_valid_ladder_passes_validation_and_stops_later_at_the_missing_gateway(self):
        result = self.run_live(self.LIMIT_OK)
        self.assertNotIn("Config error", result.stderr)


FLOOD = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "benchmark_limit_flood.sh"))
PROBE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "benchmark_latency_probe.sh"))


class BenchmarkLimitFloodTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.targets = os.path.join(self.dir, "targets.txt")
        self.sources = os.path.join(self.dir, "sources.txt")
        with open(self.targets, "w") as handle:
            handle.write("192.0.2.10\n192.0.2.11\n\n")
        with open(self.sources, "w") as handle:
            handle.write("198.51.100.1\n198.51.100.2\n198.51.100.3\n")

    def dry_run(self, pps, payload="0", secs="30", workers="4"):
        env = dict(os.environ, LIMIT_FLOOD_DRY_RUN="1", LIMIT_FLOOD_WORKERS=workers)
        return subprocess.run(["bash", FLOOD, pps, payload, secs, self.targets, self.sources],
                              capture_output=True, text=True, timeout=30, env=env)

    def test_a_paced_step_splits_the_rate_over_the_workers(self):
        result = self.dry_run("40000")
        lines = result.stdout.strip().splitlines()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(lines), 4)
        self.assertTrue(all("-i u100 " in line for line in lines))

    def test_a_max_step_sends_unpaced(self):
        lines = self.dry_run("max", payload="1400").stdout.strip().splitlines()
        self.assertTrue(all("--flood" in line and "-d 1400" in line for line in lines))

    def test_workers_take_the_next_source_and_target_in_turn(self):
        lines = self.dry_run("1000", workers="3").stdout.strip().splitlines()
        self.assertIn("-a 198.51.100.1 ", lines[0])
        self.assertIn("-a 198.51.100.3 ", lines[2])
        self.assertTrue(lines[0].endswith("192.0.2.10"))
        self.assertTrue(lines[1].endswith("192.0.2.11"))
        self.assertTrue(lines[2].endswith("192.0.2.10"))

    def test_the_step_length_is_enforced_with_a_timeout(self):
        self.assertTrue(self.dry_run("1000", secs="35").stdout.startswith("timeout 35 hping3 "))

    def test_a_rate_that_is_not_a_number_or_max_is_refused(self):
        result = self.dry_run("1000; id")
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid pps", result.stderr)

    def test_an_empty_targets_file_is_refused(self):
        open(self.targets, "w").close()
        result = self.dry_run("1000")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no targets", result.stderr)


class BenchmarkLatencyProbeTests(unittest.TestCase):
    def test_a_target_with_shell_characters_is_refused(self):
        result = subprocess.run(["sh", PROBE, "192.0.2.10;id", "0.2", "/dev/null"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid target", result.stderr)

    def test_an_interval_that_is_not_a_number_is_refused(self):
        result = subprocess.run(["sh", PROBE, "192.0.2.10", "fast", "/dev/null"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid interval", result.stderr)


if __name__ == "__main__":
    unittest.main()
