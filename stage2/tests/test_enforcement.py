"""Tests for enforcement.py: victim resolution and the block/rate-limit paths.

subprocess.run is replaced throughout so no test touches the real host
firewall. Assertions are made on the argv that would have been executed.
"""

import json
import os
import subprocess
import unittest

import _support
from _support import FakeCompleted, RecordingRun, make_logs_db, reset_db_module, temp_path, unlink

import config
import enforcement
import state


class EnforcementTestCase(unittest.TestCase):
    """Redirects every path enforcement reads, and stubs subprocess."""

    def setUp(self):
        self._saved = {
            "DB_PATH": config.DB_PATH,
            "WHITELIST_PATH": config.WHITELIST_PATH,
            "SHARED_IPS_PATH": config.SHARED_IPS_PATH,
            "VICTIMS_PATH": config.VICTIMS_PATH,
        }
        self.db_path = make_logs_db()
        self.whitelist = temp_path()
        self.shared = temp_path()
        self.victims = temp_path()
        for path in (self.whitelist, self.shared, self.victims):
            with open(path, "w") as handle:
                json.dump([], handle)

        config.DB_PATH = self.db_path
        config.WHITELIST_PATH = self.whitelist
        config.SHARED_IPS_PATH = self.shared
        config.VICTIMS_PATH = self.victims

        self.run = RecordingRun()
        self._real_run = subprocess.run
        enforcement.subprocess.run = self.run

        reset_db_module()
        state.recently_blocked.clear()
        state.ddos_sources.clear()
        self._targets = dict(state.last_metrics_by_target)
        state.last_metrics_by_target.clear()

    def tearDown(self):
        reset_db_module()
        enforcement.subprocess.run = self._real_run
        for name, value in self._saved.items():
            setattr(config, name, value)
        state.recently_blocked.clear()
        state.ddos_sources.clear()
        state.last_metrics_by_target.clear()
        state.last_metrics_by_target.update(self._targets)
        unlink(self.db_path, self.whitelist, self.shared, self.victims)

    def write_json(self, path, payload):
        with open(path, "w") as handle:
            json.dump(payload, handle)

    def logged(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT src_ip, dst_ip, rate, classification FROM logs ORDER BY id").fetchall()
        conn.close()
        return rows


class ResolveVictimIpTests(EnforcementTestCase):
    def test_keeps_a_real_address(self):
        self.assertEqual(enforcement.resolve_victim_ip("192.0.2.7"), "192.0.2.7")

    def test_treats_unknown_as_unset(self):
        self.write_json(self.victims, [{"ip": "192.0.2.3", "active": True}])
        self.assertEqual(enforcement.resolve_victim_ip("Unknown"), "192.0.2.3")

    def test_treats_the_wildcard_address_as_unset(self):
        self.write_json(self.victims, [{"ip": "192.0.2.3", "active": True}])
        self.assertEqual(enforcement.resolve_victim_ip("0.0.0.0"), "192.0.2.3")

    def test_prefers_an_active_victim(self):
        self.write_json(self.victims, [
            {"ip": "192.0.2.2", "active": False},
            {"ip": "192.0.2.5", "active": True},
        ])
        self.assertEqual(enforcement.resolve_victim_ip(None), "192.0.2.5")

    def test_falls_back_to_the_first_configured_victim(self):
        self.write_json(self.victims, [{"ip": "192.0.2.8", "active": False}])
        self.assertEqual(enforcement.resolve_victim_ip(None), "192.0.2.8")

    def test_falls_back_to_a_target_seen_in_this_session(self):
        state.last_metrics_by_target["192.0.2.44"] = {}
        self.assertEqual(enforcement.resolve_victim_ip(None), "192.0.2.44")

    def test_a_corrupt_victims_file_does_not_raise(self):
        with open(self.victims, "w") as handle:
            handle.write("{ not json")
        self.assertIsInstance(enforcement.resolve_victim_ip(None), str)


class BlockIpTests(EnforcementTestCase):
    def test_adds_the_ip_to_the_blocklist(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertTrue(self.run.ran("ipset add ddos_blocklist 198.51.100.9"))

    def test_passes_the_requested_duration(self):
        enforcement.block_ip("198.51.100.9", duration=120, victim_ip="192.0.2.3")
        argv = self.run.argv_containing("ddos_blocklist")[0]
        self.assertEqual(argv[argv.index("timeout") + 1], "120")

    def test_records_the_incident(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3", src_rate=88.0)
        self.assertEqual(self.logged(), [("198.51.100.9", "192.0.2.3", 88.0, "Blocked")])

    def test_a_whitelisted_ip_is_never_blocked(self):
        self.write_json(self.whitelist, ["198.51.100.9"])
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertEqual(self.run.calls, [])

    def test_a_whitelisted_ip_produces_no_incident_record(self):
        self.write_json(self.whitelist, ["198.51.100.9"])
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertEqual(self.logged(), [])

    def test_a_shared_ip_is_rate_limited_instead(self):
        # A NAT egress point fronts many hosts, so a hard drop would cut off
        # every legitimate user behind it.
        self.write_json(self.shared, ["198.51.100.9"])
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertTrue(self.run.ran("ddos_ratelimit 198.51.100.9"))

    def test_a_shared_ip_never_reaches_the_blocklist(self):
        self.write_json(self.shared, ["198.51.100.9"])
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertFalse(self.run.ran("ddos_blocklist 198.51.100.9"))

    def test_the_downgrade_keeps_the_source_rate(self):
        self.write_json(self.shared, ["198.51.100.9"])
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3", src_rate=51.0)
        self.assertEqual(self.logged(), [("198.51.100.9", "192.0.2.3", 51.0, "Rate Limited")])

    def test_the_downgrade_keeps_the_duration(self):
        self.write_json(self.shared, ["198.51.100.9"])
        enforcement.block_ip("198.51.100.9", duration=45, victim_ip="192.0.2.3")
        argv = self.run.argv_containing("ddos_ratelimit")[0]
        self.assertEqual(argv[argv.index("timeout") + 1], "45")

    def test_a_repeat_within_the_cooldown_is_suppressed(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.run.calls.clear()
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertEqual(self.run.calls, [])

    def test_a_different_ip_is_not_suppressed(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.run.calls.clear()
        enforcement.block_ip("198.51.100.10", victim_ip="192.0.2.3")
        self.assertTrue(self.run.ran("198.51.100.10"))

    def test_a_failed_ipset_call_logs_no_incident(self):
        enforcement.subprocess.run = RecordingRun(returncode=1)
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertEqual(self.logged(), [])

    def test_an_ipset_exception_does_not_propagate(self):
        def explode(*args, **kwargs):
            raise OSError("ipset missing")
        enforcement.subprocess.run = explode
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")


class RateLimitIpTests(EnforcementTestCase):
    def test_adds_the_ip_to_the_ratelimit_set(self):
        enforcement.ratelimit_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertTrue(self.run.ran("ipset add ddos_ratelimit 198.51.100.9"))

    def test_records_the_incident(self):
        enforcement.ratelimit_ip("198.51.100.9", victim_ip="192.0.2.3", src_rate=6.5)
        self.assertEqual(self.logged(), [("198.51.100.9", "192.0.2.3", 6.5, "Rate Limited")])

    def test_a_whitelisted_ip_is_never_rate_limited(self):
        self.write_json(self.whitelist, ["198.51.100.9"])
        enforcement.ratelimit_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertEqual(self.run.calls, [])

    def test_a_repeat_within_the_cooldown_is_suppressed(self):
        enforcement.ratelimit_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.run.calls.clear()
        enforcement.ratelimit_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertEqual(self.run.calls, [])

    def test_a_failed_ipset_call_logs_no_incident(self):
        enforcement.subprocess.run = RecordingRun(returncode=1)
        enforcement.ratelimit_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertEqual(self.logged(), [])


class UnblockIpTests(EnforcementTestCase):
    def test_removes_from_both_sets(self):
        enforcement.unblock_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertTrue(self.run.ran("ipset del ddos_blocklist 198.51.100.9"))
        self.assertTrue(self.run.ran("ipset del ddos_ratelimit 198.51.100.9"))

    def test_reports_success(self):
        self.assertTrue(enforcement.unblock_ip("198.51.100.9", victim_ip="192.0.2.3"))

    def test_records_a_release(self):
        enforcement.unblock_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertEqual(self.logged(), [("198.51.100.9", "192.0.2.3", None, "Released")])

    def test_reports_failure_when_the_ip_was_in_neither_set(self):
        enforcement.subprocess.run = RecordingRun(returncode=1)
        self.assertFalse(enforcement.unblock_ip("198.51.100.9", victim_ip="192.0.2.3"))

    def test_resolves_the_victim_before_logging(self):
        self.write_json(self.victims, [{"ip": "192.0.2.6", "active": True}])
        enforcement.unblock_ip("198.51.100.9")
        self.assertEqual(self.logged()[0][1], "192.0.2.6")


class IpsetReadbackTests(EnforcementTestCase):
    LISTING = (
        "Name: ddos_blocklist\n"
        "Type: hash:ip\n"
        "Header: family inet hashsize 1024 maxelem 65536 timeout 3600\n"
        "Number of entries: 2\n"
        "Members:\n"
        "198.51.100.9 timeout 3421\n"
        "198.51.100.10 timeout 88\n"
    )

    def test_parses_members_and_timeouts(self):
        enforcement.subprocess.run = RecordingRun(stdout=self.LISTING)
        self.assertEqual(
            enforcement.get_blocked_ips(),
            [{"ip": "198.51.100.9", "remaining_seconds": 3421},
             {"ip": "198.51.100.10", "remaining_seconds": 88}],
        )

    def test_returns_empty_when_the_set_is_missing(self):
        enforcement.subprocess.run = RecordingRun(returncode=1)
        self.assertEqual(enforcement.get_blocked_ips(), [])

    def test_returns_empty_when_there_is_no_members_section(self):
        enforcement.subprocess.run = RecordingRun(stdout="Name: ddos_blocklist\n")
        self.assertEqual(enforcement.get_blocked_ips(), [])

    def test_a_member_without_a_timeout_gets_the_default(self):
        enforcement.subprocess.run = RecordingRun(stdout="Members:\n198.51.100.9\n")
        self.assertEqual(enforcement.get_blocked_ips()[0]["remaining_seconds"], 3600)

    def test_the_ratelimit_set_is_read_separately(self):
        enforcement.subprocess.run = RecordingRun(stdout="Members:\n198.51.100.9 timeout 10\n")
        enforcement.get_ratelimited_ips()
        self.assertTrue(enforcement.subprocess.run.ran("ipset list ddos_ratelimit"))


class IncidentEntropyTests(EnforcementTestCase):
    """Entropy must come from the acting window, and zero must not mean unknown.

    Zero entropy reads as maximally concentrated traffic, the signature of a
    single source flood, so it cannot stand in for an absent measurement.
    """

    def logged_entropy(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT entropy FROM logs ORDER BY id").fetchall()
        conn.close()
        return [r[0] for r in rows]

    def test_a_block_records_the_entropy_it_was_given(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3",
                             src_rate=900.0, entropy=0.4213)
        self.assertEqual(self.logged_entropy(), [0.4213])

    def test_a_rate_limit_records_the_entropy_it_was_given(self):
        enforcement.ratelimit_ip("198.51.100.9", victim_ip="192.0.2.3",
                                 src_rate=12.0, entropy=0.9912)
        self.assertEqual(self.logged_entropy(), [0.9912])

    def test_an_unmeasured_entropy_is_stored_as_null_not_zero(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertEqual(self.logged_entropy(), [None])

    def test_the_downgrade_to_a_rate_limit_carries_the_entropy_across(self):
        self.write_json(self.shared, ["198.51.100.9"])
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3",
                             src_rate=900.0, entropy=0.7654)
        self.assertEqual(self.logged_entropy(), [0.7654])

    def test_a_release_has_no_entropy_to_record(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3",
                             src_rate=900.0, entropy=0.5)
        enforcement.unblock_ip("198.51.100.9", victim_ip="192.0.2.3")
        self.assertEqual(self.logged_entropy(), [0.5, None])


class DdosSourceRecordTests(EnforcementTestCase):
    """Only a block names an address as an attacker.

    Rate-limiting is applied to whole groups at once by the aggregate
    fallback, and as a precaution during a flash crowd, so its membership is
    not evidence that any one address attacked anything.
    """

    def test_a_blocked_source_is_recorded_as_an_attacker(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3", src_rate=900.0)
        self.assertIn("198.51.100.9", state.ddos_sources)
        self.assertEqual(state.ddos_sources["198.51.100.9"]["action"], "Blocked")
        self.assertEqual(state.ddos_sources["198.51.100.9"]["victim_ip"], "192.0.2.3")
        self.assertEqual(state.ddos_sources["198.51.100.9"]["rate"], 900.0)

    def test_a_rate_limited_source_is_not_recorded_as_an_attacker(self):
        enforcement.ratelimit_ip("198.51.100.9", victim_ip="192.0.2.3", src_rate=120.0)
        self.assertEqual(state.ddos_sources, {})

    def test_a_flash_crowd_cap_is_not_recorded_as_an_attacker(self):
        enforcement.ratelimit_ip(
            "198.51.100.9", victim_ip="192.0.2.3", src_rate=120.0,
            classification=enforcement.CLASS_RATELIMITED_FLASH)
        self.assertEqual(state.ddos_sources, {})

    def test_a_later_rate_limit_clears_an_earlier_block_record(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3", src_rate=900.0)
        self.assertIn("198.51.100.9", state.ddos_sources)
        state.recently_blocked.clear()
        enforcement.ratelimit_ip("198.51.100.9", victim_ip="192.0.2.3", src_rate=12.0)
        self.assertEqual(state.ddos_sources, {})

    def test_a_flash_crowd_cap_is_recorded_under_its_own_label(self):
        enforcement.ratelimit_ip(
            "198.51.100.9", victim_ip="192.0.2.3", src_rate=120.0,
            classification=enforcement.CLASS_RATELIMITED_FLASH)
        self.assertEqual(
            self.logged(),
            [("198.51.100.9", "192.0.2.3", 120.0, "Rate Limited (Flash Crowd)")])

    def test_a_later_flash_crowd_verdict_clears_an_earlier_attack_record(self):
        enforcement.record_ddos_source(
            "198.51.100.9", enforcement.CLASS_BLOCKED, "192.0.2.3", 900.0, 1.0)
        enforcement.record_ddos_source(
            "198.51.100.9", enforcement.CLASS_RATELIMITED_FLASH, "192.0.2.3", 12.0, 2.0)
        self.assertEqual(state.ddos_sources, {})

    def test_the_record_is_capped_keeping_the_most_recent_sources(self):
        saved = state.DDOS_SOURCES_MAX
        state.DDOS_SOURCES_MAX = 10
        try:
            for index in range(60):
                enforcement.record_ddos_source(
                    "198.51.100.%d" % index, enforcement.CLASS_BLOCKED,
                    "192.0.2.3", float(index), float(index))
            self.assertLessEqual(len(state.ddos_sources), 10)
            self.assertIn("198.51.100.59", state.ddos_sources)
            self.assertNotIn("198.51.100.0", state.ddos_sources)
        finally:
            state.DDOS_SOURCES_MAX = saved

    def test_the_record_is_restored_from_the_incident_log(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3", src_rate=900.0)
        state.ddos_sources.clear()
        enforcement.load_ddos_sources()
        self.assertIn("198.51.100.9", state.ddos_sources)

    def test_the_restore_honours_the_most_recent_verdict(self):
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3", src_rate=900.0)
        state.recently_blocked.clear()
        enforcement.ratelimit_ip(
            "198.51.100.9", victim_ip="192.0.2.3", src_rate=12.0,
            classification=enforcement.CLASS_RATELIMITED_FLASH)
        state.ddos_sources.clear()
        enforcement.load_ddos_sources()
        self.assertEqual(state.ddos_sources, {})

    def test_a_released_address_is_dropped_from_the_dashboard(self):
        """The record survives the process, so the API filters on the live set."""
        enforcement.block_ip("198.51.100.9", victim_ip="192.0.2.3", src_rate=900.0)
        import api
        # api.enforcement is the same module object, so the originals have to
        # be captured before they are replaced.
        real_blocked = enforcement.get_blocked_ips
        real_ratelimited = enforcement.get_ratelimited_ips
        enforcement.get_blocked_ips = lambda: []
        enforcement.get_ratelimited_ips = lambda: []
        try:
            self.assertEqual(api.get_state()["ddos_sources"], [])
        finally:
            enforcement.get_blocked_ips = real_blocked
            enforcement.get_ratelimited_ips = real_ratelimited


if __name__ == "__main__":
    unittest.main()
