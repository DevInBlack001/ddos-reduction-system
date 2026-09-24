"""Tests for playbooks.py: trigger evaluation, run lifecycle, and stage
execution, per docs/specs/2026-09-13-playbooks-design.md's Testing Plan.

enforcement.py, alerts.py, and report_pdf.py are mocked throughout: these
tests assert the correct function is called with the correct target, not
that a real iptables rule or a real alert was sent.
"""

import json
import time
import unittest
from unittest import mock

import _support
from _support import make_logs_db, reset_db_module, temp_path, unlink

import config
import db
import playbooks


def _definition(triggers, stages, trigger_mode="any"):
    return json.dumps({
        "triggers": triggers,
        "trigger_mode": trigger_mode,
        "stages": stages,
    })


class DefinitionValidationTests(unittest.TestCase):
    """The one gate both editing surfaces go through: a hand-edited
    definition can never express anything the form builder couldn't have
    produced."""

    def test_a_well_formed_definition_round_trips_unchanged(self):
        definition = {
            "triggers": [{"type": "tier_reached", "min_tier": 1}],
            "trigger_mode": "any",
            "stages": [{"type": "notify", "delay_seconds": 0, "channel": "discord"}],
        }
        self.assertEqual(playbooks.validate_definition(definition), definition)

    def test_a_trigger_type_outside_the_closed_list_is_rejected(self):
        definition = {
            "triggers": [{"type": "custom_script"}],
            "stages": [{"type": "notify"}],
        }
        with self.assertRaises(playbooks.DefinitionError):
            playbooks.validate_definition(definition)

    def test_a_stage_type_outside_the_closed_list_is_rejected(self):
        definition = {
            "triggers": [{"type": "tier_reached", "min_tier": 1}],
            "stages": [{"type": "run_shell_command"}],
        }
        with self.assertRaises(playbooks.DefinitionError):
            playbooks.validate_definition(definition)

    def test_a_definition_with_no_triggers_is_rejected(self):
        definition = {"triggers": [], "stages": [{"type": "notify"}]}
        with self.assertRaises(playbooks.DefinitionError):
            playbooks.validate_definition(definition)

    def test_a_definition_with_no_stages_is_rejected(self):
        definition = {"triggers": [{"type": "tier_reached", "min_tier": 1}], "stages": []}
        with self.assertRaises(playbooks.DefinitionError):
            playbooks.validate_definition(definition)

    def test_a_negative_delay_is_rejected(self):
        definition = {
            "triggers": [{"type": "tier_reached", "min_tier": 1}],
            "stages": [{"type": "notify", "delay_seconds": -5}],
        }
        with self.assertRaises(playbooks.DefinitionError):
            playbooks.validate_definition(definition)

    def test_an_unrecognised_trigger_mode_is_rejected(self):
        definition = {
            "triggers": [{"type": "tier_reached", "min_tier": 1}],
            "trigger_mode": "majority",
            "stages": [{"type": "notify"}],
        }
        with self.assertRaises(playbooks.DefinitionError):
            playbooks.validate_definition(definition)

    def test_a_form_built_and_a_hand_written_definition_of_the_same_playbook_match(self):
        form_built = {
            "triggers": [{"type": "persistence", "consecutive_windows": 5}],
            "trigger_mode": "any",
            "stages": [{"type": "escalate", "delay_seconds": 300, "target_tier": 2}],
        }
        hand_written = json.loads(json.dumps(form_built))
        self.assertEqual(
            playbooks.validate_definition(form_built),
            playbooks.validate_definition(hand_written),
        )


class TriggerEvaluationTests(unittest.TestCase):
    """Each trigger type independently, and both trigger_mode combinations."""

    def test_tier_reached_fires_at_or_above_its_min_tier(self):
        definition = json.loads(_definition([{"type": "tier_reached", "min_tier": 2}], [{"type": "notify"}]))
        self.assertTrue(playbooks.evaluate_triggers(definition, 2, 0, 0))
        self.assertTrue(playbooks.evaluate_triggers(definition, 3, 0, 0))

    def test_tier_reached_does_not_fire_below_its_min_tier(self):
        definition = json.loads(_definition([{"type": "tier_reached", "min_tier": 2}], [{"type": "notify"}]))
        self.assertFalse(playbooks.evaluate_triggers(definition, 1, 0, 0))
        self.assertFalse(playbooks.evaluate_triggers(definition, 0, 0, 0))

    def test_persistence_fires_at_or_above_its_consecutive_window_count(self):
        definition = json.loads(
            _definition([{"type": "persistence", "consecutive_windows": 5}], [{"type": "notify"}])
        )
        self.assertTrue(playbooks.evaluate_triggers(definition, 0, 5, 0))
        self.assertFalse(playbooks.evaluate_triggers(definition, 0, 4, 0))

    def test_scale_fires_at_or_above_its_host_count(self):
        definition = json.loads(
            _definition([{"type": "scale", "min_hosts_simultaneously": 3}], [{"type": "notify"}])
        )
        self.assertTrue(playbooks.evaluate_triggers(definition, 0, 0, 3))
        self.assertFalse(playbooks.evaluate_triggers(definition, 0, 0, 2))

    def test_trigger_mode_any_fires_when_only_one_of_several_triggers_matches(self):
        definition = json.loads(_definition(
            [{"type": "tier_reached", "min_tier": 4}, {"type": "persistence", "consecutive_windows": 10}],
            [{"type": "notify"}], trigger_mode="any",
        ))
        self.assertTrue(playbooks.evaluate_triggers(definition, 1, 10, 0))

    def test_trigger_mode_all_requires_every_trigger_to_match(self):
        definition = json.loads(_definition(
            [{"type": "tier_reached", "min_tier": 1}, {"type": "persistence", "consecutive_windows": 10}],
            [{"type": "notify"}], trigger_mode="all",
        ))
        self.assertFalse(playbooks.evaluate_triggers(definition, 1, 5, 0))
        self.assertTrue(playbooks.evaluate_triggers(definition, 1, 10, 0))


class RunLifecycleTestCase(unittest.TestCase):
    """Start on trigger, no duplicate run while one is already running,
    stage advancement respecting delay_seconds, completion after the last
    stage. A real temp database, since this is what schema.py and db.py
    actually do, not a stand-in for it."""

    def setUp(self):
        self._saved_db_path = config.DB_PATH
        config.DB_PATH = make_logs_db()
        reset_db_module()

    def tearDown(self):
        reset_db_module()
        unlink(config.DB_PATH)
        config.DB_PATH = self._saved_db_path

    def _insert_playbook(self, definition_dict, scope_type="host", scope_value="192.0.2.10"):
        now = time.time()
        conn = db._open()
        cur = conn.execute(
            "INSERT INTO playbooks (name, target_scope_type, target_scope_value, enabled, "
            "definition, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?, ?)",
            ("test playbook", scope_type, scope_value, json.dumps(definition_dict), now, now),
        )
        conn.commit()
        return cur.lastrowid

    def test_a_firing_trigger_starts_a_run(self):
        playbook_id = self._insert_playbook({
            "triggers": [{"type": "tier_reached", "min_tier": 1}],
            "stages": [{"type": "notify", "delay_seconds": 0, "channel": "discord"}],
        })
        with mock.patch("playbooks.alerts.dispatch_alert"):
            playbooks.check_and_start_runs("192.0.2.10", 1, 1, 1, "198.51.100.5")
        run = db.get_active_playbook_run(playbook_id, "192.0.2.10")
        self.assertIsNotNone(run)

    def test_a_non_firing_trigger_starts_no_run(self):
        self._insert_playbook({
            "triggers": [{"type": "tier_reached", "min_tier": 4}],
            "stages": [{"type": "notify"}],
        })
        playbooks.check_and_start_runs("192.0.2.10", 1, 1, 1, "198.51.100.5")
        self.assertEqual(db.get_running_playbook_runs(), [])

    def test_a_second_trigger_while_a_run_is_already_active_does_not_start_a_duplicate(self):
        playbook_id = self._insert_playbook({
            "triggers": [{"type": "tier_reached", "min_tier": 1}],
            "stages": [{"type": "notify", "delay_seconds": 9999}],
        })
        with mock.patch("playbooks.alerts.dispatch_alert"):
            playbooks.check_and_start_runs("192.0.2.10", 1, 1, 1, "198.51.100.5")
            playbooks.check_and_start_runs("192.0.2.10", 2, 2, 1, "198.51.100.5")
        self.assertEqual(len(db.get_running_playbook_runs()), 1)

    def test_a_stage_does_not_fire_before_its_delay_has_elapsed(self):
        self._insert_playbook({
            "triggers": [{"type": "tier_reached", "min_tier": 1}],
            "stages": [{"type": "notify", "delay_seconds": 300, "channel": "discord"}],
        })
        start = time.time()
        with mock.patch("playbooks.alerts.dispatch_alert"):
            playbooks.check_and_start_runs("192.0.2.10", 1, 1, 1, "198.51.100.5", now=start)
            playbooks.advance_runs(now=start + 10)
            dispatched = playbooks.alerts.dispatch_alert.called
        self.assertFalse(dispatched)
        run = db.get_active_playbook_run(1, "192.0.2.10")
        self.assertEqual(run[1], 0)  # current_stage_index unchanged

    def test_a_stage_fires_once_its_delay_has_elapsed_and_advances_to_the_next_one(self):
        self._insert_playbook({
            "triggers": [{"type": "tier_reached", "min_tier": 1}],
            "stages": [
                {"type": "notify", "delay_seconds": 0, "channel": "discord"},
                {"type": "escalate", "delay_seconds": 300, "target_tier": 2},
            ],
        })
        start = time.time()
        with mock.patch("playbooks.alerts.dispatch_alert") as notify:
            playbooks.check_and_start_runs("192.0.2.10", 1, 1, 1, "198.51.100.5", now=start)
            playbooks.advance_runs(now=start)
        notify.assert_called_once()
        run = db.get_active_playbook_run(1, "192.0.2.10")
        self.assertEqual(run[1], 1)  # advanced to stage index 1

    def test_a_run_completes_after_its_last_stage_fires(self):
        self._insert_playbook({
            "triggers": [{"type": "tier_reached", "min_tier": 1}],
            "stages": [{"type": "notify", "delay_seconds": 0, "channel": "discord"}],
        })
        start = time.time()
        with mock.patch("playbooks.alerts.dispatch_alert"):
            playbooks.check_and_start_runs("192.0.2.10", 1, 1, 1, "198.51.100.5", now=start)
            playbooks.advance_runs(now=start)
        self.assertIsNone(db.get_active_playbook_run(1, "192.0.2.10"))
        events = db._open().execute("SELECT stage_type FROM playbook_events").fetchall()
        self.assertEqual(events, [("notify",)])

    def test_a_playbook_scoped_to_all_matches_every_host(self):
        self._insert_playbook(
            {"triggers": [{"type": "tier_reached", "min_tier": 1}], "stages": [{"type": "notify"}]},
            scope_type="all", scope_value=None,
        )
        with mock.patch("playbooks.alerts.dispatch_alert"):
            playbooks.check_and_start_runs("192.0.2.20", 1, 1, 1, "198.51.100.5")
        self.assertIsNotNone(db.get_active_playbook_run(1, "192.0.2.20"))

    def test_a_disabled_playbook_never_starts_a_run(self):
        now = time.time()
        conn = db._open()
        conn.execute(
            "INSERT INTO playbooks (name, target_scope_type, target_scope_value, enabled, "
            "definition, created_at, updated_at) VALUES (?, 'host', '192.0.2.10', 0, ?, ?, ?)",
            ("disabled", json.dumps({
                "triggers": [{"type": "tier_reached", "min_tier": 1}],
                "stages": [{"type": "notify"}],
            }), now, now),
        )
        conn.commit()
        playbooks.check_and_start_runs("192.0.2.10", 1, 1, 1, "198.51.100.5")
        self.assertEqual(db.get_running_playbook_runs(), [])


class StageExecutionTests(unittest.TestCase):
    """Each stage type's action, mocked, asserting the correct function is
    called with the correct target."""

    def test_escalate_at_tier_one_or_two_calls_block_ip(self):
        with mock.patch("playbooks.enforcement.block_ip") as block, \
             mock.patch("playbooks.enforcement.ratelimit_ip") as ratelimit:
            playbooks.execute_stage(
                {"type": "escalate", "target_tier": 1}, "192.0.2.10", "198.51.100.5"
            )
        block.assert_called_once()
        self.assertEqual(block.call_args.args[0], "198.51.100.5")
        ratelimit.assert_not_called()

    def test_escalate_at_tier_three_or_four_calls_ratelimit_ip(self):
        with mock.patch("playbooks.enforcement.block_ip") as block, \
             mock.patch("playbooks.enforcement.ratelimit_ip") as ratelimit:
            playbooks.execute_stage(
                {"type": "escalate", "target_tier": 3}, "192.0.2.10", "198.51.100.5"
            )
        ratelimit.assert_called_once()
        self.assertEqual(ratelimit.call_args.args[0], "198.51.100.5")
        block.assert_not_called()

    def test_escalate_with_no_attributable_source_calls_neither(self):
        with mock.patch("playbooks.enforcement.block_ip") as block, \
             mock.patch("playbooks.enforcement.ratelimit_ip") as ratelimit:
            playbooks.execute_stage({"type": "escalate", "target_tier": 1}, "192.0.2.10", None)
        block.assert_not_called()
        ratelimit.assert_not_called()

    def test_notify_calls_dispatch_alert_with_the_target_host_in_the_message(self):
        with mock.patch("playbooks.alerts.dispatch_alert") as dispatch:
            playbooks.execute_stage({"type": "notify", "channel": "discord"}, "192.0.2.10", "198.51.100.5")
        dispatch.assert_called_once()
        self.assertIn("192.0.2.10", dispatch.call_args.args[1])

    def test_report_writes_a_pdf_under_the_configured_directory(self):
        reports_dir = temp_path(".d")
        unlink(reports_dir)  # _execute_report creates the directory itself
        saved = config.PLAYBOOK_REPORTS_DIR
        config.PLAYBOOK_REPORTS_DIR = reports_dir
        try:
            with mock.patch("report_data.build_context", return_value={}), \
                 mock.patch("report_pdf.render_pdf", return_value=b"%PDF-fake"):
                detail = playbooks.execute_stage({"type": "report"}, "192.0.2.10", None)
            self.assertTrue(detail.startswith(reports_dir))
            with open(detail, "rb") as f:
                self.assertEqual(f.read(), b"%PDF-fake")
        finally:
            config.PLAYBOOK_REPORTS_DIR = saved
            import shutil
            shutil.rmtree(reports_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
