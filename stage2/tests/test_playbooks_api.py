"""Tests for playbooks_api.py: the dashboard's playbook CRUD, definition
validation, run history, and generated-report routes.
"""

import json
import os
import time
import unittest

from fastapi import HTTPException

import _support
from _support import make_logs_db, reset_db_module, temp_path, unlink

import config
import db
import playbooks
import playbooks_api
from models import PlaybookPayload


VALID_DEFINITION = {
    "triggers": [{"type": "tier_reached", "min_tier": 1}],
    "trigger_mode": "any",
    "stages": [{"type": "notify", "delay_seconds": 0, "channel": "discord"}],
}


def _payload(**overrides):
    fields = dict(
        name="test playbook",
        target_scope_type="host",
        target_scope_value="192.0.2.10",
        enabled=True,
        definition=VALID_DEFINITION,
    )
    fields.update(overrides)
    return PlaybookPayload(**fields)


class PlaybooksApiTestCase(unittest.TestCase):
    def setUp(self):
        self._db_path = config.DB_PATH
        self.db_path = make_logs_db()
        config.DB_PATH = self.db_path
        reset_db_module()

    def tearDown(self):
        reset_db_module()
        unlink(self.db_path)
        config.DB_PATH = self._db_path


class CrudTests(PlaybooksApiTestCase):
    def test_a_new_deployment_lists_no_playbooks(self):
        self.assertEqual(playbooks_api.list_playbooks(), {"playbooks": []})

    def test_creating_a_playbook_returns_it_with_an_id(self):
        result = playbooks_api.create_playbook(_payload())
        self.assertIsInstance(result["id"], int)
        self.assertEqual(result["name"], "test playbook")
        self.assertEqual(result["target_scope_value"], "192.0.2.10")
        self.assertEqual(result["definition"], VALID_DEFINITION)
        self.assertTrue(result["enabled"])

    def test_a_created_playbook_appears_in_the_list(self):
        playbooks_api.create_playbook(_payload())
        result = playbooks_api.list_playbooks()
        self.assertEqual(len(result["playbooks"]), 1)

    def test_getting_a_missing_playbook_is_a_404(self):
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.get_playbook(999)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_getting_an_existing_playbook_returns_it(self):
        created = playbooks_api.create_playbook(_payload())
        fetched = playbooks_api.get_playbook(created["id"])
        self.assertEqual(fetched["id"], created["id"])

    def test_updating_a_playbook_changes_its_stored_definition(self):
        created = playbooks_api.create_playbook(_payload())
        new_definition = {
            "triggers": [{"type": "persistence", "consecutive_windows": 3}],
            "stages": [{"type": "escalate", "target_tier": 2}],
        }
        updated = playbooks_api.update_playbook(created["id"], _payload(definition=new_definition))
        self.assertEqual(updated["definition"], new_definition)

    def test_updating_a_missing_playbook_is_a_404(self):
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.update_playbook(999, _payload())
        self.assertEqual(ctx.exception.status_code, 404)

    def test_toggling_a_playbook_flips_enabled(self):
        created = playbooks_api.create_playbook(_payload(enabled=True))
        result = playbooks_api.toggle_playbook(created["id"], {"enabled": False})
        self.assertFalse(result["enabled"])

    def test_toggle_rejects_a_malformed_body(self):
        created = playbooks_api.create_playbook(_payload())
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.toggle_playbook(created["id"], {"enabled": "yes"})
        self.assertEqual(ctx.exception.status_code, 400)

    def test_deleting_a_playbook_removes_it_from_the_list(self):
        created = playbooks_api.create_playbook(_payload())
        playbooks_api.delete_playbook(created["id"])
        self.assertEqual(playbooks_api.list_playbooks(), {"playbooks": []})

    def test_deleting_a_missing_playbook_is_a_404(self):
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.delete_playbook(999)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_deleting_a_playbook_also_removes_its_run_history(self):
        created = playbooks_api.create_playbook(_payload())
        run_id = db.start_playbook_run(created["id"], "192.0.2.10", "198.51.100.5", "test", time.time())
        db.record_playbook_event(run_id, 0, "notify", "198.51.100.5", "notified", time.time())
        playbooks_api.delete_playbook(created["id"])
        self.assertEqual(playbooks_api.list_run_events(run_id), {"events": []})


class ScopeValidationTests(PlaybooksApiTestCase):
    def test_host_scope_requires_a_valid_address(self):
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.create_playbook(_payload(target_scope_type="host", target_scope_value="not-an-ip"))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_host_scope_requires_a_value_at_all(self):
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.create_playbook(_payload(target_scope_type="host", target_scope_value=None))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_subnet_scope_requires_a_valid_cidr(self):
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.create_playbook(_payload(target_scope_type="subnet", target_scope_value="not-a-cidr"))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_subnet_scope_accepts_a_valid_cidr(self):
        result = playbooks_api.create_playbook(
            _payload(target_scope_type="subnet", target_scope_value="192.0.2.0/24")
        )
        self.assertEqual(result["target_scope_value"], "192.0.2.0/24")

    def test_all_scope_discards_any_value_sent(self):
        result = playbooks_api.create_playbook(
            _payload(target_scope_type="all", target_scope_value="192.0.2.10")
        )
        self.assertIsNone(result["target_scope_value"])


class DefinitionValidationTests(PlaybooksApiTestCase):
    def test_creating_with_an_invalid_definition_is_a_400(self):
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.create_playbook(_payload(definition={"triggers": [], "stages": []}))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_validate_endpoint_reports_a_well_formed_definition_as_valid(self):
        result = playbooks_api.validate_definition_only(VALID_DEFINITION)
        self.assertTrue(result["valid"])

    def test_validate_endpoint_reports_an_invalid_trigger_type_as_invalid(self):
        result = playbooks_api.validate_definition_only({
            "triggers": [{"type": "not_a_real_trigger"}],
            "stages": [{"type": "notify"}],
        })
        self.assertFalse(result["valid"])
        self.assertIn("error", result)

    def test_parse_yaml_normalizes_to_the_same_shape_as_json(self):
        yaml_text = (
            "triggers:\n"
            "  - type: tier_reached\n"
            "    min_tier: 1\n"
            "stages:\n"
            "  - type: notify\n"
            "    delay_seconds: 0\n"
        )
        result = playbooks_api.parse_yaml_definition({"yaml": yaml_text})
        self.assertEqual(result["definition"]["triggers"][0]["type"], "tier_reached")
        self.assertEqual(result["definition"]["stages"][0]["type"], "notify")

    def test_parse_yaml_rejects_a_non_object_top_level(self):
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.parse_yaml_definition({"yaml": "- just\n- a\n- list\n"})
        self.assertEqual(ctx.exception.status_code, 400)

    def test_parse_yaml_rejects_malformed_yaml(self):
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.parse_yaml_definition({"yaml": "key: [unclosed"})
        self.assertEqual(ctx.exception.status_code, 400)


class RunHistoryTests(PlaybooksApiTestCase):
    def test_a_new_deployment_has_no_run_history(self):
        self.assertEqual(playbooks_api.list_runs(), {"runs": []})

    def test_a_started_run_appears_in_the_history_with_its_playbook_name(self):
        created = playbooks_api.create_playbook(_payload())
        db.start_playbook_run(created["id"], "192.0.2.10", "198.51.100.5", "tier=1", time.time())
        result = playbooks_api.list_runs()
        self.assertEqual(len(result["runs"]), 1)
        self.assertEqual(result["runs"][0]["playbook_name"], "test playbook")

    def test_events_for_a_run_come_back_in_stage_order(self):
        created = playbooks_api.create_playbook(_payload())
        run_id = db.start_playbook_run(created["id"], "192.0.2.10", "198.51.100.5", "tier=1", time.time())
        db.record_playbook_event(run_id, 1, "escalate", "198.51.100.5", "blocked", time.time())
        db.record_playbook_event(run_id, 0, "notify", "198.51.100.5", "notified", time.time())
        result = playbooks_api.list_run_events(run_id)
        self.assertEqual([e["stage_index"] for e in result["events"]], [0, 1])


class ReportListingTests(PlaybooksApiTestCase):
    def setUp(self):
        super().setUp()
        self._reports_dir = config.PLAYBOOK_REPORTS_DIR
        self.reports_dir = temp_path(".d")
        unlink(self.reports_dir)  # temp_path creates a file; the dir is created lazily by the route
        config.PLAYBOOK_REPORTS_DIR = self.reports_dir

    def tearDown(self):
        super().tearDown()
        config.PLAYBOOK_REPORTS_DIR = self._reports_dir
        if os.path.isdir(self.reports_dir):
            import shutil
            shutil.rmtree(self.reports_dir, ignore_errors=True)

    def test_an_uncreated_reports_directory_lists_as_empty(self):
        self.assertEqual(playbooks_api.list_reports(), {"reports": []})

    def test_a_written_pdf_is_listed(self):
        os.makedirs(self.reports_dir, exist_ok=True)
        with open(os.path.join(self.reports_dir, "playbook_report_192.0.2.10_1.pdf"), "wb") as f:
            f.write(b"%PDF-fake")
        result = playbooks_api.list_reports()
        self.assertEqual(len(result["reports"]), 1)
        self.assertEqual(result["reports"][0]["filename"], "playbook_report_192.0.2.10_1.pdf")

    def test_a_non_pdf_file_is_not_listed(self):
        os.makedirs(self.reports_dir, exist_ok=True)
        with open(os.path.join(self.reports_dir, "notes.txt"), "w") as f:
            f.write("not a report")
        self.assertEqual(playbooks_api.list_reports(), {"reports": []})

    def test_downloading_a_real_report_succeeds(self):
        os.makedirs(self.reports_dir, exist_ok=True)
        path = os.path.join(self.reports_dir, "playbook_report_192.0.2.10_1.pdf")
        with open(path, "wb") as f:
            f.write(b"%PDF-fake")
        response = playbooks_api.download_report("playbook_report_192.0.2.10_1.pdf")
        self.assertEqual(response.path, path)

    def test_downloading_a_missing_report_is_a_404(self):
        os.makedirs(self.reports_dir, exist_ok=True)
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.download_report("does_not_exist.pdf")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_downloading_rejects_a_path_traversal_attempt(self):
        os.makedirs(self.reports_dir, exist_ok=True)
        with self.assertRaises(HTTPException) as ctx:
            playbooks_api.download_report("../../etc/passwd")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_downloading_refuses_a_symlink(self):
        os.makedirs(self.reports_dir, exist_ok=True)
        target = temp_path(".pdf")
        with open(target, "wb") as f:
            f.write(b"%PDF-outside")
        link_path = os.path.join(self.reports_dir, "linked.pdf")
        os.symlink(target, link_path)
        try:
            with self.assertRaises(HTTPException) as ctx:
                playbooks_api.download_report("linked.pdf")
            self.assertEqual(ctx.exception.status_code, 404)
        finally:
            unlink(target)


if __name__ == "__main__":
    unittest.main()
