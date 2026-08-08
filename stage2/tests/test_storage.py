"""Tests for storage.py, the JSON persistence helpers."""

import json
import os
import stat
import unittest

import _support
from _support import temp_path, unlink

import storage


class LoadJsonFileTests(unittest.TestCase):
    def setUp(self):
        self.path = temp_path()
        os.unlink(self.path)  # start from "file does not exist"

    def tearDown(self):
        unlink(self.path)

    def test_creates_the_file_when_missing(self):
        storage.load_json_file(self.path, [])
        self.assertTrue(os.path.exists(self.path))

    def test_returns_the_default_when_missing(self):
        self.assertEqual(storage.load_json_file(self.path, ["seed"]), ["seed"])

    def test_writes_the_default_into_the_new_file(self):
        storage.load_json_file(self.path, {"a": 1})
        with open(self.path) as handle:
            self.assertEqual(json.load(handle), {"a": 1})

    def test_new_file_is_owner_only(self):
        storage.load_json_file(self.path, [])
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600, f"expected 0600, got {oct(mode)}")

    def test_reads_back_existing_content(self):
        with open(self.path, "w") as handle:
            json.dump(["198.51.100.1"], handle)
        self.assertEqual(storage.load_json_file(self.path, []), ["198.51.100.1"])

    def test_malformed_json_falls_back_to_default(self):
        with open(self.path, "w") as handle:
            handle.write("{not json at all")
        self.assertEqual(storage.load_json_file(self.path, ["fallback"]), ["fallback"])

    def test_empty_file_falls_back_to_default(self):
        open(self.path, "w").close()
        self.assertEqual(storage.load_json_file(self.path, {"k": "v"}), {"k": "v"})

    def test_malformed_json_does_not_destroy_the_file(self):
        with open(self.path, "w") as handle:
            handle.write("{still not json")
        storage.load_json_file(self.path, [])
        with open(self.path) as handle:
            self.assertEqual(handle.read(), "{still not json")

    def test_nested_structures_survive(self):
        payload = {"outer": {"inner": [1, 2, {"deep": True}]}}
        with open(self.path, "w") as handle:
            json.dump(payload, handle)
        self.assertEqual(storage.load_json_file(self.path, {}), payload)


class SaveJsonFileTests(unittest.TestCase):
    def setUp(self):
        self.path = temp_path()

    def tearDown(self):
        unlink(self.path)

    def test_writes_readable_json(self):
        storage.save_json_file(self.path, {"ip": "192.0.2.3"})
        with open(self.path) as handle:
            self.assertEqual(json.load(handle), {"ip": "192.0.2.3"})

    def test_saved_file_is_owner_only(self):
        storage.save_json_file(self.path, [])
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600, f"expected 0600, got {oct(mode)}")

    def test_overwrites_previous_content(self):
        storage.save_json_file(self.path, ["first"])
        storage.save_json_file(self.path, ["second"])
        with open(self.path) as handle:
            self.assertEqual(json.load(handle), ["second"])

    def test_unwritable_path_does_not_raise(self):
        # Enforcement calls this on a hot path; a failed write must be
        # logged and swallowed rather than taking the process down.
        storage.save_json_file("/proc/definitely/not/writable.json", {"a": 1})

    def test_round_trip_through_load(self):
        payload = {"victims": [{"ip": "192.0.2.4", "active": True}]}
        storage.save_json_file(self.path, payload)
        self.assertEqual(storage.load_json_file(self.path, {}), payload)


if __name__ == "__main__":
    unittest.main()
