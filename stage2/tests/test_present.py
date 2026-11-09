import io
import json
import os
import sys
import tempfile
import unittest

import _support  # noqa: F401

SCRIPTS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
sys.path.insert(0, SCRIPTS)
import present  # noqa: E402

STAGES_FILE = os.path.abspath(os.path.join(SCRIPTS, "..", "docs", "presentation", "stages.json"))

SAMPLE = {
    "title": "Demo",
    "stages": [
        {"id": "one", "title": "First", "description": "The first stage.",
         "steps": ["Do a thing.", {"text": "Show it.", "command": ["echo", "hi"]}]},
        {"id": "two", "title": "Second", "description": "The second stage.", "steps": ["Do another."]},
    ],
}


def render(data, **kwargs):
    out = io.StringIO()
    kwargs.setdefault("runner", lambda command: ["ran " + " ".join(command)])
    present.present(data, kwargs.pop("start_id", None), 0, kwargs.pop("run", False),
                    present.Style(False), out=out, interactive=False, **kwargs)
    return out.getvalue()


class StagesFileTests(unittest.TestCase):
    def test_the_shipped_stages_file_is_valid(self):
        data = present.load_stages(STAGES_FILE)
        self.assertGreaterEqual(len(data["stages"]), 1)

    def test_the_shipped_stages_contain_no_em_dashes(self):
        with open(STAGES_FILE, encoding="utf-8") as f:
            self.assertNotIn("—", f.read())

    def test_every_demo_command_is_a_list_so_no_shell_is_involved(self):
        for stage in present.load_stages(STAGES_FILE)["stages"]:
            for step in stage["steps"]:
                _, command = present.step_parts(step)
                self.assertTrue(command is None or isinstance(command, list))


class ValidationTests(unittest.TestCase):
    def test_a_stage_without_steps_is_reported(self):
        data = {"stages": [{"id": "a", "title": "A", "description": "d", "steps": []}]}
        self.assertTrue(any("steps" in p for p in present.validate(data)))

    def test_a_repeated_id_is_reported(self):
        stage = {"id": "a", "title": "A", "description": "d", "steps": ["x"]}
        self.assertTrue(any("repeats" in p for p in present.validate({"stages": [stage, dict(stage)]})))

    def test_a_command_that_is_a_string_is_reported(self):
        data = {"stages": [{"id": "a", "title": "A", "description": "d",
                            "steps": [{"text": "x", "command": "ls -l"}]}]}
        self.assertTrue(any("command" in p for p in present.validate(data)))

    def test_a_file_that_is_not_json_is_rejected_by_the_command_line(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("not json")
        self.addCleanup(os.unlink, f.name)
        self.assertEqual(present.main(["--stages-file", f.name, "--check"]), 1)


class PresentationTests(unittest.TestCase):
    def test_each_stage_shows_its_title_description_and_numbered_steps(self):
        text = render(SAMPLE)
        self.assertIn("1/2  First", text)
        self.assertIn("The first stage.", text)
        self.assertIn("1. Do a thing.", text)
        self.assertIn("2/2  Second", text)

    def test_demo_commands_run_only_when_asked(self):
        self.assertNotIn("ran echo hi", render(SAMPLE))
        self.assertIn("ran echo hi", render(SAMPLE, run=True))

    def test_the_presentation_can_start_at_a_later_stage(self):
        text = render(SAMPLE, start_id="two")
        self.assertNotIn("First", text)
        self.assertIn("Second", text)

    def test_an_unknown_stage_id_names_the_valid_ones(self):
        with self.assertRaises(SystemExit) as caught:
            render(SAMPLE, start_id="nope")
        self.assertIn("one, two", str(caught.exception))

    def test_a_missing_demo_program_is_reported_and_not_raised(self):
        self.assertIn("not installed", present.run_command(["definitely-not-a-program-xyz"])[0])

    def test_demo_command_output_is_capped(self):
        lines = present.run_command([sys.executable, "-c", "print('x\\n' * 100)"])
        self.assertEqual(len(lines), present.OUTPUT_LINES_MAX + 1)


if __name__ == "__main__":
    unittest.main()
