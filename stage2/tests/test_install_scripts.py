import os
import shutil
import subprocess
import tempfile
import unittest

import _support  # noqa: F401

SCRIPTS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))


def run(script, *args, cwd=None):
    return subprocess.run(["bash", os.path.join(SCRIPTS, script), *args], capture_output=True, text=True,
                          timeout=60, cwd=cwd)


class InstallerInputTests(unittest.TestCase):
    """Values written into root run systemd units are checked before anything
    else happens. These run without root, so they only reach the argument
    checks, which come before the root check."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def csv(self, name):
        path = os.path.join(self.dir, name)
        with open(path, "w") as handle:
            handle.write("x\n")
        return path

    def test_a_training_csv_with_a_quote_is_refused_by_update(self):
        result = run("update.sh", "--training-csv", self.csv("a'b.csv"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--training-csv may only contain", result.stderr + result.stdout)

    def test_a_training_csv_with_a_command_substitution_is_refused_by_install(self):
        result = run("install.sh", "--training-csv", self.csv("a$(id).csv"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--training-csv may only contain", result.stderr + result.stdout)

    def test_a_training_csv_with_a_space_is_refused(self):
        result = run("update.sh", "--training-csv", self.csv("a b.csv"))
        self.assertIn("--training-csv may only contain", result.stderr + result.stdout)

    def test_an_ordinary_training_csv_passes_the_path_check(self):
        result = run("update.sh", "--training-csv", self.csv("training_data_v2.csv"))
        self.assertNotIn("--training-csv may only contain", result.stderr + result.stdout)

    def test_an_interface_name_with_extra_arguments_is_refused(self):
        result = run("install.sh", "--interface", "eth0 --bpf-object /tmp/evil.o")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("interface name", result.stderr + result.stdout)

    def test_victim_addresses_with_a_shell_character_are_refused(self):
        result = run("install.sh", "--victim-ips", "192.0.2.10;id")
        self.assertIn("victim IPs", result.stderr + result.stdout)

    def test_a_tuning_value_that_is_not_a_number_is_refused(self):
        result = run("install.sh", "--rate-sigma-floor", "7.8 --extra")
        self.assertIn("--rate-sigma-floor takes a number", result.stderr + result.stdout)

    def test_ordinary_values_pass_the_argument_checks(self):
        result = run("install.sh", "--interface", "ens192", "--victim-subnet", "192.0.2.0/24",
                     "--exclude-ips", "192.0.2.1,192.0.2.2", "--k", "2.5")
        combined = result.stderr + result.stdout
        for phrase in ("interface name", "victim subnet", "excluded IPs", "takes a number"):
            self.assertNotIn(phrase, combined)


if __name__ == "__main__":
    unittest.main()
