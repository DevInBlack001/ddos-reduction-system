"""Tests for config.py: TLS detection, unit-file parsing, config merging."""

import json
import os
import unittest

import _support
from _support import temp_path, unlink

import config


class TlsEnabledTests(unittest.TestCase):
    def setUp(self):
        self._cert, self._key = config.TLS_CERT_PATH, config.TLS_KEY_PATH
        self.cert = temp_path(".pem")
        self.key = temp_path(".pem")

    def tearDown(self):
        config.TLS_CERT_PATH, config.TLS_KEY_PATH = self._cert, self._key
        unlink(self.cert, self.key)

    def test_false_when_neither_file_exists(self):
        config.TLS_CERT_PATH = self.cert + ".missing"
        config.TLS_KEY_PATH = self.key + ".missing"
        self.assertFalse(config.tls_enabled())

    def test_false_when_only_the_certificate_exists(self):
        config.TLS_CERT_PATH = self.cert
        config.TLS_KEY_PATH = self.key + ".missing"
        self.assertFalse(config.tls_enabled())

    def test_false_when_only_the_key_exists(self):
        config.TLS_CERT_PATH = self.cert + ".missing"
        config.TLS_KEY_PATH = self.key
        self.assertFalse(config.tls_enabled())

    def test_true_when_both_exist(self):
        config.TLS_CERT_PATH = self.cert
        config.TLS_KEY_PATH = self.key
        self.assertTrue(config.tls_enabled())

    def test_reflects_a_certificate_appearing_after_startup(self):
        # install.sh can generate the certificate after the process starts,
        # so this must not be cached.
        late = self.cert + ".late"
        config.TLS_CERT_PATH, config.TLS_KEY_PATH = late, self.key
        self.assertFalse(config.tls_enabled())
        open(late, "w").close()
        try:
            self.assertTrue(config.tls_enabled())
        finally:
            unlink(late)


class SnifferInterfaceTests(unittest.TestCase):
    def setUp(self):
        self._unit = config.STAGE1_UNIT_PATH
        self.unit = temp_path(".service")

    def tearDown(self):
        config.STAGE1_UNIT_PATH = self._unit
        unlink(self.unit)

    def write_unit(self, exec_line):
        with open(self.unit, "w") as handle:
            handle.write("[Service]\n" + exec_line + "\n")
        config.STAGE1_UNIT_PATH = self.unit

    def test_returns_none_pair_when_the_unit_is_absent(self):
        config.STAGE1_UNIT_PATH = self.unit + ".missing"
        self.assertEqual(config.get_sniffer_interfaces(), (None, None))

    def test_never_invents_a_default_interface(self):
        # It used to fall back to a hardcoded interface name, which then
        # appeared in the PDF report as though it had been detected.
        config.STAGE1_UNIT_PATH = self.unit + ".missing"
        ingress, _ = config.get_sniffer_interfaces()
        self.assertIsNone(ingress)

    def test_parses_the_ingress_interface(self):
        self.write_unit("ExecStart=/usr/local/bin/ddos_stage1 --interface eth0")
        self.assertEqual(config.get_sniffer_interfaces()[0], "eth0")

    def test_parses_the_egress_interface(self):
        self.write_unit("ExecStart=/usr/local/bin/ddos_stage1 --interface eth0 --egress-interface eth1")
        self.assertEqual(config.get_sniffer_interfaces()[1], "eth1")

    def test_parses_both_interfaces(self):
        self.write_unit("ExecStart=/x --interface eth0 --egress-interface eth1 --victim-ips 192.0.2.3")
        self.assertEqual(config.get_sniffer_interfaces(), ("eth0", "eth1"))

    def test_egress_is_none_when_not_configured(self):
        self.write_unit("ExecStart=/x --interface br0 --victim-subnet 192.0.2.0/24")
        self.assertEqual(config.get_sniffer_interfaces(), ("br0", None))

    def test_does_not_confuse_the_two_flags(self):
        # "--egress-interface" must not be read as "--interface".
        self.write_unit("ExecStart=/x --egress-interface eth1 --interface eth0")
        self.assertEqual(config.get_sniffer_interfaces(), ("eth0", "eth1"))

    def test_trailing_flag_with_no_value_is_ignored(self):
        self.write_unit("ExecStart=/x --interface")
        self.assertEqual(config.get_sniffer_interfaces(), (None, None))


class EnforcementConfigTests(unittest.TestCase):
    def setUp(self):
        self._path = config.ENFORCEMENT_CONFIG_PATH
        self.path = temp_path()
        os.unlink(self.path)
        config.ENFORCEMENT_CONFIG_PATH = self.path

    def tearDown(self):
        config.ENFORCEMENT_CONFIG_PATH = self._path
        unlink(self.path)

    def test_returns_defaults_when_no_file_exists(self):
        self.assertEqual(
            config.get_enforcement_config()["block_rate_floor_pps"],
            config.DEFAULT_ENFORCEMENT_CONFIG["block_rate_floor_pps"],
        )

    def test_saved_values_override_defaults(self):
        with open(self.path, "w") as handle:
            json.dump({"block_rate_floor_pps": 999.0}, handle)
        self.assertEqual(config.get_enforcement_config()["block_rate_floor_pps"], 999.0)

    def test_keys_absent_from_the_saved_file_still_resolve(self):
        # An older saved file must not hide newer settings.
        with open(self.path, "w") as handle:
            json.dump({"block_rate_floor_pps": 1.0}, handle)
        merged = config.get_enforcement_config()
        for key in config.DEFAULT_ENFORCEMENT_CONFIG:
            self.assertIn(key, merged)

    def test_every_default_key_is_present(self):
        merged = config.get_enforcement_config()
        self.assertEqual(set(merged), set(config.DEFAULT_ENFORCEMENT_CONFIG))

    def test_defaults_are_not_mutated_by_a_merge(self):
        original = dict(config.DEFAULT_ENFORCEMENT_CONFIG)
        with open(self.path, "w") as handle:
            json.dump({"block_rate_floor_pps": 12345.0}, handle)
        config.get_enforcement_config()
        self.assertEqual(config.DEFAULT_ENFORCEMENT_CONFIG, original)


if __name__ == "__main__":
    unittest.main()
