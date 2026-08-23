"""Tests for models.py: the request payloads and the IP validator.

These are the outermost input gate. Anything that slips through here can
reach ipset, so the rejections matter as much as the acceptances.
"""

import unittest

import _support

from pydantic import ValidationError

import models
from models import (
    CreateUserPayload,
    DeleteUserPayload,
    EnforcementConfigPayload,
    IpPayload,
    SetPasswordPayload,
    VictimPayload,
)


class IpValidatorTests(unittest.TestCase):
    def test_accepts_an_ipv4_host(self):
        self.assertEqual(models._validate_host_ip("192.0.2.3"), "192.0.2.3")

    def test_accepts_an_ipv6_host(self):
        self.assertEqual(models._validate_host_ip("2001:db8::1"), "2001:db8::1")

    def test_rejects_cidr_notation(self):
        # ipset hash:ip would expand a range into every host in it, so a
        # CIDR string must never reach enforcement.
        with self.assertRaises(ValueError):
            models._validate_host_ip("192.0.2.0/24")

    def test_rejects_a_hostname(self):
        with self.assertRaises(ValueError):
            models._validate_host_ip("victim.example.com")

    def test_rejects_an_octet_above_255(self):
        with self.assertRaises(ValueError):
            models._validate_host_ip("192.0.2.999")

    def test_rejects_an_empty_string(self):
        with self.assertRaises(ValueError):
            models._validate_host_ip("")

    def test_rejects_a_shell_metacharacter_payload(self):
        with self.assertRaises(ValueError):
            models._validate_host_ip("192.0.2.1; rm -rf /")

    def test_rejects_an_html_payload(self):
        with self.assertRaises(ValueError):
            models._validate_host_ip("<script>alert(1)</script>")


class IpPayloadTests(unittest.TestCase):
    def test_accepts_a_valid_ip(self):
        self.assertEqual(IpPayload(ip="192.0.2.3").ip, "192.0.2.3")

    def test_victim_ip_is_optional(self):
        self.assertIsNone(IpPayload(ip="192.0.2.3").victim_ip)

    def test_validates_victim_ip_when_supplied(self):
        with self.assertRaises(ValidationError):
            IpPayload(ip="192.0.2.3", victim_ip="not-an-ip")

    def test_rejects_an_invalid_ip(self):
        with self.assertRaises(ValidationError):
            IpPayload(ip="999.999.999.999")


class VictimPayloadTests(unittest.TestCase):
    def test_accepts_a_normal_description(self):
        self.assertEqual(VictimPayload(ip="192.0.2.4", description="web").description, "web")

    def test_rejects_an_overlong_description(self):
        with self.assertRaises(ValidationError):
            VictimPayload(ip="192.0.2.4", description="x" * 201)

    def test_accepts_a_description_at_the_limit(self):
        VictimPayload(ip="192.0.2.4", description="x" * 200)


class UserPayloadTests(unittest.TestCase):
    def test_create_requires_the_callers_own_password(self):
        with self.assertRaises(ValidationError):
            CreateUserPayload(username="alice", password="longenough")

    def test_create_accepts_a_complete_payload(self):
        payload = CreateUserPayload(username="alice", password="longenough", admin_password="mine")
        self.assertEqual(payload.username, "alice")

    def test_create_rejects_a_short_password(self):
        with self.assertRaises(ValidationError):
            CreateUserPayload(username="alice", password="short", admin_password="mine")

    def test_create_rejects_an_empty_username(self):
        with self.assertRaises(ValidationError):
            CreateUserPayload(username="", password="longenough", admin_password="mine")

    def test_create_rejects_an_overlong_username(self):
        with self.assertRaises(ValidationError):
            CreateUserPayload(username="x" * 65, password="longenough", admin_password="mine")

    def test_admin_password_has_no_length_floor(self):
        # It is checked against an existing bcrypt hash, so it must accept
        # whatever the account's real password already is.
        CreateUserPayload(username="alice", password="longenough", admin_password="x")

    def test_set_password_requires_the_callers_own_password(self):
        with self.assertRaises(ValidationError):
            SetPasswordPayload(username="alice", new_password="longenough")

    def test_set_password_rejects_a_short_new_password(self):
        with self.assertRaises(ValidationError):
            SetPasswordPayload(username="alice", new_password="short", admin_password="mine")

    def test_delete_requires_the_callers_own_password(self):
        with self.assertRaises(ValidationError):
            DeleteUserPayload(username="alice")

    def test_delete_accepts_a_complete_payload(self):
        self.assertEqual(DeleteUserPayload(username="bob", admin_password="mine").username, "bob")

    def test_delete_validates_the_username(self):
        with self.assertRaises(ValidationError):
            DeleteUserPayload(username="", admin_password="mine")


class OtherPayloadTests(unittest.TestCase):
    def test_enforcement_config_fields_are_all_optional(self):
        self.assertIsNone(EnforcementConfigPayload().block_rate_floor_pps)

    def test_enforcement_config_accepts_a_partial_update(self):
        self.assertEqual(EnforcementConfigPayload(block_rate_floor_pps=42.0).block_rate_floor_pps, 42.0)


if __name__ == "__main__":
    unittest.main()
