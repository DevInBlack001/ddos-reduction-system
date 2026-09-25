"""Tests for alerts.py's channel filtering: dispatch_alert()'s channel
argument and _process_alert()'s per-channel dispatch. send_discord_alert
and send_email_alert are mocked throughout: these tests assert which
channel functions are called, not that a real webhook or SMTP send
happened.
"""

import queue
import unittest
from unittest import mock

import alerts


class DispatchAlertChannelTests(unittest.TestCase):
    def setUp(self):
        self._queue = alerts._alert_queue
        alerts._alert_queue = queue.Queue(maxsize=100)

    def tearDown(self):
        alerts._alert_queue = self._queue

    def test_the_default_channel_is_all(self):
        alerts.dispatch_alert("subject", "message")
        _, _, channel = alerts._alert_queue.get_nowait()
        self.assertEqual(channel, "all")

    def test_a_recognised_channel_is_kept_as_is(self):
        alerts.dispatch_alert("subject", "message", channel="discord")
        _, _, channel = alerts._alert_queue.get_nowait()
        self.assertEqual(channel, "discord")

    def test_an_unrecognised_channel_falls_back_to_all_rather_than_dropping_the_alert(self):
        alerts.dispatch_alert("subject", "message", channel="slack")
        _, _, channel = alerts._alert_queue.get_nowait()
        self.assertEqual(channel, "all")


class ProcessAlertChannelTests(unittest.TestCase):
    """_process_alert() is the per-item work run_alert_worker()'s loop
    does, pulled out so it can be exercised directly without the queue's
    blocking get() or the worker's infinite loop."""

    def test_a_discord_only_alert_does_not_call_send_email_alert(self):
        with mock.patch("alerts.send_discord_alert") as discord, \
             mock.patch("alerts.send_email_alert") as email:
            alerts._process_alert("subject", "message", "discord")
        discord.assert_called_once()
        email.assert_not_called()

    def test_an_email_only_alert_does_not_call_send_discord_alert(self):
        with mock.patch("alerts.send_discord_alert") as discord, \
             mock.patch("alerts.send_email_alert") as email:
            alerts._process_alert("subject", "message", "email")
        email.assert_called_once()
        discord.assert_not_called()

    def test_an_all_channel_alert_calls_both(self):
        with mock.patch("alerts.send_discord_alert") as discord, \
             mock.patch("alerts.send_email_alert") as email:
            alerts._process_alert("subject", "message", "all")
        discord.assert_called_once()
        email.assert_called_once()


if __name__ == "__main__":
    unittest.main()
