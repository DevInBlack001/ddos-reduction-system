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

    def test_a_discord_only_alert_calls_nothing_else(self):
        with mock.patch("alerts.send_discord_alert") as discord, \
             mock.patch("alerts.send_email_alert") as email, \
             mock.patch("alerts.send_telegram_alert") as telegram, \
             mock.patch("alerts.send_webhook_alert") as webhook:
            alerts._process_alert("subject", "message", "discord")
        discord.assert_called_once()
        email.assert_not_called()
        telegram.assert_not_called()
        webhook.assert_not_called()

    def test_an_email_only_alert_calls_nothing_else(self):
        with mock.patch("alerts.send_discord_alert") as discord, \
             mock.patch("alerts.send_email_alert") as email, \
             mock.patch("alerts.send_telegram_alert") as telegram, \
             mock.patch("alerts.send_webhook_alert") as webhook:
            alerts._process_alert("subject", "message", "email")
        email.assert_called_once()
        discord.assert_not_called()
        telegram.assert_not_called()
        webhook.assert_not_called()

    def test_a_telegram_only_alert_calls_nothing_else(self):
        with mock.patch("alerts.send_discord_alert") as discord, \
             mock.patch("alerts.send_email_alert") as email, \
             mock.patch("alerts.send_telegram_alert") as telegram, \
             mock.patch("alerts.send_webhook_alert") as webhook:
            alerts._process_alert("subject", "message", "telegram")
        telegram.assert_called_once()
        discord.assert_not_called()
        email.assert_not_called()
        webhook.assert_not_called()

    def test_a_webhook_only_alert_calls_nothing_else(self):
        with mock.patch("alerts.send_discord_alert") as discord, \
             mock.patch("alerts.send_email_alert") as email, \
             mock.patch("alerts.send_telegram_alert") as telegram, \
             mock.patch("alerts.send_webhook_alert") as webhook:
            alerts._process_alert("subject", "message", "webhook")
        webhook.assert_called_once()
        discord.assert_not_called()
        email.assert_not_called()
        telegram.assert_not_called()

    def test_an_all_channel_alert_calls_every_channel(self):
        with mock.patch("alerts.send_discord_alert") as discord, \
             mock.patch("alerts.send_email_alert") as email, \
             mock.patch("alerts.send_telegram_alert") as telegram, \
             mock.patch("alerts.send_webhook_alert") as webhook:
            alerts._process_alert("subject", "message", "all")
        discord.assert_called_once()
        email.assert_called_once()
        telegram.assert_called_once()
        webhook.assert_called_once()


class SendTelegramAlertTests(unittest.TestCase):
    """send_discord_alert/send_email_alert already establish this pattern
    (mock requests/smtplib, assert the (success, error) return and what
    was actually called); send_telegram_alert follows it exactly."""

    def setUp(self):
        self._real_get_config = alerts.config.get_alerts_config

    def tearDown(self):
        alerts.config.get_alerts_config = self._real_get_config

    def _cfg(self, **overrides):
        base = {"telegram_enabled": True, "telegram_bot_token": "123:ABC", "telegram_chat_id": "-100"}
        base.update(overrides)
        alerts.config.get_alerts_config = lambda: base

    def test_not_enabled_returns_a_clear_error_without_calling_requests(self):
        self._cfg(telegram_enabled=False)
        with mock.patch("alerts.requests.post") as post:
            ok, err = alerts.send_telegram_alert("hello")
        self.assertFalse(ok)
        self.assertIn("not enabled", err)
        post.assert_not_called()

    def test_a_successful_send_posts_to_the_bot_s_own_endpoint(self):
        self._cfg()
        with mock.patch("alerts.requests.post") as post:
            post.return_value = mock.Mock(status_code=200)
            ok, err = alerts.send_telegram_alert("hello")
        self.assertTrue(ok)
        self.assertEqual(err, "")
        url = post.call_args.args[0]
        self.assertEqual(url, "https://api.telegram.org/bot123:ABC/sendMessage")
        self.assertEqual(post.call_args.kwargs["json"], {"chat_id": "-100", "text": "hello"})

    def test_a_non_2xx_response_is_reported_as_a_failure(self):
        self._cfg()
        with mock.patch("alerts.requests.post") as post:
            post.return_value = mock.Mock(status_code=401, text="Unauthorized")
            ok, err = alerts.send_telegram_alert("hello")
        self.assertFalse(ok)
        self.assertIn("401", err)

    def test_the_bot_token_is_redacted_from_a_raised_exception(self):
        self._cfg()
        with mock.patch("alerts.requests.post", side_effect=Exception("connect to bot123:ABC failed")):
            ok, err = alerts.send_telegram_alert("hello")
        self.assertFalse(ok)
        self.assertNotIn("123:ABC", err)


class SendWebhookAlertTests(unittest.TestCase):
    def setUp(self):
        self._real_get_config = alerts.config.get_alerts_config

    def tearDown(self):
        alerts.config.get_alerts_config = self._real_get_config

    def _cfg(self, **overrides):
        base = {
            "webhook_enabled": True,
            "webhook_url": "https://example.com/hook",
            "webhook_headers": {"Authorization": "Bearer secret-token"},
        }
        base.update(overrides)
        alerts.config.get_alerts_config = lambda: base

    def test_not_enabled_returns_a_clear_error_without_calling_requests(self):
        self._cfg(webhook_enabled=False)
        with mock.patch("alerts.requests.post") as post:
            ok, err = alerts.send_webhook_alert("subject", "message")
        self.assertFalse(ok)
        self.assertIn("not enabled", err)
        post.assert_not_called()

    def test_a_successful_send_posts_the_fixed_body_shape_with_configured_headers(self):
        self._cfg()
        with mock.patch("alerts.requests.post") as post:
            post.return_value = mock.Mock(status_code=200)
            ok, err = alerts.send_webhook_alert("Subject", "Message")
        self.assertTrue(ok)
        body = post.call_args.kwargs["json"]
        self.assertEqual(body["subject"], "Subject")
        self.assertEqual(body["message"], "Message")
        self.assertEqual(body["text"], "Subject: Message")
        self.assertEqual(body["title"], "Subject")
        self.assertEqual(post.call_args.kwargs["headers"], {"Authorization": "Bearer secret-token"})

    def test_a_non_2xx_response_is_reported_as_a_failure(self):
        self._cfg()
        with mock.patch("alerts.requests.post") as post:
            post.return_value = mock.Mock(status_code=500, text="Internal Server Error")
            ok, err = alerts.send_webhook_alert("subject", "message")
        self.assertFalse(ok)
        self.assertIn("500", err)

    def test_the_header_value_is_redacted_from_a_raised_exception(self):
        self._cfg()
        with mock.patch("alerts.requests.post", side_effect=Exception("auth failed: Bearer secret-token")):
            ok, err = alerts.send_webhook_alert("subject", "message")
        self.assertFalse(ok)
        self.assertNotIn("secret-token", err)

    def test_the_url_is_redacted_from_a_raised_exception(self):
        self._cfg()
        with mock.patch("alerts.requests.post", side_effect=Exception("could not reach https://example.com/hook")):
            ok, err = alerts.send_webhook_alert("subject", "message")
        self.assertFalse(ok)
        self.assertNotIn("https://example.com/hook", err)


class RedactConfigTests(unittest.TestCase):
    """_redact() is what /api/config/alerts (GET) returns; a credential
    must never come back in that response."""

    def test_telegram_bot_token_becomes_a_boolean_flag(self):
        safe = alerts._redact({"telegram_bot_token": "123:ABC"})
        self.assertNotIn("telegram_bot_token", safe)
        self.assertTrue(safe["telegram_bot_token_set"])

    def test_webhook_url_becomes_a_boolean_flag(self):
        safe = alerts._redact({"webhook_url": "https://example.com/hook"})
        self.assertNotIn("webhook_url", safe)
        self.assertTrue(safe["webhook_url_set"])

    def test_webhook_header_values_are_dropped_but_names_are_kept(self):
        safe = alerts._redact({"webhook_headers": {"Authorization": "Bearer secret-token", "X-Api-Key": "k"}})
        self.assertNotIn("webhook_headers", safe)
        self.assertEqual(safe["webhook_header_names"], ["Authorization", "X-Api-Key"])
        self.assertNotIn("secret-token", str(safe))


if __name__ == "__main__":
    unittest.main()
