"""
alerts.py: Discord webhook + SMTP email alerting.

Real-time alerts (from ipc_receiver.py) are dispatched through a bounded
background queue/worker thread so a slow or hanging SMTP connection can
never stall the IPC receive hot path, ipc_receiver.py only ever enqueues,
never sends synchronously. The one exception is /api/alerts/test, which
sends synchronously and reports per-channel success/failure, since the
entire point of a "test" button is immediate feedback on misconfiguration.
"""

import re
import smtplib
import logging
import queue
import threading
from email.mime.text import MIMEText

import requests
from fastapi import APIRouter, HTTPException

import config
from storage import save_json_file
from models import AlertsConfigPayload

router = APIRouter()

_alert_queue = queue.Queue(maxsize=100)

_WEBHOOK_PATH_RE = re.compile(r"/api/webhooks/\d+/[A-Za-z0-9_-]+")

# Whether each channel's last attempt already reported a failure. A gateway
# with no route out fails on every alert, and an identical error per attempt
# buries everything else in the journal.
_reported_down = {"discord": False, "email": False}


def _report_failure(channel: str, message: str):
    """Log a channel failure the first time, then stay quiet until it works."""
    if not _reported_down[channel]:
        logging.error(f"[-] {message}")
        _reported_down[channel] = True


def _report_recovered(channel: str):
    if _reported_down[channel]:
        logging.info(f"[+] {channel.capitalize()} alerts are working again.")
        _reported_down[channel] = False


def _redact_secrets(text: str, cfg: dict) -> str:
    """Strip credentials from an error string before it is logged or
    returned to the dashboard.

    A network exception does not necessarily contain the webhook URL as one
    contiguous substring; requests/urllib3 often format the host and the
    path into separate parts of the message. Matching the path pattern
    itself, rather than the full URL, catches it either way. The SMTP
    username and password are matched as literal substrings since those are
    not reformatted by smtplib.
    """
    text = _WEBHOOK_PATH_RE.sub("/api/webhooks/REDACTED", text)
    password = cfg.get("smtp_app_password") or ""
    username = cfg.get("smtp_username") or ""
    if password:
        text = text.replace(password, "REDACTED")
    if username:
        text = text.replace(username, "REDACTED")
    return text


def send_discord_alert(message: str):
    """Returns (success, error_message)."""
    cfg = config.get_alerts_config()
    if not cfg["discord_enabled"] or not cfg["discord_webhook_url"]:
        return False, "Discord alerts are not enabled/configured."
    try:
        resp = requests.post(cfg["discord_webhook_url"], json={"content": message}, timeout=10)
        if resp.status_code >= 300:
            body = _redact_secrets(resp.text[:200], cfg)
            err = f"Discord webhook returned HTTP {resp.status_code}"
            _report_failure("discord", f"{err}: {body}")
            return False, err
        _report_recovered("discord")
        return True, ""
    except Exception as e:
        err = _redact_secrets(str(e), cfg)
        _report_failure("discord", f"Failed to send Discord alert: {err}")
        return False, err


def send_email_alert(subject: str, body: str):
    """Returns (success, error_message)."""
    cfg = config.get_alerts_config()
    if not cfg["email_enabled"] or not cfg["smtp_username"] or not cfg["smtp_app_password"] or not cfg["email_recipients"]:
        return False, "Email alerts are not enabled/fully configured."
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = cfg["smtp_username"]
        msg["To"] = ", ".join(cfg["email_recipients"])
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=10) as server:
            server.starttls()
            server.login(cfg["smtp_username"], cfg["smtp_app_password"])
            server.sendmail(cfg["smtp_username"], cfg["email_recipients"], msg.as_string())
        _report_recovered("email")
        return True, ""
    except Exception as e:
        err = _redact_secrets(str(e), cfg)
        _report_failure("email", f"Failed to send email alert: {err}")
        return False, err


def dispatch_alert(subject: str, message: str):
    """Non-blocking: enqueue for the background worker. Drops the alert
    (logged) rather than blocking the caller if the queue is full, a
    slow-draining queue during a severe incident shouldn't back-pressure
    the IPC receive loop."""
    try:
        _alert_queue.put_nowait((subject, message))
    except queue.Full:
        logging.warning(f"[!] Alert queue full, dropping alert: {subject}")


def run_alert_worker():
    """Background thread entry point (started from stage2.py main(),
    alongside the existing IPC/ipset threads)."""
    logging.info("[+] Starting alert dispatch worker thread...")
    while True:
        subject, message = _alert_queue.get()
        send_discord_alert(f"**{subject}**\n{message}")
        send_email_alert(subject, message)


# Config + test routes

def _redact(cfg: dict) -> dict:
    safe = dict(cfg)
    safe["smtp_app_password_set"] = bool(safe.pop("smtp_app_password", ""))
    # The webhook URL is itself a credential, so it's redacted the same way.
    safe["discord_webhook_url_set"] = bool(safe.pop("discord_webhook_url", ""))
    return safe


@router.get("/api/config/alerts")
def get_alerts_config_api():
    return _redact(config.get_alerts_config())


@router.post("/api/config/alerts")
def update_alerts_config(payload: AlertsConfigPayload):
    current = config.get_alerts_config()
    updates = {k: v for k, v in payload.dict().items() if v is not None}
    new_config = {**current, **updates}
    save_json_file(config.ALERTS_CONFIG_PATH, new_config)
    logging.warning(f"[+] Alerts config updated: {list(updates.keys())}")
    return _redact(new_config)


@router.post("/api/alerts/test")
def send_test_alert(channel: str = "all"):
    """`channel` is "discord", "email", or "all" (default, tests every
    enabled channel). Scoped per-channel so each panel's own "Send Test
    Alert" button doesn't also fire the other configured channel."""
    if channel not in ("discord", "email", "all"):
        raise HTTPException(status_code=400, detail="channel must be 'discord', 'email', or 'all'.")

    cfg = config.get_alerts_config()
    test_discord = channel in ("discord", "all") and cfg["discord_enabled"]
    test_email = channel in ("email", "all") and cfg["email_enabled"]
    if not test_discord and not test_email:
        raise HTTPException(status_code=400, detail="That channel is not enabled.")

    results = {}
    if test_discord:
        ok, err = send_discord_alert(
            "**FLOD System Test Alert**\nThis is a test message, if you're reading this, Discord alerting is working."
        )
        results["discord"] = "ok" if ok else f"failed: {err}"
    if test_email:
        ok, err = send_email_alert(
            "FLOD System Test Alert",
            "This is a test message from the FLOD System dashboard. If you're reading this, email alerting is working."
        )
        results["email"] = "ok" if ok else f"failed: {err}"
    return results
