"""
alerts.py — Discord webhook + SMTP email alerting.

Real-time alerts (from ipc_receiver.py) are dispatched through a bounded
background queue/worker thread so a slow or hanging SMTP connection can
never stall the IPC receive hot path -- ipc_receiver.py only ever enqueues,
never sends synchronously. The one exception is /api/alerts/test, which
sends synchronously and reports per-channel success/failure, since the
entire point of a "test" button is immediate feedback on misconfiguration.
"""

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


def send_discord_alert(message: str):
    """Returns (success, error_message)."""
    cfg = config.get_alerts_config()
    if not cfg["discord_enabled"] or not cfg["discord_webhook_url"]:
        return False, "Discord alerts are not enabled/configured."
    try:
        resp = requests.post(cfg["discord_webhook_url"], json={"content": message}, timeout=10)
        if resp.status_code >= 300:
            err = f"Discord webhook returned HTTP {resp.status_code}"
            logging.error(f"[-] {err}: {resp.text[:200]}")
            return False, err
        return True, ""
    except Exception as e:
        logging.error(f"[-] Failed to send Discord alert: {e}")
        return False, str(e)


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
        return True, ""
    except Exception as e:
        logging.error(f"[-] Failed to send email alert: {e}")
        return False, str(e)


def dispatch_alert(subject: str, message: str):
    """Non-blocking: enqueue for the background worker. Drops the alert
    (logged) rather than blocking the caller if the queue is full -- a
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


# -----------------------------------------------------------------------------
# Config + test routes
# -----------------------------------------------------------------------------

def _redact(cfg: dict) -> dict:
    safe = dict(cfg)
    safe["smtp_app_password_set"] = bool(safe.pop("smtp_app_password", ""))
    # The webhook URL IS the credential (anyone holding it can post as this
    # bot to the target channel), so it gets the same treatment as the SMTP
    # app password rather than being echoed back in the clear.
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
    """`channel` is "discord", "email", or "all" (default -- tests every
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
            "**SHIELD Gateway Test Alert**\nThis is a test message -- if you're reading this, Discord alerting is working."
        )
        results["discord"] = "ok" if ok else f"failed: {err}"
    if test_email:
        ok, err = send_email_alert(
            "SHIELD Gateway Test Alert",
            "This is a test message from the SHIELD Gateway dashboard. If you're reading this, email alerting is working."
        )
        results["email"] = "ok" if ok else f"failed: {err}"
    return results
