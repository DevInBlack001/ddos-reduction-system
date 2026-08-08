#!/usr/bin/env python3
"""
stage2.py — Stage 2: Real-time IPC Classifier & Mitigation Engine + Web API Console
---------------------------------------------------------------------------------
Listens on the Unix Domain Socket at /run/ddos_stage1/stage1.sock for 184-byte
feature vectors containing window statistics and the dominant IP address.
Predicts traffic class (0: Normal, 1: Flash Crowd, 2: DDoS) in real-time
and triggers kernel-level mitigation via ipset for DDoS.

This file is just the application entrypoint: it builds the FastAPI app,
mounts static files, registers the auth middleware, wires in each feature
area's router, starts the background threads, and initializes SQLite. The
actual logic lives in:

  storage.py        generic JSON-file read/write helpers (no other deps)
  state.py          shared in-memory state (sessions, metrics, blocklists)
  config.py         path constants + enforcement_config.json load/save
  models.py         Pydantic request payloads + shared IP validator
  db.py             SQLite audit-log writers (logs, metrics_history)
  enforcement.py    ipset/iptables control, block/ratelimit/unblock
  auth.py           login/logout routes, session middleware, rate-limit
  users.py          admin account management (add/delete/change password)
  alerts.py         Discord webhook + SMTP email alerting
  ipc_receiver.py   Unix socket listener thread + classification/tiers
  reports.py        CSV/PDF incident report export routes
  api.py            dashboard state/history/whitelist/victim/config routes

Features integrated:
- FastAPI backend serving multi-page HTML console under /static/
- User Authentication (bcrypt) with 10-minute session limits and login throttling
- Persistence of incident logs and Welford histories in SQLite
- Active connection flow visualizer pulling from Stage 1 active flow logs
- Dynamic kernel blocklist viewer and administrative whitelist manager
- CSV/PDF Incident Report Exporter embedding base64-decoded Chart.js graphs
"""

import os
import sqlite3
import logging
import threading

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

import config
import auth
import api
import reports
import users
import alerts
from ipc_receiver import run_ipc_receiver
from enforcement import run_ipset_monitor
from storage import load_json_file

# -----------------------------------------------------------------------------
# FastAPI Core Web App
# -----------------------------------------------------------------------------

app = FastAPI(title="FLOD System Management Console", docs_url=None, redoc_url=None)

# Mount static files folder
app.mount("/static", StaticFiles(directory=os.path.join(config.SCRIPT_DIR, "static")), name="static")

# Session-gating + request-size middleware (must attach to `app` directly --
# middleware can't be registered on an APIRouter).
app.middleware("http")(auth.auth_middleware)

app.include_router(auth.router)
app.include_router(api.router)
app.include_router(reports.router)
app.include_router(users.router)
app.include_router(alerts.router)

# -----------------------------------------------------------------------------
# Main Application Launch Hook
# -----------------------------------------------------------------------------

def start_api_server():
    import uvicorn
    ssl_kwargs = {}
    if config.tls_enabled():
        ssl_kwargs = {"ssl_certfile": config.TLS_CERT_PATH, "ssl_keyfile": config.TLS_KEY_PATH}
        logging.info(f"[+] Starting Uvicorn API Server on port 8000 (HTTPS, cert: {config.TLS_CERT_PATH})...")
    else:
        logging.warning(
            f"[!] No TLS certificate found at {config.TLS_CERT_PATH}/{config.TLS_KEY_PATH} -- "
            "falling back to plain HTTP. Login credentials and session cookies "
            "will travel unencrypted. Re-run install.sh or provide a cert/key pair."
        )
        logging.info("[+] Starting Uvicorn API Server on port 8000 (HTTP)...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning", **ssl_kwargs)

def main():
    # Ensure SQLite initialized and migrated
    os.makedirs(os.path.dirname(os.path.abspath(config.DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    # stage2.db holds password hashes and salts. Both services run as root,
    # so without this it inherits the process umask (often world readable),
    # letting any local account read the admin credentials off disk.
    # Done before the WAL pragma: SQLite gives the sidecar files the mode the
    # database has when it creates them, and they hold recently written pages.
    os.chmod(config.DB_PATH, 0o600)
    # WAL is a property of the file, so setting it once here covers every
    # module that opens its own connection. Without it a dashboard read and
    # a window write block each other.
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, salt TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, src_ip TEXT, dst_ip TEXT, proto TEXT, rate REAL, entropy REAL, classification TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS metrics_history (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, ewma_rate REAL, entropy REAL, mean_h REAL, mean_r REAL, sigma_h REAL, sigma_r REAL, k_multiplier REAL, victim_ip TEXT)")

    # Migration check: check if victim_ip column exists in metrics_history
    cursor.execute("PRAGMA table_info(metrics_history)")
    columns = [col[1] for col in cursor.fetchall()]
    if "victim_ip" not in columns:
        logging.info("[*] Migrating database: adding victim_ip column to metrics_history")
        try:
            cursor.execute("ALTER TABLE metrics_history ADD COLUMN victim_ip TEXT DEFAULT ''")
        except Exception as me:
            logging.error(f"[-] Migration failed: {me}")

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        logging.warning(
            "[!] No administrator account exists. Run setup_admin.py before "
            "starting the API server -- there is no default credential."
        )
    conn.commit()
    conn.close()

    # Ensure configs initialized
    load_json_file(config.WHITELIST_PATH, [])
    load_json_file(config.VICTIMS_PATH, [])

    # Start IPC socket listener thread
    ipc_thread = threading.Thread(target=run_ipc_receiver, daemon=True)
    ipc_thread.start()

    # Start IPSET capacity monitor thread
    monitor_thread = threading.Thread(target=run_ipset_monitor, daemon=True)
    monitor_thread.start()

    # Start alert dispatch worker thread
    alert_thread = threading.Thread(target=alerts.run_alert_worker, daemon=True)
    alert_thread.start()

    # Start FastAPI / Uvicorn server synchronously on main thread
    start_api_server()

if __name__ == "__main__":
    main()
