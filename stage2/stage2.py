#!/usr/bin/env python3
"""
Stage 2: classifier, enforcement, and the web console.

Listens on a Unix domain socket for feature vectors from Stage 1, predicts a
traffic class, and triggers kernel level mitigation.

This file is the entrypoint only. It builds the app, mounts static files,
registers middleware, wires in each router, starts the background threads, and
initialises the database. The logic lives in the modules it imports.
"""

import os
import sqlite3
import logging
import threading

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

import config
import schema
import auth
import api
import reports
import users
import alerts
from ipc_receiver import run_ipc_receiver
import enforcement
from enforcement import run_ipset_monitor
from storage import load_json_file

# FastAPI Core Web App

app = FastAPI(title="FLOD System Management Console", docs_url=None, redoc_url=None)

class RevalidatingStaticFiles(StaticFiles):
    """Static files the browser must revalidate before reusing.

    An update replaces the dashboard's scripts and pages together. A browser
    holding a cached theme.js while loading a new page renders nothing, and a
    hard reload is the only way out. ETags still make an unchanged file a 304,
    so this costs a request, not a download.
    """

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


app.mount(
    "/static",
    RevalidatingStaticFiles(directory=os.path.join(config.SCRIPT_DIR, "static")),
    name="static",
)

# Session-gating + request-size middleware (must attach to `app` directly,
# middleware can't be registered on an APIRouter).
app.middleware("http")(auth.auth_middleware)

app.include_router(auth.router)
app.include_router(api.router)
app.include_router(reports.router)
app.include_router(users.router)
app.include_router(alerts.router)

# Main Application Launch Hook

def start_api_server():
    import uvicorn
    ssl_kwargs = {}
    if config.tls_enabled():
        ssl_kwargs = {"ssl_certfile": config.TLS_CERT_PATH, "ssl_keyfile": config.TLS_KEY_PATH}
        logging.info(f"[+] Starting Uvicorn API Server on port 8000 (HTTPS, cert: {config.TLS_CERT_PATH})...")
    else:
        logging.warning(
            f"[!] No TLS certificate found at {config.TLS_CERT_PATH}/{config.TLS_KEY_PATH}, "
            "falling back to plain HTTP. Login credentials and session cookies "
            "will travel unencrypted. Re-run install.sh or provide a cert/key pair."
        )
        logging.info("[+] Starting Uvicorn API Server on port 8000 (HTTP)...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning", **ssl_kwargs)

def main():
    logging.info(f"[+] FLOD System: Stage 2 starting | version {config.VERSION}")

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
    schema.apply(conn)

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        logging.warning(
            "[!] No administrator account exists. Run setup_admin.py before "
            "starting the API server, there is no default credential."
        )
    conn.commit()
    conn.close()

    # Ensure configs initialized
    load_json_file(config.WHITELIST_PATH, [])
    load_json_file(config.VICTIMS_PATH, [])

    # Firewall entries survive a restart of this process, so the record of
    # which of them are attack sources is restored to match.
    enforcement.load_ddos_sources()

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
