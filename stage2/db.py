"""
db.py — SQLite audit-log writers (the `logs` and `metrics_history` tables).

Deliberately does NOT depend on enforcement.py: log_incident() used to
resolve an unset victim_ip itself (via enforcement.resolve_victim_ip),
which would make this module depend on enforcement.py while enforcement.py
(block_ip/ratelimit_ip/unblock_ip) depends on this module for log_incident
-- a cycle. Every caller now resolves victim_ip before calling in here
(block_ip/ratelimit_ip already did; unblock_ip was the one call site that
didn't and now does too), so this module only needs config + state.
"""

import sqlite3
import logging

import config
import state


def log_incident(timestamp, src_ip, classification, victim_ip="Unknown"):
    try:
        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO logs (timestamp, src_ip, dst_ip, proto, rate, entropy, classification) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (timestamp, src_ip, victim_ip, "MIXED", state.last_metrics.get("ewma_rate", 0.0), state.last_metrics.get("entropy", 0.0), classification)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"[-] Failed to write incident to SQLite: {e}")


def log_metrics_history(timestamp, rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k, victim_ip):
    try:
        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO metrics_history (timestamp, ewma_rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k_multiplier, victim_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k, victim_ip)
        )
        # Purge old metrics history (keep last 1000)
        cursor.execute("DELETE FROM metrics_history WHERE id NOT IN (SELECT id FROM metrics_history ORDER BY id DESC LIMIT 1000)")
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"[-] Failed to save metrics history: {e}")
