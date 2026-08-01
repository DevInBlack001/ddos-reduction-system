"""
config.py — Path constants, wire-format constants, and the operator-tunable
enforcement threshold config (enforcement_config.json).

Sets up root logging as a side effect of being imported (every other module
imports this one, directly or transitively, before it logs anything).
"""

import os
import sys
import struct
import logging

from storage import load_json_file

# -----------------------------------------------------------------------------
# Configuration Paths
# -----------------------------------------------------------------------------

# /run/ddos_stage1 (not /tmp) for the IPC socket and the active-flows file --
# /tmp is world-writable, which would let any local account race to bind the
# socket path before this process does, or plant a fake active-flows file.
RUNTIME_DIR = "/run/ddos_stage1"
SOCKET_PATH = os.path.join(RUNTIME_DIR, "stage1.sock")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "ddos_rf_model.joblib")
FEATURE_VECTOR_FORMAT = "<17d16s16s"  # 17 x f64 (136 bytes) + 16-byte dominant IP + 16-byte victim IP = 168 bytes
PAYLOAD_SIZE = struct.calcsize(FEATURE_VECTOR_FORMAT)

DB_PATH = os.environ.get("DB_PATH", os.path.join(SCRIPT_DIR, "stage2.db"))
WHITELIST_PATH = os.path.join(SCRIPT_DIR, "whitelist.json")
VICTIMS_PATH = os.path.join(SCRIPT_DIR, "victims.json")
FLOWS_PATH = os.path.join(RUNTIME_DIR, "active_flows.json")
ENFORCEMENT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "enforcement_config.json")
ALERTS_CONFIG_PATH = os.path.join(SCRIPT_DIR, "alerts_config.json")

TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "/etc/ddos_stage2/tls/cert.pem")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "/etc/ddos_stage2/tls/key.pem")

# -----------------------------------------------------------------------------
# Enforcement thresholds -- these were previously hardcoded magic numbers
# scattered through the enforcement logic. Kept as a deterministic,
# operator-tunable rule set (not statistically self-adjusted) so a given
# decision can always be explained by pointing at a specific configured
# value, editable live from the dashboard without touching code.
# -----------------------------------------------------------------------------

DEFAULT_ENFORCEMENT_CONFIG = {
    # Tier 1 fast-path gate: how concentrated traffic must be on one source
    # before that source alone is enough to justify a block.
    "dominant_ip_ratio_block_threshold": 0.40,
    # Classification override: dominant_ip_ratio above this forces DDoS
    # regardless of entropy (a near-single-source flood is unambiguous).
    "dominant_ip_ratio_extreme_threshold": 0.75,
    # Floor under block_threshold/extreme_dominant_rate_boundary so a
    # near-idle victim's baseline can't produce an absurdly low bar.
    "block_rate_floor_pps": 300.0,
    # Floor under flow_threshold (the softer rate-limit tier).
    "ratelimit_rate_floor_pps": 50.0,
    # Sigma multiplier shared by Tier 2's per-source block_threshold and the
    # classification override's extreme_dominant_rate_boundary -- kept as
    # ONE value so the two stay consistent with each other by construction.
    "block_sigma_multiplier": 10.0,
    # Consecutive class-2 windows required before a block action (not
    # rate-limit) is allowed to fire.
    "block_hysteresis_windows": 2,
    # ipset entry lifetime for auto-triggered blocks/rate-limits (self-heal).
    "block_duration_seconds": 3600,
    "ratelimit_duration_seconds": 3600,
    # The actual pps cap enforced by the ddos_ratelimit iptables hashlimit
    # rule. Unlike the others, changing this requires live iptables rule
    # surgery (see enforcement.update_ratelimit_hashlimit()), not just a
    # Python read.
    "ratelimit_hashlimit_pps": 50,
}


def get_enforcement_config():
    """Load enforcement config, merged over defaults so a partially-old
    saved file (missing newer keys) still works."""
    saved = load_json_file(ENFORCEMENT_CONFIG_PATH, DEFAULT_ENFORCEMENT_CONFIG)
    return {**DEFAULT_ENFORCEMENT_CONFIG, **saved}


# -----------------------------------------------------------------------------
# Alerting (Discord webhook + SMTP email) -- disabled by default. Holds an
# SMTP app password at rest; alerts_config.json gets the same chmod 0600
# treatment as everything else storage.save_json_file touches, same trust
# model as stage2.db/enforcement_config.json (protects against other local
# accounts, not against root compromise).
# -----------------------------------------------------------------------------

DEFAULT_ALERTS_CONFIG = {
    "discord_enabled": False,
    "discord_webhook_url": "",
    "email_enabled": False,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_username": "",
    "smtp_app_password": "",
    "email_recipients": [],
}


def get_alerts_config():
    saved = load_json_file(ALERTS_CONFIG_PATH, DEFAULT_ALERTS_CONFIG)
    return {**DEFAULT_ALERTS_CONFIG, **saved}


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] stage2: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(SCRIPT_DIR, "stage2.log"), mode="a")
    ]
)
