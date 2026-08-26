"""
config.py: Path constants, wire-format constants, and the operator-tunable
enforcement threshold config (enforcement_config.json).

Sets up root logging as a side effect of being imported (every other module
imports this one, directly or transitively, before it logs anything).
"""

import os
import sys
import struct
import logging

from storage import load_json_file

# Configuration Paths

# /run/ddos_stage1 (not /tmp) for the IPC socket and the active-flows file,
# /tmp is world-writable, which would let any local account race to bind the
# socket path before this process does, or plant a fake active-flows file.
RUNTIME_DIR = "/run/ddos_stage1"
SOCKET_PATH = os.path.join(RUNTIME_DIR, "stage1.sock")
# Kept in step with the Rust crates in stage1/Cargo.toml and with the release
# tag. Reported at startup and by /api/version so a deployed gateway can be
# identified without inspecting files.
VERSION = "1.2.0"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "ddos_rf_model.joblib")
# V7: the Isolation Forest, trained separately (train_isolation_forest.py)
# from the RandomForest above (train.py). Both load and run every window.
IF_MODEL_PATH = os.path.join(SCRIPT_DIR, "ddos_if_model.joblib")
FEATURE_VECTOR_FORMAT = "<23d16s16s"  # 23 x f64 (184 bytes) + 16-byte dominant IP + 16-byte victim IP = 216 bytes
PAYLOAD_SIZE = struct.calcsize(FEATURE_VECTOR_FORMAT)

DB_PATH = os.environ.get("DB_PATH", os.path.join(SCRIPT_DIR, "stage2.db"))
WHITELIST_PATH = os.path.join(SCRIPT_DIR, "whitelist.json")
# V5: IPs known to front many hosts (carrier NAT, corporate egress, proxies).
# Never hard-blocked, see enforcement.block_ip().
SHARED_IPS_PATH = os.path.join(SCRIPT_DIR, "shared_ips.json")
VICTIMS_PATH = os.path.join(SCRIPT_DIR, "victims.json")
FLOWS_PATH = os.path.join(RUNTIME_DIR, "active_flows.json")
ENFORCEMENT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "enforcement_config.json")
ALERTS_CONFIG_PATH = os.path.join(SCRIPT_DIR, "alerts_config.json")

STAGE1_UNIT_PATH = "/etc/systemd/system/ddos-stage1.service"


def get_sniffer_interfaces():
    """(ingress, egress) interface names read from the Stage 1 unit file.

    Either may be None, the unit isn't installed (running from source),
    or --egress-interface simply wasn't passed. Callers report what is
    actually configured rather than substituting a guess.
    """
    ingress = None
    egress = None
    try:
        with open(STAGE1_UNIT_PATH, "r") as f:
            parts = f.read().split()
        for i, part in enumerate(parts):
            if i + 1 >= len(parts):
                break
            if part == "--interface":
                ingress = parts[i + 1]
            elif part == "--egress-interface":
                egress = parts[i + 1]
    except Exception:
        pass
    return ingress, egress


def tls_enabled():
    """True when both TLS files are present, so the server will serve HTTPS.

    Checked at request time rather than cached, because install.sh may
    generate the certificate after the process has already started."""
    return os.path.exists(TLS_CERT_PATH) and os.path.exists(TLS_KEY_PATH)


TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "/etc/ddos_stage2/tls/cert.pem")
TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "/etc/ddos_stage2/tls/key.pem")

# Enforcement thresholds, a deterministic, operator-tunable rule set
# (not statistically self-adjusted), editable live from the dashboard.

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
    # classification override's extreme_dominant_rate_boundary, kept as
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


# Alerting (Discord webhook + SMTP email), disabled by default.
# alerts_config.json is chmod 0600, same as stage2.db/enforcement_config.json.

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


# Logging

# Mirrors stage1's RUST_LOG: default INFO in production, raised to DEBUG for
# a single run without editing this file, e.g. to see the V7 Anomalous
# feature-vector dump in ipc_receiver.py.
_LOG_LEVEL = getattr(logging, os.environ.get("FLOD_LOG_LEVEL", "INFO").upper(), logging.INFO)

logging.basicConfig(
    level=_LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] stage2: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(SCRIPT_DIR, "stage2.log"), mode="a")
    ]
)
