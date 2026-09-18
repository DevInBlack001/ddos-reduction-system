"""
config.py: Path constants, wire-format constants, and the operator-tunable
enforcement threshold config (enforcement_config.json).

Sets up root logging as a side effect of being imported (every other module
imports this one, directly or transitively, before it logs anything).
"""

import os
import sys
import json
import struct
import logging

from storage import load_json_file

# Configuration Paths

# /run/ddos_stage1 (not /tmp) for the IPC socket and the active-flows file,
# /tmp is world-writable, which would let any local account race to bind the
# socket path before this process does, or plant a fake active-flows file.
RUNTIME_DIR = "/run/ddos_stage1"
SOCKET_PATH = os.path.join(RUNTIME_DIR, "stage1.sock")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_version():
    """Read version.json, the project's single source of truth for the
    release version (stage1's build.rs reads the same file at compile
    time). FLOD_VERSION_FILE overrides the path outright; otherwise this
    checks beside config.py first (where install.sh/update.sh copy it in
    a production install) and falls back to the repo root (a checkout run
    directly). Deliberately read-only: unlike load_json_file, a missing
    file must not get a default written back to it, that would silently
    paper over a real deployment mistake."""
    candidates = []
    override = os.environ.get("FLOD_VERSION_FILE")
    if override:
        candidates.append(override)
    candidates.append(os.path.join(SCRIPT_DIR, "version.json"))
    candidates.append(os.path.join(SCRIPT_DIR, "..", "version.json"))

    for path in candidates:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            continue
        try:
            with os.fdopen(fd, "r") as f:
                return json.load(f)["version"]
        except Exception:
            continue
    return "Unknown"


# Reported at startup and by /api/version so a deployed gateway can be
# identified without inspecting files.
VERSION = _load_version()

# Every path below defaults to living beside this file, which is what a
# checkout run directly (scripts/run.sh, development) wants. A production
# install is different on purpose: install.sh copies the Stage 2 code into
# a root-owned directory and points these at root-owned locations instead
# (FLOD_STATE_DIR under /var/lib, models under /var/lib, DB_PATH already
# followed this pattern before the rest did). The code that reads a model
# file or a JSON config as root should never be reading something an
# operator's ordinary login account can still write to; see
# docs/security.md for the reasoning in full. FLOD_STATE_DIR is a single
# override point for everything that isn't already independently
# overridable, so a systemd unit only has to set one variable, not eight.
_STATE_DIR = os.environ.get("FLOD_STATE_DIR", SCRIPT_DIR)

MODEL_PATH = os.environ.get("MODEL_PATH", os.path.join(_STATE_DIR, "ddos_rf_model.joblib"))
# V7: the Isolation Forest, trained separately (train_isolation_forest.py)
# from the RandomForest above (train.py). Both load and run every window.
IF_MODEL_PATH = os.environ.get("IF_MODEL_PATH", os.path.join(_STATE_DIR, "ddos_if_model.joblib"))
FEATURE_VECTOR_FORMAT = "<23d16s16s"  # 23 x f64 (184 bytes) + 16-byte dominant IP + 16-byte victim IP = 216 bytes
PAYLOAD_SIZE = struct.calcsize(FEATURE_VECTOR_FORMAT)

# V7: every window the Isolation Forest flags Anomalous gets appended here,
# in the same column order training.csv uses, plus context columns for a
# human to go investigate with. label is left blank; nothing fills it in
# automatically. See docs/training.md#reviewing-anomalous-traffic.
ANOMALOUS_CSV_PATH = os.environ.get("ANOMALOUS_CSV_PATH", os.path.join(_STATE_DIR, "anomalous_capture.csv"))
# V8: windows captured before any RandomForest model exists, no capture
# path in production has ever existed for these before. label is blank
# the same way anomalous_capture.csv's is, filled in by auto_label.py
# once a model exists to score it. See docs/specs/2026-09-13-confidence-
# gated-labeling-design.md.
PRETRAINING_CSV_PATH = os.environ.get("PRETRAINING_CSV_PATH", os.path.join(_STATE_DIR, "pretraining_capture.csv"))
# Windows the RandomForest already confidently calls DDoS. The Isolation
# Forest is never consulted for these (see the pred_class in (0, 1) check
# around ANOMALOUS_CSV_PATH's own write site), so without this path DDoS
# never had any way into confidence gated automatic labeling, the training
# corpus only ever grew Normal and Flash Crowd. auto_label.py re-scores
# these the same way, same agreement, confidence, and freshness checks,
# before any of it reaches training data. See docs/roadmap.md#known-gaps
# for the full reasoning this closes.
DDOS_CAPTURE_CSV_PATH = os.environ.get("DDOS_CAPTURE_CSV_PATH", os.path.join(_STATE_DIR, "ddos_capture.csv"))
# Rows auto_label.py has confidently labeled, staged here rather than
# written into training_data.csv directly: nothing enters the
# authoritative training set without a deliberate, recorded merge, the
# same discipline every past merge in this project's history already
# follows, this only removes the per-row manual labeling effort.
AUTO_LABELED_CSV_PATH = os.environ.get("AUTO_LABELED_CSV_PATH", os.path.join(_STATE_DIR, "auto_labeled_capture.csv"))
# V8: a second, independently trained classifier auto_label.py checks
# agreement against before trusting a label. Never loaded by
# ipc_receiver.py; only auto_label.py and train_second_model.py touch it.
SECOND_MODEL_PATH = os.environ.get("SECOND_MODEL_PATH", os.path.join(_STATE_DIR, "ddos_gb_model.joblib"))
# Starting points, not proven values, same convention as every other
# tuning default in this project.
AUTO_LABEL_DELAY_HOURS = float(os.environ.get("AUTO_LABEL_DELAY_HOURS", "24"))
AUTO_LABEL_CONFIDENCE_THRESHOLD = float(os.environ.get("AUTO_LABEL_CONFIDENCE_THRESHOLD", "0.90"))
AUTO_LABEL_MAX_QUEUE_ROWS = int(os.environ.get("AUTO_LABEL_MAX_QUEUE_ROWS", "50000"))
# Where the dashboard's Merge button appends staged auto-labeled rows.
# Empty by default, no path is guessed: the same "no safe universal
# default" reasoning the retrain timer's own --training-csv flag
# already uses. install.sh/update.sh write this from that same flag, so
# one operator choice controls both the periodic retrain target and
# what the dashboard merges into. Merge is disabled in the UI, and the
# API refuses the request, while this is unset.
TRAINING_CSV_PATH = os.environ.get("TRAINING_CSV_PATH", "")
# Maximum bytes for pretraining_capture.csv and anomalous_capture.csv before
# new appends are skipped. Cold-start capture can run for hours without a model;
# unbounded file growth to gigabytes is possible on heavy traffic. Starting point
# of 50 MB; adjust downward on constrained systems or upward if trimming needs to
# run less frequently.
PRETRAINING_MAX_BYTES = int(os.environ.get("PRETRAINING_MAX_BYTES", "52428800"))

DB_PATH = os.environ.get("DB_PATH", os.path.join(_STATE_DIR, "stage2.db"))
WHITELIST_PATH = os.environ.get("WHITELIST_PATH", os.path.join(_STATE_DIR, "whitelist.json"))
# V5: IPs known to front many hosts (carrier NAT, corporate egress, proxies).
# Never hard-blocked, see enforcement.block_ip().
SHARED_IPS_PATH = os.environ.get("SHARED_IPS_PATH", os.path.join(_STATE_DIR, "shared_ips.json"))
VICTIMS_PATH = os.environ.get("VICTIMS_PATH", os.path.join(_STATE_DIR, "victims.json"))
FLOWS_PATH = os.path.join(RUNTIME_DIR, "active_flows.json")
ENFORCEMENT_CONFIG_PATH = os.environ.get("ENFORCEMENT_CONFIG_PATH", os.path.join(_STATE_DIR, "enforcement_config.json"))
ALERTS_CONFIG_PATH = os.environ.get("ALERTS_CONFIG_PATH", os.path.join(_STATE_DIR, "alerts_config.json"))

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

_LOG_PATH = os.environ.get("STAGE2_LOG_PATH", os.path.join(_STATE_DIR, "stage2.log"))

logging.basicConfig(
    level=_LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] stage2: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(_LOG_PATH, mode="a")
    ]
)
