#!/usr/bin/env python3
"""
stage2.py — Stage 2: Real-time IPC Classifier & Mitigation Engine + Web API Console
---------------------------------------------------------------------------------
Listens on the Unix Domain Socket at /tmp/ddos_stage1.sock for 88-byte feature
vectors containing window statistics and the dominant IP address.
Predicts traffic class (0: Normal, 1: Flash Crowd, 2: DDoS) in real-time
and triggers kernel-level mitigation via ipset for DDoS.

Features integrated:
- FastAPI backend serving multi-page HTML console under /static/
- User Authentication (salted SHA-256) with 10-minute session limits
- Persistence of incident logs and Welford histories in SQLite
- Active connection flow visualizer pulling from Stage 1 active flow logs
- Dynamic kernel blocklist viewer and administrative whitelist manager
- CSV/PDF Incident Report Exporter embedding base64-decoded Chart.js graphs
"""

import os
import sys
import time
import json
import socket
import struct
import ipaddress
import subprocess
import logging
import sqlite3
import hashlib
import secrets
import threading
from io import BytesIO
from typing import List, Optional
import joblib

# FastAPI Imports
from fastapi import FastAPI, Depends, HTTPException, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ReportLab PDF Imports
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Configuration Paths
SOCKET_PATH = "/tmp/ddos_stage1.sock"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "ddos_rf_model.joblib")
FEATURE_VECTOR_FORMAT = "<17d16s16s"  # 17 x f64 (136 bytes) + 16-byte dominant IP + 16-byte victim IP = 168 bytes
PAYLOAD_SIZE = struct.calcsize(FEATURE_VECTOR_FORMAT)

DB_PATH = os.environ.get("DB_PATH", os.path.join(SCRIPT_DIR, "stage2.db"))
WHITELIST_PATH = os.path.join(SCRIPT_DIR, "whitelist.json")
VICTIMS_PATH = os.path.join(SCRIPT_DIR, "victims.json")
FLOWS_PATH = "/tmp/ddos_active_flows.json"
ENFORCEMENT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "enforcement_config.json")

# Enforcement thresholds -- these were previously hardcoded magic numbers
# scattered through the enforcement logic. Kept as a deterministic,
# operator-tunable rule set (not statistically self-adjusted) so a given
# decision can always be explained by pointing at a specific configured
# value, editable live from the dashboard without touching code.
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
    # surgery (see update_ratelimit_hashlimit()), not just a Python read.
    "ratelimit_hashlimit_pps": 50,
}

def get_enforcement_config():
    """Load enforcement config, merged over defaults so a partially-old
    saved file (missing newer keys) still works."""
    saved = load_json_file(ENFORCEMENT_CONFIG_PATH, DEFAULT_ENFORCEMENT_CONFIG)
    return {**DEFAULT_ENFORCEMENT_CONFIG, **saved}

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] stage2: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(SCRIPT_DIR, "stage2.log"), mode="a")
    ]
)

# -----------------------------------------------------------------------------
# Configuration Helper Functions
# -----------------------------------------------------------------------------

def load_json_file(path, default):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default, f)
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default

def save_json_file(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logging.error(f"[-] Failed to save configuration to {path}: {e}")

# Global state trackers in memory (synced to SQLite/JSON)
last_metrics = {
    "entropy": 0.0,
    "ewma_rate": 0.0,
    "mean_h": 0.0,
    "mean_r": 0.0,
    "sigma_h": 0.0,
    "sigma_r": 0.0,
    "proto_ratio": 1.0,
    "dominant_ip_ratio": 0.0,
    "timestamp": 0.0,
    "k_multiplier": 2.0,
    "cooldown": 0,
    "latest_classification": "Normal",
    "proto_tcp": 1.0,
    "proto_udp": 0.0,
    "proto_icmp": 0.0,
    "proto_sctp": 0.0,
    "proto_gre": 0.0,
    "proto_esp": 0.0
}
last_metrics_by_target = {}  # victim_ip -> last_metrics dict

# Hysteresis for hard blocks: how many CONSECUTIVE class-2 (DDoS) windows a
# victim must see before a block action is allowed to fire (configurable --
# see DEFAULT_ENFORCEMENT_CONFIG["block_hysteresis_windows"]). Rate-limiting
# is unaffected by this -- it's intentionally the immediate, reversible
# tier. Keeps a single noisy window from triggering an irreversible-feeling
# action; the ipset entries self-heal regardless, this just raises the bar
# before an entry gets created in the first place.
consecutive_ddos_windows = {}  # victim_ip -> count of consecutive class-2 windows

active_sessions = {}  # session_token -> last_active_timestamp

# -----------------------------------------------------------------------------
# Kernel netfilter blocklist control (ipset / iptables)
# -----------------------------------------------------------------------------

def _ensure_hashlimit_rule(pps):
    """Insert the ddos_ratelimit hashlimit rule (INPUT + FORWARD) at the
    given pps cap, if not already present. Idempotent -- iptables -C checks
    before inserting, matching the pattern used for ddos_blocklist."""
    for chain in ("INPUT", "FORWARD"):
        check = subprocess.run(
            ["iptables", "-C", chain, "-m", "set", "--match-set", "ddos_ratelimit", "src",
             "-m", "hashlimit", "--hashlimit-above", f"{pps}/sec", "--hashlimit-burst", "20",
             "--hashlimit-name", "ddoslimit", "--hashlimit-mode", "srcip", "-j", "DROP"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if check.returncode != 0:
            subprocess.run(
                ["iptables", "-I", chain, "-m", "set", "--match-set", "ddos_ratelimit", "src",
                 "-m", "hashlimit", "--hashlimit-above", f"{pps}/sec", "--hashlimit-burst", "20",
                 "--hashlimit-name", "ddoslimit", "--hashlimit-mode", "srcip", "-j", "DROP"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            logging.info(f"[+] Linked 'ddos_ratelimit' with {pps}pps hashlimit to iptables {chain} chain.")

def update_ratelimit_hashlimit(old_pps, new_pps):
    """Called when the operator changes ratelimit_hashlimit_pps via the
    dashboard. iptables rules are matched exactly on insert, including the
    hashlimit value, so changing the cap means removing the rule that
    matches the OLD value and inserting one with the new value -- there's
    no in-place edit. Safe to call even if old==new (no-op) or if the old
    rule is somehow already gone (delete just fails silently, matched by
    returncode, not raised)."""
    if old_pps == new_pps:
        return
    for chain in ("INPUT", "FORWARD"):
        subprocess.run(
            ["iptables", "-D", chain, "-m", "set", "--match-set", "ddos_ratelimit", "src",
             "-m", "hashlimit", "--hashlimit-above", f"{old_pps}/sec", "--hashlimit-burst", "20",
             "--hashlimit-name", "ddoslimit", "--hashlimit-mode", "srcip", "-j", "DROP"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    _ensure_hashlimit_rule(new_pps)
    logging.warning(f"[+] Updated ddos_ratelimit hashlimit cap: {old_pps}/sec -> {new_pps}/sec")

def setup_ipset():
    """Ensure the target ipset lists exist and are linked to iptables rules."""
    try:
        # 1. Create ddos_blocklist set (outright drop)
        subprocess.run(
            ["ipset", "create", "ddos_blocklist", "hash:ip", "timeout", "3600"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        logging.info("[+] Kernel ipset 'ddos_blocklist' verified/created.")

        # Link ddos_blocklist to INPUT chain if not present
        check_input = subprocess.run(
            ["iptables", "-C", "INPUT", "-m", "set", "--match-set", "ddos_blocklist", "src", "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if check_input.returncode != 0:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-m", "set", "--match-set", "ddos_blocklist", "src", "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            logging.info("[+] Linked 'ddos_blocklist' to iptables INPUT chain.")
            
        # Link ddos_blocklist to FORWARD chain if not present
        check_forward = subprocess.run(
            ["iptables", "-C", "FORWARD", "-m", "set", "--match-set", "ddos_blocklist", "src", "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if check_forward.returncode != 0:
            subprocess.run(
                ["iptables", "-I", "FORWARD", "-m", "set", "--match-set", "ddos_blocklist", "src", "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            logging.info("[+] Linked 'ddos_blocklist' to iptables FORWARD chain.")

        # 2. Create ddos_ratelimit set (rate-limits traffic per configured cap)
        subprocess.run(
            ["ipset", "create", "ddos_ratelimit", "hash:ip", "timeout", "3600"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        logging.info("[+] Kernel ipset 'ddos_ratelimit' verified/created.")

        # Hashlimit cap is operator-configurable (see enforcement_config.json,
        # ratelimit_hashlimit_pps) -- ensure the rule reflects whatever is
        # currently configured, not a hardcoded value, so a value saved
        # before a restart takes effect immediately on startup too.
        _ensure_hashlimit_rule(get_enforcement_config()["ratelimit_hashlimit_pps"])

    except Exception as e:
        logging.warning(f"[-] Could not setup/verify ipset or iptables: {e}")

recently_blocked = {}

def resolve_victim_ip(victim_ip=None):
    if victim_ip and victim_ip not in ("Unknown", "0.0.0.0", "::"):
        return victim_ip
    
    try:
        if os.path.exists(VICTIMS_PATH):
            with open(VICTIMS_PATH, "r") as f:
                victims = json.load(f)
                active_victims = [v["ip"] for v in victims if v.get("active")]
                if active_victims:
                    return active_victims[0]
                if victims:
                    return victims[0]["ip"]
    except Exception:
        pass

    if last_metrics_by_target:
        return next(iter(last_metrics_by_target.keys()))

    return "10.0.0.3"

def block_ip(ip, duration=3600, victim_ip="Unknown"):
    """Add offending IP to ddos_blocklist."""
    global recently_blocked
    now = time.time()
    
    if ip in recently_blocked and now - recently_blocked[ip] < 10.0:
        return
        
    victim_ip = resolve_victim_ip(victim_ip)
    try:
        # Check whitelist bypass
        whitelist = load_json_file(WHITELIST_PATH, [])
        if ip in whitelist:
            logging.info(f"[Whitelist Bypass] Skipping block for whitelisted administrative IP: {ip}")
            return

        res = subprocess.run(
            ["ipset", "add", "ddos_blocklist", ip, "timeout", str(duration), "-exist"],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            logging.warning(f"[!!!] MITIGATION TRIGGERED: Blocked offending IP {ip} (duration: {duration}s)")
            # Log to SQLite
            log_incident(now, ip, "Blocked", victim_ip)
        else:
            logging.error(f"[-] Failed to block IP {ip}: {res.stderr.strip()}")
    except Exception as e:
        logging.error(f"[-] Error calling ipset: {e}")
    finally:
        recently_blocked[ip] = now

def ratelimit_ip(ip, duration=3600, victim_ip="Unknown"):
    """Add offending IP to ddos_ratelimit set (enforces the configured
    ratelimit_hashlimit_pps cap, default 50pps)."""
    global recently_blocked
    now = time.time()
    
    if ip in recently_blocked and now - recently_blocked[ip] < 10.0:
        return
        
    victim_ip = resolve_victim_ip(victim_ip)
    try:
        # Check whitelist bypass
        whitelist = load_json_file(WHITELIST_PATH, [])
        if ip in whitelist:
            logging.info(f"[Whitelist Bypass] Skipping rate-limit for whitelisted administrative IP: {ip}")
            return

        res = subprocess.run(
            ["ipset", "add", "ddos_ratelimit", ip, "timeout", str(duration), "-exist"],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            rl_cap = get_enforcement_config()["ratelimit_hashlimit_pps"]
            logging.warning(f"[!!!] MITIGATION TRIGGERED: Rate-limited offending IP {ip} (duration: {duration}s, {rl_cap}pps cap)")
            # Log to SQLite
            log_incident(now, ip, "Rate Limited", victim_ip)
        else:
            logging.error(f"[-] Failed to rate-limit IP {ip}: {res.stderr.strip()}")
    except Exception as e:
        logging.error(f"[-] Error calling ipset: {e}")
    finally:
        recently_blocked[ip] = now

def unblock_ip(ip, victim_ip="Unknown"):
    """Remove IP from both ddos_blocklist and ddos_ratelimit."""
    try:
        res1 = subprocess.run(
            ["ipset", "del", "ddos_blocklist", ip],
            capture_output=True,
            text=True
        )
        res2 = subprocess.run(
            ["ipset", "del", "ddos_ratelimit", ip],
            capture_output=True,
            text=True
        )
        if res1.returncode == 0 or res2.returncode == 0:
            logging.info(f"[+] Released firewall block/rate-limit for IP {ip}")
            log_incident(time.time(), ip, "Released", victim_ip)
            return True
        else:
            logging.error(f"[-] Failed to release IP {ip}: {res1.stderr.strip()} / {res2.stderr.strip()}")
            return False
    except Exception as e:
        logging.error(f"[-] Error calling ipset: {e}")
        return False


def check_ipset_capacity():
    """Check ipset entries count vs maxelem and log alert if > 80% capacity."""
    try:
        res = subprocess.run(
            ["ipset", "list", "ddos_blocklist"],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            lines = res.stdout.splitlines()
            maxelem = 65536
            entries = 0
            for line in lines:
                if "maxelem" in line:
                    parts = line.split()
                    try:
                        # Find maxelem token
                        for idx, p in enumerate(parts):
                            if p == "maxelem":
                                maxelem = int(parts[idx + 1])
                                break
                    except (ValueError, IndexError):
                        pass
                elif line.startswith("Number of entries:"):
                    try:
                        entries = int(line.split(":")[-1].strip())
                    except ValueError:
                        pass
            
            if maxelem > 0:
                usage = entries / maxelem
                if usage > 0.80:
                    logging.critical(
                        f"[!!!] IPSET CAPACITY ALERT: ddos_blocklist is at {usage:.1%} capacity "
                        f"({entries}/{maxelem} entries). New attackers may fail to block."
                    )
                else:
                    logging.info(f"[+] ipset capacity status: {entries}/{maxelem} entries ({usage:.1%})")
        else:
            logging.error(f"[-] Failed to query ipset list: {res.stderr.strip()}")
    except Exception as e:
        logging.error(f"[-] Error checking ipset capacity: {e}")

def run_ipset_monitor():
    """Background thread to monitor ipset capacity status every 30 seconds."""
    logging.info("[+] Starting ipset capacity monitor thread...")
    while True:
        check_ipset_capacity()
        time.sleep(30)

def _get_ipset_members(set_name):
    """Extract member IPs and remaining timeouts directly from a kernel ipset."""
    try:
        res = subprocess.run(["ipset", "list", set_name], capture_output=True, text=True)
        if res.returncode != 0:
            return []
        lines = res.stdout.split('\n')
        members_idx = -1
        for i, line in enumerate(lines):
            if line.startswith("Members:"):
                members_idx = i
                break
        if members_idx == -1:
            return []

        members = []
        for line in lines[members_idx+1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "timeout":
                members.append({"ip": parts[0], "remaining_seconds": int(parts[2])})
            else:
                members.append({"ip": parts[0], "remaining_seconds": 3600})
        return members
    except Exception:
        return []

def get_blocked_ips():
    """Extract hard-blocked IPs and remaining timeouts directly from kernel."""
    return _get_ipset_members("ddos_blocklist")

def get_ratelimited_ips():
    """Extract rate-limited (50pps cap) IPs and remaining timeouts directly from kernel."""
    return _get_ipset_members("ddos_ratelimit")

def decode_ip(ip_bytes):
    try:
        ip_v6 = ipaddress.IPv6Address(ip_bytes)
        if ip_v6.ipv4_mapped:
            return str(ip_v6.ipv4_mapped)
        return str(ip_v6)
    except Exception as e:
        logging.error(f"[-] Failed to parse IP bytes: {e}")
        return "Unknown"

# -----------------------------------------------------------------------------
# SQLite Audit Database Helpers
# -----------------------------------------------------------------------------

def log_incident(timestamp, src_ip, classification, victim_ip="Unknown"):
    victim_ip = resolve_victim_ip(victim_ip)
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO logs (timestamp, src_ip, dst_ip, proto, rate, entropy, classification) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (timestamp, src_ip, victim_ip, "MIXED", last_metrics.get("ewma_rate", 0.0), last_metrics.get("entropy", 0.0), classification)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"[-] Failed to write incident to SQLite: {e}")

def log_metrics_history(timestamp, rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k, victim_ip):
    try:
        conn = sqlite3.connect(DB_PATH)
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

# -----------------------------------------------------------------------------
# IPC Socket Receiver Thread
# -----------------------------------------------------------------------------

def run_ipc_receiver():
    global last_metrics
    
    # Setup ipset
    setup_ipset()

    # Load Model
    if not os.path.exists(MODEL_PATH):
        logging.error(f"[-] Model not found at '{MODEL_PATH}'. UI will run in passive mode.")
        clf = None
    else:
        try:
            clf = joblib.load(MODEL_PATH)
            logging.info("[+] ML Classifier loaded successfully.")
        except Exception as e:
            logging.error(f"[-] Failed to load classifier: {e}")
            clf = None

    if os.path.exists(SOCKET_PATH):
        try:
            os.remove(SOCKET_PATH)
        except OSError:
            pass
            
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o666)
        server.listen(5)
        logging.info(f"[+] IPC socket listening on: {SOCKET_PATH}")
    except Exception as e:
        logging.error(f"[-] Failed to bind socket to {SOCKET_PATH}: {e}")
        return

    while True:
        try:
            conn, _ = server.accept()
            while True:
                data = conn.recv(PAYLOAD_SIZE)
                if not data:
                    break
                if len(data) < PAYLOAD_SIZE:
                    while len(data) < PAYLOAD_SIZE:
                        chunk = conn.recv(PAYLOAD_SIZE - len(data))
                        if not chunk:
                            break
                        data += chunk
                    if len(data) < PAYLOAD_SIZE:
                        break
                        
                unpacked = struct.unpack(FEATURE_VECTOR_FORMAT, data)
                entropy = unpacked[0]
                ewma_rate = unpacked[1]
                mean_h = unpacked[2]
                mean_r = unpacked[3]
                sigma_h = unpacked[4]
                sigma_r = unpacked[5]
                proto_ratio = unpacked[6]
                dominant_ip_ratio = unpacked[7]
                timestamp = unpacked[8]
                proto_tcp = unpacked[9]
                proto_udp = unpacked[10]
                proto_icmp = unpacked[11]
                proto_sctp = unpacked[12]
                proto_gre = unpacked[13]
                proto_esp = unpacked[14]
                k_multiplier = unpacked[15]
                cooldown_counter = unpacked[16]
                ip_str = decode_ip(unpacked[17])
                victim_ip_str = decode_ip(unpacked[18])
                victim_ip_str = resolve_victim_ip(victim_ip_str)

                # Calculate delta features
                delta_rate = ewma_rate - mean_r
                delta_entropy = entropy - mean_h

                # dominant_rate: estimated pps of the single busiest source in
                # this window. Computed once here -- fed to the classifier as
                # an input feature (matches train.py's FEATURE_COLS order
                # exactly), and reused below by the enforcement guards instead
                # of each recomputing it independently.
                dominant_rate = ewma_rate * dominant_ip_ratio

                # Load once per packet -- operator-tunable thresholds for
                # everything below (see DEFAULT_ENFORCEMENT_CONFIG for what
                # each key means and why it's configurable, not hardcoded).
                cfg = get_enforcement_config()

                pred_class = 0
                if clf:
                    import pandas as pd
                    features_df = pd.DataFrame([[
                        entropy, ewma_rate, mean_h, mean_r, sigma_h, sigma_r,
                        proto_ratio, dominant_ip_ratio, delta_rate, delta_entropy,
                        dominant_rate
                    ]], columns=[
                        "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
                        "proto_ratio", "dominant_ip_ratio", "delta_rate", "delta_entropy",
                        "dominant_rate"
                    ])
                    pred_class = int(clf.predict(features_df)[0])

                # Adaptive Safety overrides
                # 1. Rate anomaly trigger: mean_r + k_multiplier * sigma_r (mirrors Stage 1's live k)
                #    Aggregate rate is fine as the outer "is this worth a second
                #    look" gate -- it doesn't decide Flash-Crowd vs DDoS by itself.
                rate_anomaly_boundary = mean_r + k_multiplier * sigma_r
                # 2. Extreme SINGLE-SOURCE rate trigger -- based on dominant_rate
                #    (busiest source's estimated pps), NOT raw aggregate ewma_rate.
                #    Aggregate rate can't distinguish "one attacker producing an
                #    extreme volume" from "many genuine users each producing a
                #    normal trickle" -- a legitimate flash crowd's aggregate scales
                #    with participant count exactly like an attacker's does. This
                #    used to check ewma_rate directly, which meant a large but
                #    genuinely distributed crowd (e.g. running the same generator
                #    from two machines at once) could get force-classified as DDoS
                #    purely from aggregate volume, bypassing the entropy/dom_ratio
                #    check below entirely. Threshold matches Track B's per-source
                #    block_threshold for consistency -- same bar that triggers a
                #    hard block now also triggers this classification override.
                #    (block_rate_floor_pps / block_sigma_multiplier are shared
                #    with Tier 2's block_threshold below, computed once as
                #    extreme_dominant_rate_boundary and reused there too.)
                extreme_dominant_rate_boundary = max(
                    cfg["block_rate_floor_pps"], mean_r + cfg["block_sigma_multiplier"] * sigma_r
                )
                # 3. Entropy anomaly trigger: mean_h - k_multiplier * sigma_h (mirrors Stage 1's live k)
                entropy_anomaly_boundary = mean_h - k_multiplier * sigma_h

                if pred_class in (0, 1) and ewma_rate > rate_anomaly_boundary:
                    if dominant_rate > extreme_dominant_rate_boundary:
                        pred_class = 2
                    elif entropy < entropy_anomaly_boundary or dominant_ip_ratio > cfg["dominant_ip_ratio_extreme_threshold"]:
                        pred_class = 2
                    else:
                        pred_class = 1

                class_names = {0: "Normal", 1: "Flash Crowd", 2: "DDoS"}
                pred_name = class_names.get(pred_class, "Normal")

                # Update live stats
                last_metrics = {
                    "entropy": entropy,
                    "ewma_rate": ewma_rate,
                    "mean_h": mean_h,
                    "mean_r": mean_r,
                    "sigma_h": sigma_h,
                    "sigma_r": sigma_r,
                    "proto_ratio": proto_ratio,
                    "dominant_ip_ratio": dominant_ip_ratio,
                    "timestamp": timestamp,
                    "k_multiplier": k_multiplier,
                    "cooldown": int(cooldown_counter),
                    "latest_classification": pred_name,
                    "victim_ip": victim_ip_str,
                    "proto_tcp": proto_tcp,
                    "proto_udp": proto_udp,
                    "proto_icmp": proto_icmp,
                    "proto_sctp": proto_sctp,
                    "proto_gre": proto_gre,
                    "proto_esp": proto_esp
                }
                last_metrics_by_target[victim_ip_str] = last_metrics.copy()

                # Save history
                log_metrics_history(timestamp, ewma_rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k_multiplier, victim_ip_str)

                # Track consecutive class-2 windows per victim for block
                # hysteresis (rate-limiting is NOT gated by this -- only the
                # hard-block tiers below are).
                if pred_class == 2:
                    consecutive_ddos_windows[victim_ip_str] = consecutive_ddos_windows.get(victim_ip_str, 0) + 1
                else:
                    consecutive_ddos_windows[victim_ip_str] = 0

                # Trigger block / rate-limit
                if pred_class == 2:
                    if ip_str not in ("Unknown", "0.0.0.0", "::"):
                        dominant_rate_threshold = mean_r + k_multiplier * sigma_r
                        # Per-source block bar: sustained rate no legitimate
                        # client/flash-crowd participant could produce.
                        # (Same formula/values as extreme_dominant_rate_boundary
                        # above -- reuse it directly to guarantee they can't drift
                        # apart from each other.)
                        block_threshold = extreme_dominant_rate_boundary
                        # Softer bar for the rate-limit tier (unchanged from before).
                        flow_threshold = max(cfg["ratelimit_rate_floor_pps"], mean_r + sigma_r)
                        block_ready = consecutive_ddos_windows.get(victim_ip_str, 0) >= cfg["block_hysteresis_windows"]

                        # Load and aggregate active flows BY SOURCE IP once, up
                        # front -- every tier below reads from this same
                        # aggregation instead of re-parsing the flows file
                        # repeatedly. Aggregating by IP (summed across all of
                        # that source's flow tuples) rather than per-flow means
                        # an attacker spreading across multiple dst ports can't
                        # dodge the per-source thresholds below by fragmenting
                        # its traffic into several smaller-looking flows.
                        per_source_rate = {}
                        if os.path.exists(FLOWS_PATH):
                            try:
                                with open(FLOWS_PATH, "r") as f:
                                    flow_data = json.load(f)
                                for flow in flow_data.get("active_ips", []):
                                    f_ip = flow.get("ip")
                                    if f_ip and f_ip not in ("Unknown", "0.0.0.0", "::"):
                                        per_source_rate[f_ip] = per_source_rate.get(f_ip, 0.0) + flow.get("rate", 0.0)
                            except Exception as ce:
                                logging.error(f"[-] Failed to parse active flows: {ce}")

                        acted_on = set()

                        # Tier 1 -- dominant-source fast path: one source
                        # clearly drives the attack (both concentrated AND
                        # fast). Gated by hysteresis like every block action.
                        if block_ready and dominant_ip_ratio >= cfg["dominant_ip_ratio_block_threshold"] and dominant_rate >= dominant_rate_threshold:
                            block_ip(ip_str, victim_ip=victim_ip_str, duration=cfg["block_duration_seconds"])
                            acted_on.add(ip_str)

                        # Tier 2 -- independent per-source-rate escalation.
                        # NOT gated behind dominant_ip_ratio: a source
                        # sustaining an impossible rate gets blocked even if
                        # it's one of many sources and the AGGREGATE looks
                        # distributed. This is what closes the evasion gap --
                        # spreading across sources no longer helps once every
                        # source is still individually well above
                        # human/flash-crowd rates.
                        if block_ready:
                            for f_ip, agg_rate in per_source_rate.items():
                                if f_ip in acted_on:
                                    continue
                                if agg_rate >= block_threshold:
                                    logging.warning(
                                        f"[!] Per-source block: {f_ip} sustaining {agg_rate:.2f} pps "
                                        f"(threshold {block_threshold:.2f}) across its active flows."
                                    )
                                    block_ip(f_ip, victim_ip=victim_ip_str, duration=cfg["block_duration_seconds"])
                                    acted_on.add(f_ip)

                        if not block_ready and per_source_rate:
                            logging.info(
                                f"[i] Class-2 window {consecutive_ddos_windows.get(victim_ip_str, 0)}/"
                                f"{cfg['block_hysteresis_windows']} for victim {victim_ip_str} -- "
                                f"block actions held pending hysteresis, rate-limiting only this window."
                            )

                        # Tier 3 -- softer rate-limit for sources elevated but
                        # below the hard-block bar (the original Cluster Block
                        # Mode). NOT gated by hysteresis -- this is the
                        # intentionally-immediate, reversible tier.
                        for f_ip, agg_rate in per_source_rate.items():
                            if f_ip in acted_on:
                                continue
                            if agg_rate >= flow_threshold:
                                ratelimit_ip(f_ip, victim_ip=victim_ip_str, duration=cfg["ratelimit_duration_seconds"])
                                acted_on.add(f_ip)

                        # Tier 4 -- aggregate cap fallback. Class-2 verdict but
                        # nothing above matched any single source individually
                        # (fully distributed at sub-threshold per-source
                        # rates). Previously this meant doing NOTHING at all
                        # despite a confirmed DDoS classification -- rate-limit
                        # every currently-active flow to the victim as a last
                        # resort so a class-2 verdict never silently goes
                        # unhandled.
                        if not acted_on and per_source_rate:
                            logging.warning(
                                "[!] Aggregate cap fallback: class-2 verdict but no individual "
                                "source was attributable -- rate-limiting all active flows."
                            )
                            for f_ip in per_source_rate:
                                ratelimit_ip(f_ip, victim_ip=victim_ip_str, duration=cfg["ratelimit_duration_seconds"])
                        elif not per_source_rate and not acted_on:
                            logging.warning("[!] Class-2 verdict but no active flow data available to act on.")
                elif pred_class == 1:
                    # Log flash crowd incident
                    log_incident(timestamp, ip_str, "Flash Crowd", victim_ip_str)
                    # If the dominant IP rate is highly elevated during a flash crowd, apply rate-limit (not block)
                    # (dominant_rate computed once above, alongside the classifier features.)
                    dominant_rate_threshold = mean_r + k_multiplier * sigma_r
                    if ip_str not in ("Unknown", "0.0.0.0", "::") and dominant_ip_ratio >= cfg["dominant_ip_ratio_block_threshold"] and dominant_rate >= dominant_rate_threshold:
                        logging.warning(
                            f"[!] Legitimate flash crowd dominant IP {ip_str} rate highly elevated "
                            f"({dominant_rate:.2f} pps). Applying rate-limit ({cfg['ratelimit_hashlimit_pps']}pps cap) as precaution."
                        )
                        ratelimit_ip(ip_str, victim_ip=victim_ip_str, duration=cfg["ratelimit_duration_seconds"])
                elif pred_class == 0:
                    # Log normal traffic
                    log_incident(timestamp, ip_str, "Normal", victim_ip_str)

            conn.close()
        except Exception as e:
            logging.error(f"[-] Socket read loop error: {e}")
            time.sleep(1)

# -----------------------------------------------------------------------------
# FastAPI Core Web App
# -----------------------------------------------------------------------------

app = FastAPI(title="SHIELD Gateway Management Console", docs_url=None, redoc_url=None)

# Mount static files folder
app.mount("/static", StaticFiles(directory=os.path.join(SCRIPT_DIR, "static")), name="static")

# Middleware: Verify Cookie Authenticated Sessions
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # Automatically normalize active-ips.html (hyphen) to active_ips.html (underscore)
    if "active-ips.html" in path:
        new_path = path.replace("active-ips.html", "active_ips.html")
        if not new_path.startswith("/static/"):
            new_path = f"/static{new_path}"
        return RedirectResponse(url=new_path)

    # Automatically redirect root-level HTML file requests to /static/ path
    if path != "/" and path.endswith(".html") and not path.startswith("/static/"):
        return RedirectResponse(url=f"/static{path}")

    # Skip auth checks for login pages, API endpoints, css assets
    if path.startswith("/static/login.html") or path.startswith("/api/login") or path.startswith("/static/base.css"):
        return await call_next(request)

    # Protected paths: static HTMLs, API routes, root path
    if path.endswith(".html") or path == "/" or path.startswith("/api/"):
        session_id = request.cookies.get("session_id")
        is_valid = False
        if session_id in active_sessions:
            # Check 10 minutes timeout (600s)
            if time.time() - active_sessions[session_id] <= 600:
                active_sessions[session_id] = time.time()  # refresh
                is_valid = True
            else:
                del active_sessions[session_id]

        if not is_valid:
            if path.startswith("/api/"):
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=401, content={"detail": "Session expired. Re-authenticate."})
            return RedirectResponse(url="/static/login.html")

    return await call_next(request)

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")

# -----------------------------------------------------------------------------
# API Handlers
# -----------------------------------------------------------------------------

@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credentials.")
            
        stored_hash, salt = row
        hasher = hashlib.sha256()
        hasher.update((password + salt).encode('utf-8'))
        
        if hasher.hexdigest() == stored_hash:
            # Generate session
            session_token = secrets.token_hex(24)
            active_sessions[session_token] = time.time()
            response = RedirectResponse(url="/static/index.html", status_code=status.HTTP_303_SEE_OTHER)
            response.set_cookie(
                key="session_id",
                value=session_token,
                max_age=600,
                httponly=True,
                samesite="lax"
            )
            return response
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Handshake credentials rejected.")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/logout")
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in active_sessions:
        del active_sessions[session_id]
    response = RedirectResponse(url="/static/login.html")
    response.delete_cookie("session_id")
    return response

def get_interface_ip(ifname):
    import socket
    import fcntl
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        return "UNASSIGNED"

def is_interface_promisc(ifname):
    try:
        with open(f"/sys/class/net/{ifname}/flags", "r") as f:
            flags = int(f.read().strip(), 16)
            return (flags & 0x100) != 0
    except Exception:
        return False

@app.get("/api/state")
def get_state(target: Optional[str] = None):
    # Load flows
    active_flows = []
    if os.path.exists(FLOWS_PATH):
        try:
            with open(FLOWS_PATH, "r") as f:
                active_flows = json.load(f).get("active_ips", [])
        except Exception:
            pass

    # Load Whitelisted
    whitelist = load_json_file(WHITELIST_PATH, [])
    # Load Victims
    victims = load_json_file(VICTIMS_PATH, [])
    
    # Load Blocks
    blocked_detail = get_blocked_ips()
    blocked_ips_only = [b["ip"] for b in blocked_detail]

    # Load Rate-Limited (previously invisible to the dashboard -- only
    # ddos_blocklist was ever queried, so throttled IPs never showed up
    # anywhere in the UI even though the enforcement was actually active)
    ratelimited_detail = get_ratelimited_ips()
    ratelimited_ips_only = [r["ip"] for r in ratelimited_detail]

    # Load Interfaces
    interfaces = []
    try:
        for name in os.listdir('/sys/class/net'):
            try:
                with open(f"/sys/class/net/{name}/operstate", "r") as f:
                    up = f.read().strip() == "up"
            except Exception:
                up = False
            try:
                with open(f"/sys/class/net/{name}/address", "r") as f:
                    mac = f.read().strip()
            except Exception:
                mac = ""
            ip = get_interface_ip(name)
            promisc = is_interface_promisc(name)
            interfaces.append({"name": name, "mac": mac, "ip": ip, "up": up, "promisc": promisc})
    except Exception:
        pass

    # Read latest logs from db
    latest_logs = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, dst_ip, classification FROM logs WHERE classification IN ('Blocked', 'Rate Limited', 'DDoS') ORDER BY id DESC LIMIT 5")
        latest_logs = [{"timestamp": r[0], "src_ip": r[1], "victim_ip": r[2], "classification": r[3]} for r in cursor.fetchall()]
        conn.close()
    except Exception:
        pass

    # Read active sniffer interface from stage 1 service (simulate or read default ens19)
    active_interface = "ens19"
    try:
        if os.path.exists("/etc/systemd/system/ddos-stage1.service"):
            with open("/etc/systemd/system/ddos-stage1.service", "r") as f:
                content = f.read()
                for part in content.split():
                    if part.startswith("--interface"):
                        idx = content.split().index(part)
                        active_interface = content.split()[idx+1]
                        break
    except Exception:
        pass

    # Select which target's metrics to return
    metrics = last_metrics
    if target:
        metrics = last_metrics_by_target.get(target, {
            "entropy": 0.0,
            "ewma_rate": 0.0,
            "mean_h": 0.0,
            "mean_r": 0.0,
            "sigma_h": 0.0,
            "sigma_r": 0.0,
            "proto_ratio": 1.0,
            "dominant_ip_ratio": 0.0,
            "timestamp": 0.0,
            "k_multiplier": 2.0,
            "cooldown": 0,
            "latest_classification": "Normal",
            "victim_ip": target,
            "proto_tcp": 1.0,
            "proto_udp": 0.0,
            "proto_icmp": 0.0,
            "proto_sctp": 0.0,
            "proto_gre": 0.0,
            "proto_esp": 0.0
        })
    # else: no target requested -- keep `metrics = last_metrics` from above.
    # last_metrics is already the most-recently-received window across ALL
    # targets (overwritten on every packet regardless of victim), so it's
    # the correct thing to show for an overview/no-target-selected view.
    # There used to be an `elif last_metrics_by_target:` here that replaced
    # it with last_metrics_by_target[first_target] -- "first" meaning
    # whichever victim happened to be the first one ever registered, not
    # the most recent. On a multi-target setup that pinned the dashboard's
    # global status badge to one victim's stale history forever, even while
    # a different victim was actively (and correctly) logging something
    # else. Removed -- last_metrics was already right.

    return {
        **metrics,
        "active_flows": active_flows,
        "whitelisted_ips": whitelist,
        "blocked_ips": blocked_ips_only,
        "blocked_ips_detail": blocked_detail,
        "blocked_count": len(blocked_ips_only),
        "ratelimited_ips": ratelimited_ips_only,
        "ratelimited_ips_detail": ratelimited_detail,
        "ratelimited_count": len(ratelimited_ips_only),
        "victim_targets": victims,
        "interfaces": interfaces,
        "active_interface": active_interface,
        "latest_logs": latest_logs,
        "last_metrics_by_target": last_metrics_by_target
    }

@app.get("/api/history")
def get_history(target: Optional[str] = None):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        if target:
            cursor.execute(
                "SELECT timestamp, ewma_rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k_multiplier, victim_ip "
                "FROM metrics_history WHERE victim_ip = ? ORDER BY id DESC LIMIT 30",
                (target,)
            )
        else:
            cursor.execute(
                "SELECT timestamp, ewma_rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k_multiplier, victim_ip "
                "FROM metrics_history ORDER BY id DESC LIMIT 30"
            )
        rows = cursor.fetchall()
        conn.close()
        
        # Reverse to get chronological order
        rows.reverse()
        return [
            {
                "timestamp": r[0],
                "ewma_rate": r[1],
                "entropy": r[2],
                "mean_h": r[3],
                "mean_r": r[4],
                "sigma_h": r[5],
                "sigma_r": r[6],
                "k_multiplier": r[7],
                "victim_ip": r[8] if len(r) > 8 else ""
            }
            for r in rows
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Whitelist endpoints
class IpPayload(BaseModel):
    ip: str
    victim_ip: Optional[str] = None

@app.post("/api/whitelist")
def add_whitelist(payload: IpPayload):
    whitelist = load_json_file(WHITELIST_PATH, [])
    if payload.ip not in whitelist:
        whitelist.append(payload.ip)
        save_json_file(WHITELIST_PATH, whitelist)
    return {"status": "success"}

@app.delete("/api/whitelist")
def delete_whitelist(ip: str):
    whitelist = load_json_file(WHITELIST_PATH, [])
    if ip in whitelist:
        whitelist.remove(ip)
        save_json_file(WHITELIST_PATH, whitelist)
    return {"status": "success"}

# Victim targets endpoints
class VictimPayload(BaseModel):
    ip: str
    description: str

@app.post("/api/victim")
def add_victim(payload: VictimPayload):
    victims = load_json_file(VICTIMS_PATH, [])
    for v in victims:
        if v["ip"] == payload.ip:
            raise HTTPException(status_code=400, detail="Asset IP is already deployed.")
    victims.append({"ip": payload.ip, "description": payload.description, "active": True})
    save_json_file(VICTIMS_PATH, victims)
    return {"status": "success"}

@app.delete("/api/victim")
def delete_victim(ip: str):
    victims = load_json_file(VICTIMS_PATH, [])
    victims = [v for v in victims if v["ip"] != ip]
    save_json_file(VICTIMS_PATH, victims)
    return {"status": "success"}

@app.post("/api/victim/toggle")
def toggle_victim(ip: str):
    victims = load_json_file(VICTIMS_PATH, [])
    for v in victims:
        if v["ip"] == ip:
            v["active"] = not v["active"]
    save_json_file(VICTIMS_PATH, victims)
    return {"status": "success"}

# Firewall blocks endpoints
@app.post("/api/firewall/block")
def manual_block(payload: IpPayload):
    block_ip(payload.ip, duration=600, victim_ip=payload.victim_ip)
    return {"status": "success"}

@app.post("/api/firewall/unblock")
def manual_unblock(payload: IpPayload):
    if unblock_ip(payload.ip, victim_ip=payload.victim_ip):
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Failed to release firewall block.")

# -----------------------------------------------------------------------------
# Enforcement threshold configuration (dashboard-editable)
# -----------------------------------------------------------------------------

class EnforcementConfigPayload(BaseModel):
    dominant_ip_ratio_block_threshold: Optional[float] = None
    dominant_ip_ratio_extreme_threshold: Optional[float] = None
    block_rate_floor_pps: Optional[float] = None
    ratelimit_rate_floor_pps: Optional[float] = None
    block_sigma_multiplier: Optional[float] = None
    block_hysteresis_windows: Optional[int] = None
    block_duration_seconds: Optional[int] = None
    ratelimit_duration_seconds: Optional[int] = None
    ratelimit_hashlimit_pps: Optional[int] = None

@app.get("/api/config/enforcement")
def get_enforcement_config_api():
    return get_enforcement_config()

@app.post("/api/config/enforcement")
def update_enforcement_config(payload: EnforcementConfigPayload):
    current = get_enforcement_config()
    updates = {k: v for k, v in payload.dict().items() if v is not None}

    # Sanity bounds -- reject nonsensical values rather than silently
    # accepting something that would lock the system into always/never
    # blocking. Keeps this a "tune within reason" control, not a way to
    # accidentally disable enforcement from a typo.
    bounds = {
        "dominant_ip_ratio_block_threshold": (0.0, 1.0),
        "dominant_ip_ratio_extreme_threshold": (0.0, 1.0),
        "block_rate_floor_pps": (0.0, None),
        "ratelimit_rate_floor_pps": (0.0, None),
        "block_sigma_multiplier": (0.0, None),
        "block_hysteresis_windows": (0, None),
        "block_duration_seconds": (1, None),
        "ratelimit_duration_seconds": (1, None),
        "ratelimit_hashlimit_pps": (1, None),
    }
    for key, value in updates.items():
        lo, hi = bounds.get(key, (None, None))
        if lo is not None and value < lo:
            raise HTTPException(status_code=422, detail=f"{key} must be >= {lo}")
        if hi is not None and value > hi:
            raise HTTPException(status_code=422, detail=f"{key} must be <= {hi}")

    new_config = {**current, **updates}
    save_json_file(ENFORCEMENT_CONFIG_PATH, new_config)
    logging.warning(f"[+] Enforcement config updated: {updates}")

    # Hashlimit pps requires live iptables rule surgery -- every other key
    # is just a Python value read fresh on the next packet, no extra work.
    if "ratelimit_hashlimit_pps" in updates and updates["ratelimit_hashlimit_pps"] != current["ratelimit_hashlimit_pps"]:
        try:
            update_ratelimit_hashlimit(current["ratelimit_hashlimit_pps"], updates["ratelimit_hashlimit_pps"])
        except Exception as e:
            logging.error(f"[-] Failed to apply new hashlimit cap to iptables: {e}")
            raise HTTPException(status_code=500, detail=f"Config saved but iptables rule update failed: {e}")

    return new_config

# Logs API
@app.get("/api/logs")
def get_logs(classification: str = "ALL", limit: int = 50, offset: int = 0):
    # The `logs` table has no size cap -- log_incident() writes a row for
    # essentially every processed window, so over any sustained runtime this
    # table grows into the hundreds of thousands of rows. It used to be
    # fetched here with no LIMIT at all and rendered into the DOM in one
    # shot by logs.html, which froze the tab once the table got large.
    # Bounded + paginated now, with the row count operator-selectable from
    # the page itself (default 50) rather than a fixed server-side cap. The
    # full-history CSV export is intentionally left unbounded since that's
    # a deliberate one-time download, not something rendered live.
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        if classification == "ALL":
            where_clause = ""
            params: tuple = ()
        elif classification == "DDoS":
            where_clause = "WHERE classification IN ('Blocked', 'Rate Limited', 'DDoS')"
            params = ()
        else:
            where_clause = "WHERE classification = ?"
            params = (classification,)

        cursor.execute(f"SELECT COUNT(*) FROM logs {where_clause}", params)
        total_count = cursor.fetchone()[0]

        cursor.execute(
            f"SELECT timestamp, src_ip, dst_ip, proto, rate, entropy, classification "
            f"FROM logs {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + (limit, offset)
        )
        rows = cursor.fetchall()
        conn.close()
        return {
            "logs": [
                {
                    "timestamp": r[0],
                    "src_ip": r[1],
                    "dst_ip": r[2],
                    "proto": r[3],
                    "rate": r[4],
                    "entropy": r[5],
                    "classification": r[6]
                }
                for r in rows
            ],
            "total_count": total_count,
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs/export/csv")
def export_csv():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, dst_ip, proto, rate, entropy, classification FROM logs ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()

        def iter_csv():
            yield "Timestamp,Source IP,Destination IP,Protocol,Packet Rate (PPS),Shannon Entropy (bits),Classification\n"
            for r in rows:
                date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r[0]))
                yield f"{date_str},{r[1]},{r[2] or ''},{r[3] or ''},{r[4]:.2f},{r[5]:.4f},{r[6]}\n"

        return StreamingResponse(
            iter_csv(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=shield_gateway_logs.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# PDF Generator Endpoint
class PdfReportPayload(BaseModel):
    rate_chart_base64: str
    entropy_chart_base64: str

@app.post("/api/logs/export/pdf")
def export_pdf(payload: PdfReportPayload):
    import base64
    
    # Decode charts
    try:
        rate_data = base64.b64decode(payload.rate_chart_base64.split(",")[1])
        entropy_data = base64.b64decode(payload.entropy_chart_base64.split(",")[1])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 chart data: {e}")

    # Write temporary image files
    temp_rate_path = os.path.join(SCRIPT_DIR, "temp_rate.png")
    temp_entropy_path = os.path.join(SCRIPT_DIR, "temp_entropy.png")
    try:
        with open(temp_rate_path, "wb") as f:
            f.write(rate_data)
        with open(temp_entropy_path, "wb") as f:
            f.write(entropy_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to decode chart images: {e}")

    pdf_buffer = BytesIO()
    try:
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            textColor=colors.HexColor('#00a2b0'),
            spaceAfter=15
        )
        subtitle_style = ParagraphStyle(
            'SubTitleStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#5c7b80'),
            spaceAfter=25
        )
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#333333'),
            spaceAfter=10
        )
        header_style = ParagraphStyle(
            'HeaderStyle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            textColor=colors.HexColor('#00a2b0'),
            spaceAfter=8
        )

        elements = []
        
        # Title
        elements.append(Paragraph("SHIELD GATEWAY INCIDENT REPORT", title_style))
        elements.append(Paragraph(f"GENERATED: {time.strftime('%Y-%m-%d %H:%M:%S')} // SECURE LOG AUDITING", subtitle_style))
        
        # System Overview Info
        blocked_ips = get_blocked_ips()
        overview_data = [
            ["OPERATIONAL MODE", "TRANSPARENT BRIDGE"],
            ["ML CLASSIFIER MODEL", "RANDOM FOREST MULTI-CLASS"],
            ["ACTIVE BLOCKED HOSTS", f"{len(blocked_ips)} IPS IN KERNEL SET"],
            ["CURRENT INTERFACE", "ens19"]
        ]
        t_overview = Table(overview_data, colWidths=[200, 300])
        t_overview.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f5fcfd')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#00a2b0')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#111111')),
        ]))
        elements.append(t_overview)
        elements.append(Spacer(1, 20))

        # Embed Chart Images
        elements.append(Paragraph("HISTORICAL ANOMALY GRAPHICS", header_style))
        chart_table_data = [
            [RLImage(temp_rate_path, width=250, height=150), RLImage(temp_entropy_path, width=250, height=150)]
        ]
        t_charts = Table(chart_table_data, colWidths=[270, 270])
        t_charts.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(t_charts)
        elements.append(Spacer(1, 20))
        
        # Welford Baselines
        elements.append(Paragraph("CURRENT SYSTEM BASELINES", header_style))
        baseline_data = [
            ["METRIC", "CURRENT STATE", "BASELINE LIMITS"],
            ["Rate (PPS)", f"{last_metrics.get('ewma_rate', 0.0):.1f} pps", f"μ: {last_metrics.get('mean_r', 0.0):.1f} | σ: {last_metrics.get('sigma_r', 0.0):.1f} | μ+2σ: {last_metrics.get('mean_r', 0.0) + 2 * last_metrics.get('sigma_r', 0.0):.1f}"],
            ["Entropy (bits)", f"{last_metrics.get('entropy', 0.0):.4f}", f"μ: {last_metrics.get('mean_h', 0.0):.4f} | σ: {last_metrics.get('sigma_h', 0.0):.4f} | μ-2σ: {last_metrics.get('mean_h', 0.0) - 2 * last_metrics.get('sigma_h', 0.0):.4f}"],
            ["Protocol Ratios", "TCP / UDP / ICMP", f"{last_metrics.get('proto_tcp', 0.0):.1%} / {last_metrics.get('proto_udp', 0.0):.1%} / {last_metrics.get('proto_icmp', 0.0):.1%}"]
        ]
        t_base = Table(baseline_data, colWidths=[120, 150, 270])
        t_base.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00a2b0')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f9f9f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ]))
        elements.append(t_base)
        elements.append(Spacer(1, 20))

        # Blocked IPs
        elements.append(Paragraph(f"ACTIVE MITIGATION TARGETS (TOP 10)", header_style))
        blocked_data = [["BLOCKED IP", "REMAINING TIME (S)"]]
        for b in blocked_ips[:10]:
            blocked_data.append([b["ip"], str(b["remaining_seconds"])])
        if len(blocked_ips) == 0:
            blocked_data.append(["NO ACTIVE BLOCKS", "N/A"])
        
        t_blocked = Table(blocked_data, colWidths=[300, 240])
        t_blocked.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00a2b0')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f9f9f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ]))
        elements.append(t_blocked)
        elements.append(Spacer(1, 20))

        # Recent Logs Table
        elements.append(Paragraph("LATEST RECORDED THREAT METADATA (LAST 100 INCIDENTS)", header_style))
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, dst_ip, rate, entropy, classification FROM logs ORDER BY id DESC LIMIT 100")
        rows = cursor.fetchall()
        conn.close()

        log_table_data = [["TIMESTAMP", "SOURCE IP", "VICTIM IP", "RATE", "ENTROPY", "CLASSIFICATION"]]
        for r in rows:
            date_str = time.strftime('%H:%M:%S', time.localtime(r[0]))
            log_table_data.append([
                date_str,
                r[1],
                r[2],
                f"{r[3]:.1f} pps",
                f"{r[4]:.4f}",
                r[5].upper()
            ])
            
        t_logs = Table(log_table_data, colWidths=[80, 100, 100, 80, 80, 100])
        t_logs.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00a2b0')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f9f9f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('ALIGN', (0,0), (-1,-1), 'CENTER')
        ]))
        elements.append(t_logs)

        # Build PDF
        doc.build(elements)
        pdf_buffer.seek(0)
        
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=shield_gateway_report.pdf"}
        )
    except Exception as e:
        logging.error(f"[-] Failed to generate PDF Document: {e}")
        raise HTTPException(status_code=500, detail=f"PDF build error: {e}")
    finally:
        # Clean up temp image files
        if os.path.exists(temp_rate_path):
            os.remove(temp_rate_path)
        if os.path.exists(temp_entropy_path):
            os.remove(temp_entropy_path)

# -----------------------------------------------------------------------------
# Main Application Launch Hook
# -----------------------------------------------------------------------------

def start_api_server():
    import uvicorn
    logging.info("[+] Starting Uvicorn API Server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

def main():
    # Ensure SQLite initialized and migrated
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
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

    # Insert default password just in case (setup_admin.py handles this properly)
    cursor.execute("INSERT OR IGNORE INTO users VALUES ('admin', '4a0f4439c2794eb8f73111f1816e8e8156641d40a23277717469a4731c3c97e6', 'abcdef0123456789')")
    conn.commit()
    conn.close()

    # Ensure configs initialized
    load_json_file(WHITELIST_PATH, [])
    load_json_file(VICTIMS_PATH, [])

    # Start IPC socket listener thread
    ipc_thread = threading.Thread(target=run_ipc_receiver, daemon=True)
    ipc_thread.start()

    # Start IPSET capacity monitor thread
    monitor_thread = threading.Thread(target=run_ipset_monitor, daemon=True)
    monitor_thread.start()

    # Start FastAPI / Uvicorn server synchronously on main thread
    start_api_server()

if __name__ == "__main__":
    main()
