"""
api.py — Dashboard state/history endpoints, whitelist/victim/firewall
management, and the enforcement-config editor.
"""

import os
import json
import sqlite3
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse

import config
import state
import enforcement
from storage import load_json_file, save_json_file
from models import IpPayload, VictimPayload, EnforcementConfigPayload, _validate_host_ip_or_400

router = APIRouter()


@router.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")


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


@router.get("/api/state")
def get_state(target: Optional[str] = None):
    # Load flows
    active_flows = []
    if os.path.exists(config.FLOWS_PATH):
        try:
            with open(config.FLOWS_PATH, "r") as f:
                active_flows = json.load(f).get("active_ips", [])
        except Exception:
            pass

    # Load Whitelisted
    whitelist = load_json_file(config.WHITELIST_PATH, [])
    # V5: shared/NAT egress points
    shared_ips = load_json_file(config.SHARED_IPS_PATH, [])
    # Load Victims
    victims = load_json_file(config.VICTIMS_PATH, [])

    # Load Blocks
    blocked_detail = enforcement.get_blocked_ips()
    blocked_ips_only = [b["ip"] for b in blocked_detail]

    # Load Rate-Limited (previously invisible to the dashboard -- only
    # ddos_blocklist was ever queried, so throttled IPs never showed up
    # anywhere in the UI even though the enforcement was actually active)
    ratelimited_detail = enforcement.get_ratelimited_ips()
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
        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, src_ip, dst_ip, classification FROM logs WHERE classification IN ('Blocked', 'Rate Limited', 'DDoS') ORDER BY id DESC LIMIT 5")
        latest_logs = [{"timestamp": r[0], "src_ip": r[1], "victim_ip": r[2], "classification": r[3]} for r in cursor.fetchall()]
        conn.close()
    except Exception:
        pass

    # Both sniffer interfaces, read from the Stage 1 unit file. Reporting
    # only --interface left the egress NIC showing as idle on the
    # interfaces page even while it was actively being captured.
    active_interface, egress_interface = config.get_sniffer_interfaces()

    # Select which target's metrics to return
    metrics = state.last_metrics
    if target:
        metrics = state.last_metrics_by_target.get(target, {
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
            "egress_rate": None,
            "drop_ratio": None,
            "proto_tcp": 1.0,
            "proto_udp": 0.0,
            "proto_icmp": 0.0,
            "proto_sctp": 0.0,
            "proto_gre": 0.0,
            "proto_esp": 0.0
        })
    # else: no target requested -- state.last_metrics is already the most
    # recent window across all targets, correct for the overview view.

    return {
        **metrics,
        "active_flows": active_flows,
        "whitelisted_ips": whitelist,
        "shared_ips": shared_ips,
        "blocked_ips": blocked_ips_only,
        "blocked_ips_detail": blocked_detail,
        "blocked_count": len(blocked_ips_only),
        "ratelimited_ips": ratelimited_ips_only,
        "ratelimited_ips_detail": ratelimited_detail,
        "ratelimited_count": len(ratelimited_ips_only),
        "victim_targets": victims,
        "interfaces": interfaces,
        "active_interface": active_interface,
        "egress_interface": egress_interface,
        "latest_logs": latest_logs,
        "last_metrics_by_target": state.last_metrics_by_target
    }


@router.get("/api/history")
def get_history(target: Optional[str] = None):
    try:
        conn = sqlite3.connect(config.DB_PATH)
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
@router.post("/api/whitelist")
def add_whitelist(payload: IpPayload):
    whitelist = load_json_file(config.WHITELIST_PATH, [])
    if payload.ip not in whitelist:
        whitelist.append(payload.ip)
        save_json_file(config.WHITELIST_PATH, whitelist)
    return {"status": "success"}

@router.delete("/api/whitelist")
def delete_whitelist(ip: str):
    ip = _validate_host_ip_or_400(ip)
    whitelist = load_json_file(config.WHITELIST_PATH, [])
    if ip in whitelist:
        whitelist.remove(ip)
        save_json_file(config.WHITELIST_PATH, whitelist)
    return {"status": "success"}


# V5: shared/NAT egress points -- rate-limited but never hard-blocked, so a
# single ipset entry can't take out every legitimate user behind them.
@router.post("/api/shared-ips")
def add_shared_ip(payload: IpPayload):
    shared = load_json_file(config.SHARED_IPS_PATH, [])
    if payload.ip not in shared:
        shared.append(payload.ip)
        save_json_file(config.SHARED_IPS_PATH, shared)
        logging.warning(f"[+] Marked {payload.ip} as a shared/NAT egress point (never hard-blocked)")
    return {"status": "success"}

@router.delete("/api/shared-ips")
def delete_shared_ip(ip: str):
    ip = _validate_host_ip_or_400(ip)
    shared = load_json_file(config.SHARED_IPS_PATH, [])
    if ip in shared:
        shared.remove(ip)
        save_json_file(config.SHARED_IPS_PATH, shared)
        logging.warning(f"[+] {ip} is no longer marked as a shared/NAT egress point")
    return {"status": "success"}


# Victim targets endpoints
@router.post("/api/victim")
def add_victim(payload: VictimPayload):
    victims = load_json_file(config.VICTIMS_PATH, [])
    for v in victims:
        if v["ip"] == payload.ip:
            raise HTTPException(status_code=400, detail="Asset IP is already deployed.")
    victims.append({"ip": payload.ip, "description": payload.description, "active": True})
    save_json_file(config.VICTIMS_PATH, victims)
    return {"status": "success"}

@router.delete("/api/victim")
def delete_victim(ip: str):
    ip = _validate_host_ip_or_400(ip)
    victims = load_json_file(config.VICTIMS_PATH, [])
    victims = [v for v in victims if v["ip"] != ip]
    save_json_file(config.VICTIMS_PATH, victims)
    return {"status": "success"}

@router.post("/api/victim/toggle")
def toggle_victim(ip: str):
    ip = _validate_host_ip_or_400(ip)
    victims = load_json_file(config.VICTIMS_PATH, [])
    for v in victims:
        if v["ip"] == ip:
            v["active"] = not v["active"]
    save_json_file(config.VICTIMS_PATH, victims)
    return {"status": "success"}


# Firewall blocks endpoints
@router.post("/api/firewall/block")
def manual_block(payload: IpPayload):
    enforcement.block_ip(payload.ip, duration=600, victim_ip=payload.victim_ip)
    return {"status": "success"}

@router.post("/api/firewall/unblock")
def manual_unblock(payload: IpPayload):
    if enforcement.unblock_ip(payload.ip, victim_ip=payload.victim_ip):
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Failed to release firewall block.")


# -----------------------------------------------------------------------------
# Enforcement threshold configuration (dashboard-editable)
# -----------------------------------------------------------------------------

@router.get("/api/config/enforcement")
def get_enforcement_config_api():
    return config.get_enforcement_config()

@router.post("/api/config/enforcement")
def update_enforcement_config(payload: EnforcementConfigPayload):
    current = config.get_enforcement_config()
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
    save_json_file(config.ENFORCEMENT_CONFIG_PATH, new_config)
    logging.warning(f"[+] Enforcement config updated: {updates}")

    # Hashlimit pps requires live iptables rule surgery -- every other key
    # is just a Python value read fresh on the next packet, no extra work.
    if "ratelimit_hashlimit_pps" in updates and updates["ratelimit_hashlimit_pps"] != current["ratelimit_hashlimit_pps"]:
        try:
            enforcement.update_ratelimit_hashlimit(current["ratelimit_hashlimit_pps"], updates["ratelimit_hashlimit_pps"])
        except Exception as e:
            logging.error(f"[-] Failed to apply new hashlimit cap to iptables: {e}")
            raise HTTPException(status_code=500, detail=f"Config saved but iptables rule update failed: {e}")

    return new_config


# Logs API
@router.get("/api/logs")
def get_logs(classification: str = "ALL", limit: int = 50, offset: int = 0):
    # The `logs` table has no size cap and can grow into the hundreds of
    # thousands of rows, so this endpoint is paginated (the CSV export
    # stays unbounded -- that's a deliberate one-time download).
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    try:
        conn = sqlite3.connect(config.DB_PATH)
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
