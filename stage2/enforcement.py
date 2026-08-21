"""
enforcement.py: ipset/iptables control, block/ratelimit/unblock actions,
and victim-IP resolution.
"""

import os
import json
import time
import subprocess
import logging

import config
import state
import db
from storage import load_json_file

# What gets written to logs.classification by an enforcement action.
# The two rate-limit labels record why the cap was applied, which the cap
# itself does not distinguish: the same ipset holds sources of an
# unattributable DDoS and the dominant source of a legitimate flash crowd.
CLASS_BLOCKED = "Blocked"
CLASS_RATELIMITED = "Rate Limited"
CLASS_RATELIMITED_FLASH = "Rate Limited (Flash Crowd)"
CLASS_RELEASED = "Released"

# Only a block names an address as an attacker. Blocking requires a DDoS
# verdict sustained across block_hysteresis_windows and a source the window
# actually attributes the traffic to. Rate-limiting requires neither: the
# aggregate fallback caps every active flow to the victim when no individual
# source is attributable, so its members are whoever was talking to the host
# at the time, not confirmed attackers.
DDOS_CLASSIFICATIONS = (CLASS_BLOCKED,)


def record_ddos_source(ip, classification, victim_ip, src_rate, when):
    """Note an address named as an attacker by a block.

    Any lesser action clears an earlier entry instead of adding one: the most
    recent verdict for an address is the one that stands.
    """
    if classification not in DDOS_CLASSIFICATIONS:
        state.ddos_sources.pop(ip, None)
        return

    state.ddos_sources[ip] = {
        "ip": ip,
        "victim_ip": victim_ip,
        "rate": src_rate,
        "timestamp": when,
        "action": classification,
    }
    _prune_ddos_sources()


def _prune_ddos_sources():
    """Keep the newest entries once the cap is passed.

    How many sources appear is attacker controlled, so the bound is on count
    rather than on age. Trimmed well below the cap rather than to it, so a
    flood does not pay for a sort on every source it adds.
    """
    if len(state.ddos_sources) <= state.DDOS_SOURCES_MAX:
        return
    keep = int(state.DDOS_SOURCES_MAX * 0.9)
    newest = sorted(
        state.ddos_sources.items(),
        key=lambda item: item[1]["timestamp"],
        reverse=True,
    )[:keep]
    state.ddos_sources.clear()
    state.ddos_sources.update(newest)


def load_ddos_sources():
    """Rebuild the DDoS source list from the incident log at startup.

    ipset entries outlive the Stage 2 process, so without this a restart
    during an attack leaves enforcement active but the dashboard unable to
    say which addresses it is enforcing against.
    """
    try:
        conn = db.connect()
        rows = conn.execute(
            "SELECT src_ip, dst_ip, rate, timestamp, classification FROM logs"
            " WHERE classification IN (?, ?, ?)"
            " ORDER BY id DESC LIMIT ?",
            (CLASS_BLOCKED, CLASS_RATELIMITED, CLASS_RATELIMITED_FLASH,
             state.DDOS_SOURCES_MAX * 4),
        ).fetchall()
        conn.close()
    except Exception as e:
        logging.error(f"[-] Could not restore the DDoS source list: {e}")
        return

    seen = set()
    for src_ip, dst_ip, rate, when, classification in rows:
        # Rows arrive newest first, so a later row for the same address is
        # an older action and must not overwrite the current verdict.
        if src_ip in seen:
            continue
        seen.add(src_ip)
        record_ddos_source(src_ip, classification, dst_ip, rate, when)

    if state.ddos_sources:
        logging.info(f"[+] Restored {len(state.ddos_sources)} DDoS source records from the incident log")


def resolve_victim_ip(victim_ip=None):
    if victim_ip and victim_ip not in ("Unknown", "0.0.0.0", "::"):
        return victim_ip

    try:
        if os.path.exists(config.VICTIMS_PATH):
            with open(config.VICTIMS_PATH, "r") as f:
                victims = json.load(f)
                active_victims = [v["ip"] for v in victims if v.get("active")]
                if active_victims:
                    return active_victims[0]
                if victims:
                    return victims[0]["ip"]
    except Exception:
        pass

    if state.last_metrics_by_target:
        return next(iter(state.last_metrics_by_target.keys()))

    return "Unknown"


# Kernel netfilter blocklist control (ipset / iptables)

def _ensure_hashlimit_rule(pps):
    """Insert the ddos_ratelimit hashlimit rule (INPUT + FORWARD) at the
    given pps cap, if not already present. Idempotent, iptables -C checks
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
    matches the OLD value and inserting one with the new value, there's
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
        # ratelimit_hashlimit_pps), ensure the rule reflects whatever is
        # currently configured, not a hardcoded value, so a value saved
        # before a restart takes effect immediately on startup too.
        _ensure_hashlimit_rule(config.get_enforcement_config()["ratelimit_hashlimit_pps"])

    except Exception as e:
        logging.warning(f"[-] Could not setup/verify ipset or iptables: {e}")


def block_ip(ip, duration=3600, victim_ip="Unknown", src_rate=None):
    """Add offending IP to ddos_blocklist."""
    now = time.time()

    if ip in state.recently_blocked and now - state.recently_blocked[ip] < 10.0:
        return

    victim_ip = resolve_victim_ip(victim_ip)
    try:
        # Check whitelist bypass
        whitelist = load_json_file(config.WHITELIST_PATH, [])
        if ip in whitelist:
            logging.info(f"[Whitelist Bypass] Skipping block for whitelisted administrative IP: {ip}")
            return

        # NAT-safe enforcement: a shared egress IP fronts many hosts, so the
        # unconditional DROP in ddos_blocklist would cut off every legitimate
        # user behind it. Throttle instead, the attacker's share of the
        # traffic is capped while everyone else keeps working.
        shared_ips = load_json_file(config.SHARED_IPS_PATH, [])
        if ip in shared_ips:
            logging.warning(
                f"[NAT-Safe] {ip} is marked as a shared/NAT egress point, "
                f"rate-limiting instead of hard-blocking."
            )
            ratelimit_ip(ip, duration=duration, victim_ip=victim_ip, src_rate=src_rate)
            return

        res = subprocess.run(
            ["ipset", "add", "ddos_blocklist", ip, "timeout", str(duration), "-exist"],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            logging.warning(f"[!!!] MITIGATION TRIGGERED: Blocked offending IP {ip} (duration: {duration}s)")
            db.log_incident(now, ip, CLASS_BLOCKED, victim_ip, src_rate)
            record_ddos_source(ip, CLASS_BLOCKED, victim_ip, src_rate, now)
        else:
            logging.error(f"[-] Failed to block IP {ip}: {res.stderr.strip()}")
    except Exception as e:
        logging.error(f"[-] Error calling ipset: {e}")
    finally:
        state.recently_blocked[ip] = now

def ratelimit_ip(ip, duration=3600, victim_ip="Unknown", src_rate=None,
                 classification=CLASS_RATELIMITED):
    """Add offending IP to ddos_ratelimit set (enforces the configured
    ratelimit_hashlimit_pps cap, default 50pps).

    `classification` is what gets recorded, and it is not always the same
    verdict. The same cap is applied both to sources of a DDoS the classifier
    could not attribute to any single address, and, precautionarily, to the
    dominant source of a window judged a legitimate flash crowd. Recording
    both as the same thing makes the two indistinguishable afterwards, so the
    flash crowd path passes CLASS_RATELIMITED_FLASH instead."""
    now = time.time()

    if ip in state.recently_blocked and now - state.recently_blocked[ip] < 10.0:
        return

    victim_ip = resolve_victim_ip(victim_ip)
    try:
        # Check whitelist bypass
        whitelist = load_json_file(config.WHITELIST_PATH, [])
        if ip in whitelist:
            logging.info(f"[Whitelist Bypass] Skipping rate-limit for whitelisted administrative IP: {ip}")
            return

        res = subprocess.run(
            ["ipset", "add", "ddos_ratelimit", ip, "timeout", str(duration), "-exist"],
            capture_output=True,
            text=True
        )
        if res.returncode == 0:
            rl_cap = config.get_enforcement_config()["ratelimit_hashlimit_pps"]
            logging.warning(f"[!!!] MITIGATION TRIGGERED: Rate-limited offending IP {ip} (duration: {duration}s, {rl_cap}pps cap)")
            db.log_incident(now, ip, classification, victim_ip, src_rate)
            record_ddos_source(ip, classification, victim_ip, src_rate, now)
        else:
            logging.error(f"[-] Failed to rate-limit IP {ip}: {res.stderr.strip()}")
    except Exception as e:
        logging.error(f"[-] Error calling ipset: {e}")
    finally:
        state.recently_blocked[ip] = now

def unblock_ip(ip, victim_ip="Unknown"):
    """Remove IP from both ddos_blocklist and ddos_ratelimit."""
    victim_ip = resolve_victim_ip(victim_ip)
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
            db.log_incident(time.time(), ip, CLASS_RELEASED, victim_ip)
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
    """Extract throttled IPs and remaining timeouts directly from kernel.

    The cap itself is operator-configurable (ratelimit_hashlimit_pps)."""
    return _get_ipset_members("ddos_ratelimit")
