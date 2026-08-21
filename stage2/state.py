"""
state.py: Shared, in-memory, mutable state for the running Stage 2 process.

Always reached via `import state; state.xxx`, never `from state import xxx`:
`last_metrics` gets rebound to a new dict every window, and a `from` import
would keep pointing at the stale object.
"""

# Most recent window's metrics, across all victims (last one received wins).
# Used for the dashboard's overview/no-target-selected view.
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
    # V5: None until a window arrives from a sensor with an egress interface.
    "egress_rate": None,
    "drop_ratio": None,
    "proto_tcp": 1.0,
    "proto_udp": 0.0,
    "proto_icmp": 0.0,
    "proto_sctp": 0.0,
    "proto_gre": 0.0,
    "proto_esp": 0.0
}

# victim_ip -> last_metrics dict for that specific victim.
last_metrics_by_target = {}

# victim_ip -> count of consecutive class-2 (DDoS) windows, gating hard
# blocks (config.DEFAULT_ENFORCEMENT_CONFIG["block_hysteresis_windows"]).
# Rate-limiting isn't gated by this, it's the immediate, reversible tier.
consecutive_ddos_windows = {}

# ip -> last-acted-on timestamp, used by enforcement.block_ip/ratelimit_ip
# to debounce repeated ipset calls for the same IP within a short window.
recently_blocked = {}

# session_token -> {"username": str, "last_active": float}. Keyed by
# username too so auth.revoke_sessions_for_user() can invalidate a specific
# account's sessions after a password change or deletion.
active_sessions = {}

# Login brute-force throttling, keyed by client IP, not username, so an
# attacker can't dodge the lockout by cycling usernames.
failed_login_attempts = {}  # client_ip -> list of failure timestamps
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECS = 300
LOGIN_LOCKOUT_SECS = 300

# Throttling for the admin-password re-entry account management requires
# (users.py), keyed by the caller's own username: the same lockout policy
# as login, since the caller already holds a valid session and could
# otherwise guess unboundedly.
failed_reauth_attempts = {}  # username -> list of failure timestamps

SESSION_IDLE_TIMEOUT_SECS = 600

# victim_ip -> last classification seen, so alerts.py only alerts on an
# actual transition, not every window spent classified DDoS.
last_classification_by_target = {}

# ip -> timestamp of the last block alert sent, suppressed for
# cfg["block_duration_seconds"] (see alerts.py).
last_block_alert = {}

# ip -> {"victim_ip", "rate", "timestamp", "action"} for addresses a block
# named as attackers, which is a stricter set than either ipset: the
# rate-limit set also holds flash crowd precautions and the aggregate
# fallback's indiscriminate cap on every active flow.
# Seeded from the incident log at startup, because ipset entries outlive the
# process. Capped, since an attacker controls how many sources appear.
ddos_sources = {}
DDOS_SOURCES_MAX = 4096
