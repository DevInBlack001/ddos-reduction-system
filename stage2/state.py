"""
state.py — Shared, in-memory, mutable state for the running Stage 2 process.

Every other module reaches this state via `import state; state.xxx`, never
`from state import xxx` -- `last_metrics` in particular is replaced with a
brand-new dict on every window (see ipc_receiver.run_ipc_receiver), and a
`from` import would silently keep pointing at the stale dict object instead
of following the rebind. Module-attribute access always sees the live
value, so that's the only safe pattern here.
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
    "proto_tcp": 1.0,
    "proto_udp": 0.0,
    "proto_icmp": 0.0,
    "proto_sctp": 0.0,
    "proto_gre": 0.0,
    "proto_esp": 0.0
}

# victim_ip -> last_metrics dict for that specific victim.
last_metrics_by_target = {}

# Hysteresis for hard blocks: how many CONSECUTIVE class-2 (DDoS) windows a
# victim must see before a block action is allowed to fire (configurable --
# see config.DEFAULT_ENFORCEMENT_CONFIG["block_hysteresis_windows"]).
# Rate-limiting is unaffected by this -- it's intentionally the immediate,
# reversible tier. Keeps a single noisy window from triggering an
# irreversible-feeling action; the ipset entries self-heal regardless, this
# just raises the bar before an entry gets created in the first place.
consecutive_ddos_windows = {}  # victim_ip -> count of consecutive class-2 windows

# ip -> last-acted-on timestamp, used by enforcement.block_ip/ratelimit_ip
# to debounce repeated ipset calls for the same IP within a short window.
recently_blocked = {}

# session_token -> last_active_timestamp
active_sessions = {}

# Login brute-force throttling -- keyed by client IP, not username, so an
# attacker can't dodge the lockout by cycling usernames.
failed_login_attempts = {}  # client_ip -> list of failure timestamps
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECS = 300
LOGIN_LOCKOUT_SECS = 300
