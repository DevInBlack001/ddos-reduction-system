"""
report_data.py: aggregates the `logs`/`metrics_history` tables and live
enforcement state into the plain-data context the PDF incident report
renders from. No HTML or PDF concerns live here.
"""

import math
import time
import uuid

import config
import db
import state
import enforcement

# "Released" marks an enforcement action being lifted, not a traffic
# classification, so it is excluded from the mix, the per-window chart, and
# the timeline. "Rate Limited (Flash Crowd)" is its own row in the mix but
# folds into "Rate Limited" for the stacked per-window chart, since giving it
# a fifth sliver there is unreadable at typical volumes. "Anomalous" (V7) is
# the Isolation Forest flagging a window the RandomForest called Normal or
# Flash Crowd as unlike anything either model has seen, kept as its own
# slice rather than folded in, since it is a distinct signal, not a variant
# of an existing one, see stage2/ipc_receiver.py.
TRAFFIC_CLASSES = ["Normal", "Flash Crowd", "Anomalous", "Rate Limited (Flash Crowd)", "Rate Limited", "Blocked"]
STACK_CLASSES = ["Normal", "Flash Crowd", "Anomalous", "Rate Limited", "Blocked"]
SEVERITY_ORDER = ["Blocked", "Rate Limited", "Rate Limited (Flash Crowd)", "Flash Crowd", "Anomalous", "Normal"]

COLORS = {
    "Normal": "#5b93a8",
    "Flash Crowd": "#dcc257",
    "Anomalous": "#a78bfa",
    "Rate Limited": "#d99a4a",
    "Rate Limited (Flash Crowd)": "#e3d67e",
    "Blocked": "#c8493c",
}

MAX_BUCKETS = 180
BUCKET_STEPS_SECONDS = (60, 300, 900, 1800, 3600, 7200, 21600, 43200, 86400)
MAX_LIST_ROWS = 10
MAX_PHASES = 4


def _pick_bucket_seconds(hours: float) -> int:
    span = max(hours, 1 / 60) * 3600
    for step in BUCKET_STEPS_SECONDS:
        if span / step <= MAX_BUCKETS:
            return step
    return BUCKET_STEPS_SECONDS[-1]


def _nice_ceiling(value: float) -> float:
    """Round up to a visually clean axis maximum: 1/2/5 x a power of ten."""
    if value <= 0:
        return 1.0
    exp = math.floor(math.log10(value))
    for mult in (1, 2, 5, 10):
        candidate = mult * (10 ** exp)
        if candidate >= value:
            return float(candidate)
    return float(10 ** (exp + 1))


def _fmt_int(n) -> str:
    return f"{int(n):,}"


def _fmt_time(epoch: float) -> str:
    return time.strftime("%H:%M", time.gmtime(epoch))


def _bucket_time(bucket_idx: int, bucket_seconds: int) -> float:
    return bucket_idx * bucket_seconds


def _rate_threshold(mean_r, sigma_r, k):
    return (mean_r or 0.0) + (k or 2.0) * (sigma_r or 0.0)


def _entropy_threshold(mean_h, sigma_h, k):
    return (mean_h or 0.0) - (k or 2.0) * (sigma_h or 0.0)


def build_context(hours: float) -> dict:
    since = time.time() - hours * 3600
    bucket_s = _pick_bucket_seconds(hours)

    conn = db.connect()
    cur = conn.cursor()

    cur.execute(
        "SELECT COUNT(*), COUNT(DISTINCT src_ip), COUNT(DISTINCT dst_ip) FROM logs "
        "WHERE timestamp >= ? AND classification != 'Released'",
        (since,),
    )
    total_records, unique_sources, unique_victims = cur.fetchone()
    total_records = total_records or 0

    cur.execute(
        "SELECT classification, COUNT(*) FROM logs WHERE timestamp >= ? "
        "AND classification != 'Released' GROUP BY classification",
        (since,),
    )
    mix_counts = dict(cur.fetchall())

    cur.execute(
        "SELECT src_ip, COUNT(*) AS n FROM logs WHERE timestamp >= ? "
        "AND classification != 'Released' GROUP BY src_ip ORDER BY n DESC LIMIT ?",
        (since, MAX_LIST_ROWS),
    )
    top_sources_rows = cur.fetchall()

    cur.execute(
        "SELECT dst_ip, COUNT(*) AS n FROM logs WHERE timestamp >= ? AND dst_ip IS NOT NULL "
        "AND classification != 'Released' GROUP BY dst_ip ORDER BY n DESC LIMIT ?",
        (since, MAX_LIST_ROWS),
    )
    top_victims_rows = cur.fetchall()

    cur.execute(
        "SELECT CAST(timestamp / ? AS INTEGER) AS bucket, classification, COUNT(*), MAX(rate), AVG(entropy) "
        "FROM logs WHERE timestamp >= ? AND classification != 'Released' "
        "GROUP BY bucket, classification ORDER BY bucket",
        (bucket_s, since),
    )
    class_rows = cur.fetchall()

    cur.execute(
        "SELECT CAST(timestamp / ? AS INTEGER) AS bucket, MAX(rate), AVG(entropy) FROM logs "
        "WHERE timestamp >= ? AND classification != 'Released' GROUP BY bucket",
        (bucket_s, since),
    )
    bucket_stats = {r[0]: (r[1] or 0.0, r[2] if r[2] is not None else None) for r in cur.fetchall()}

    cur.execute(
        "SELECT CAST(timestamp / ? AS INTEGER) AS bucket, AVG(mean_r), AVG(sigma_r), "
        "AVG(mean_h), AVG(sigma_h), AVG(k_multiplier) FROM metrics_history "
        "WHERE timestamp >= ? GROUP BY bucket",
        (bucket_s, since),
    )
    threshold_rows = {r[0]: r[1:] for r in cur.fetchall()}

    conn.close()

    bucket_class_counts = {}
    for bucket_idx, classification, n, _max_rate, _avg_entropy in class_rows:
        bucket_class_counts.setdefault(bucket_idx, {}).setdefault(classification, 0)
        bucket_class_counts[bucket_idx][classification] += n

    live = state.last_metrics
    fallback_threshold = (live.get("mean_r", 0.0), live.get("sigma_r", 0.0),
                           live.get("mean_h", 0.0), live.get("sigma_h", 0.0), live.get("k_multiplier", 2.0))

    cols = []
    max_total_per_bucket = 1
    max_peak_rate = 1.0
    lo, hi = (min(bucket_stats), max(bucket_stats)) if bucket_stats else (0, -1)
    for idx in range(lo, hi + 1):
        counts = bucket_class_counts.get(idx, {})
        stacked = {cls: counts.get(cls, 0) for cls in STACK_CLASSES}
        stacked["Rate Limited"] += counts.get("Rate Limited (Flash Crowd)", 0)
        total = sum(stacked.values())
        max_total_per_bucket = max(max_total_per_bucket, total)

        peak_rate, avg_entropy = bucket_stats.get(idx, (0.0, None))
        max_peak_rate = max(max_peak_rate, peak_rate)

        mean_r, sigma_r, mean_h, sigma_h, k = threshold_rows.get(idx, fallback_threshold)
        rate_threshold = _rate_threshold(mean_r, sigma_r, k)
        entropy_threshold = _entropy_threshold(mean_h, sigma_h, k)

        dominant = None
        for cls in SEVERITY_ORDER:
            if counts.get(cls, 0) > 0:
                dominant = cls
                break

        cols.append({
            "idx": idx,
            "start": _bucket_time(idx, bucket_s),
            "total": total,
            "stacked": stacked,
            "peak_rate": peak_rate,
            "avg_entropy": avg_entropy,
            "rate_threshold": rate_threshold,
            "entropy_threshold": entropy_threshold,
            "dominant": dominant,
            "counts": counts,
        })

    axis_total_max = _nice_ceiling(max_total_per_bucket)
    axis_rate_max = _nice_ceiling(max(max_peak_rate, max((c["rate_threshold"] for c in cols), default=1.0)))

    label_every = max(1, len(cols) // 22) if cols else 1
    for i, c in enumerate(cols):
        c["tick"] = _fmt_time(c["start"]) if i % label_every == 0 else ""
        c["h_normal"] = f"{c['stacked']['Normal'] / axis_total_max * 100:.2f}%"
        c["h_flash"] = f"{c['stacked']['Flash Crowd'] / axis_total_max * 100:.2f}%"
        c["h_anomalous"] = f"{c['stacked']['Anomalous'] / axis_total_max * 100:.2f}%"
        c["h_rl"] = f"{c['stacked']['Rate Limited'] / axis_total_max * 100:.2f}%"
        c["h_blocked"] = f"{c['stacked']['Blocked'] / axis_total_max * 100:.2f}%"
        pr = c["peak_rate"]
        c["rate_h"] = f"{(math.log10(pr + 1) / math.log10(axis_rate_max + 1) * 100):.2f}%" if pr > 0 else "0%"
        if c["rate_threshold"] <= 0:
            # No learned baseline yet for this window (still warming up):
            # nothing to compare against, so don't paint it as anomalous.
            c["rate_color"] = COLORS["Normal"]
        else:
            c["rate_color"] = (COLORS["Blocked"] if pr > c["rate_threshold"] * 10 else
                                COLORS["Rate Limited"] if pr > c["rate_threshold"] else COLORS["Normal"])
        if c["avg_entropy"] is None:
            c["entropy_h"] = "0%"
            c["entropy_color"] = COLORS["Normal"]
        else:
            c["entropy_h"] = f"{max(0.0, min(1.0, c['avg_entropy'])) * 100:.2f}%"
            c["entropy_color"] = COLORS["Blocked"] if c["avg_entropy"] < c["entropy_threshold"] else COLORS["Normal"]

    rate_threshold_pct = (f"{(math.log10(cols[-1]['rate_threshold'] + 1) / math.log10(axis_rate_max + 1) * 100):.2f}%"
                           if cols else "0%")
    entropy_threshold_pct = f"{max(0.0, min(1.0, cols[-1]['entropy_threshold'])) * 100:.2f}%" if cols else "0%"
    entropy_threshold_val = cols[-1]["entropy_threshold"] if cols else _entropy_threshold(*fallback_threshold[2:4], fallback_threshold[4])
    rate_threshold_val = cols[-1]["rate_threshold"] if cols else _rate_threshold(*fallback_threshold[0:2], fallback_threshold[4])

    phases = _build_phases(cols, bucket_s)

    classes_mix = []
    for cls in TRAFFIC_CLASSES:
        n = mix_counts.get(cls, 0)
        pct = (n / total_records * 100) if total_records else 0.0
        classes_mix.append({"name": cls, "n": n, "count": _fmt_int(n), "pct": f"{pct:.2f}%",
                             "w": f"{pct:.3f}%", "color": COLORS[cls]})

    max_victim = max((n for _ip, n in top_victims_rows), default=1)
    victims = [{"ip": ip, "n": _fmt_int(n), "w": f"{n / max_victim * 100:.2f}%"} for ip, n in top_victims_rows]

    max_source = max((n for _ip, n in top_sources_rows), default=1)
    sources = [{
        "ip": ip, "n": _fmt_int(n), "w": f"{n / max_source * 100:.2f}%",
        "unattributed": ip in ("0.0.0.0", "::", "Unknown"),
    } for ip, n in top_sources_rows]
    unattributed_source = next((s for s in sources if s["unattributed"]), None)

    blocked_ips = sorted(enforcement.get_blocked_ips(), key=lambda b: -b["remaining_seconds"])
    ratelimited_ips = enforcement.get_ratelimited_ips()
    max_block_hold = max((b["remaining_seconds"] for b in blocked_ips), default=1)
    blocks = [{
        "ip": b["ip"], "left": f"{b['remaining_seconds']}s",
        "w": f"{min(100.0, b['remaining_seconds'] / max_block_hold * 100):.2f}%",
    } for b in blocked_ips[:MAX_LIST_ROWS]]

    peak_rate_overall = max((c["peak_rate"] for c in cols), default=0.0)
    peak_multiple = (peak_rate_overall / rate_threshold_val) if rate_threshold_val > 0 else 0.0

    below_entropy = sum(1 for c in cols if c["avg_entropy"] is not None and c["avg_entropy"] < c["entropy_threshold"])
    below_entropy_pct = (below_entropy / len(cols) * 100) if cols else 0.0

    current_rate = live.get("ewma_rate", 0.0)
    current_entropy = live.get("entropy", 0.0)
    live_rate_threshold = _rate_threshold(live.get("mean_r"), live.get("sigma_r"), live.get("k_multiplier"))
    live_entropy_threshold = _entropy_threshold(live.get("mean_h"), live.get("sigma_h"), live.get("k_multiplier"))

    enforced_total = len(blocked_ips) + len(ratelimited_ips)
    blocked_share = (len(blocked_ips) / enforced_total * 100) if enforced_total else 0.0
    ratelimited_share = 100.0 - blocked_share if enforced_total else 0.0

    window_start = cols[0]["start"] if cols else since
    window_end = cols[-1]["start"] + bucket_s if cols else time.time()
    ingress_iface, egress_iface = config.get_sniffer_interfaces()

    return {
        "report_id": f"FLOD-{uuid.uuid4().hex[:12].upper()}",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "window_label": f"{_fmt_time(window_start)} → {_fmt_time(window_end)} UTC" if cols else "no traffic in the selected window",
        "hours": hours,
        "version": config.VERSION,
        "ingress_iface": ingress_iface or "not configured",
        "egress_iface": egress_iface or "not configured",
        "classifier_state": live.get("latest_classification", "Normal"),
        "total_records": _fmt_int(total_records),
        "unique_sources": unique_sources or 0,
        "unique_victims": unique_victims or 0,
        "blocked_count": len(blocked_ips),
        "ratelimited_count": len(ratelimited_ips),
        "peak_rate": peak_rate_overall,
        "peak_rate_fmt": f"{peak_rate_overall:,.0f}",
        "peak_multiple": peak_multiple,
        "cols": cols,
        "axis_total_ticks": [_fmt_int(axis_total_max), _fmt_int(axis_total_max * 2 / 3), _fmt_int(axis_total_max / 3), "0"],
        "axis_rate_top": f"{axis_rate_max:,.0f}",
        "rate_threshold_val": rate_threshold_val,
        "rate_threshold_pct": rate_threshold_pct,
        "entropy_threshold_val": entropy_threshold_val,
        "entropy_threshold_pct": entropy_threshold_pct,
        "phases": phases,
        "classes_mix": classes_mix,
        "victims": victims,
        "sources": sources,
        "unattributed_source": unattributed_source,
        "blocks": blocks,
        "blocked_ips_total": len(blocked_ips),
        "current_rate": current_rate,
        "current_entropy": current_entropy,
        "live_rate_threshold": live_rate_threshold,
        "live_entropy_threshold": live_entropy_threshold,
        "rate_gauge_pct": f"{min(100.0, current_rate / live_rate_threshold * 100) if live_rate_threshold else 0:.2f}%",
        "entropy_gauge_pct": f"{max(0.0, min(1.0, current_entropy)) * 100:.2f}%",
        "entropy_marker_pct": f"{max(0.0, min(1.0, live_entropy_threshold)) * 100:.2f}%",
        "below_entropy_count": below_entropy,
        "below_entropy_pct": below_entropy_pct,
        "enforced_total": enforced_total,
        "blocked_share_pct": f"{blocked_share:.2f}%",
        "ratelimited_share_pct": f"{ratelimited_share:.2f}%",
    }


def _build_phases(cols, bucket_s):
    runs = []
    for c in cols:
        if c["dominant"] is None:
            runs.append(None)
            continue
        if runs and runs[-1] is not None and runs[-1]["dominant"] == c["dominant"]:
            runs[-1]["cols"].append(c)
        else:
            runs.append({"dominant": c["dominant"], "cols": [c]})
    runs = [r for r in runs if r is not None]

    if not runs:
        return []

    # Prefer showing the more severe phases even if short-lived: a two-minute
    # attack spike matters more to a reader than an hour of quiet traffic.
    # Longest run first only breaks ties within the same severity.
    def _priority(run):
        return (SEVERITY_ORDER.index(run["dominant"]), -len(run["cols"]))

    runs.sort(key=_priority)
    kept = runs[:MAX_PHASES]
    kept.sort(key=lambda r: r["cols"][0]["start"])

    phases = []
    for r in kept:
        rows = r["cols"]
        start, end = rows[0]["start"], rows[-1]["start"] + bucket_s
        total_records = sum(c["total"] for c in rows)
        peak = max(c["peak_rate"] for c in rows)
        entropies = [c["avg_entropy"] for c in rows if c["avg_entropy"] is not None]
        avg_entropy = sum(entropies) / len(entropies) if entropies else None
        phases.append({
            "time": f"{_fmt_time(start)}–{_fmt_time(end)}",
            "title": r["dominant"],
            "color": COLORS[r["dominant"]],
            "body": _phase_body(total_records, len(rows), peak, avg_entropy),
        })
    return phases


def _phase_body(total_records, n_buckets, peak, avg_entropy):
    avg_per_bucket = total_records / n_buckets if n_buckets else 0
    parts = [f"About {avg_per_bucket:.0f} records logged per window."]
    if peak > 0:
        parts.append(f"Highest single rate seen was {peak:,.1f} pps.")
    if avg_entropy is not None:
        parts.append(f"Average source spread (entropy) was {avg_entropy:.2f} bits.")
    return " ".join(parts)
