"""
ipc_receiver.py: Unix domain socket listener thread.

Receives FeatureVector windows from Stage 1, runs the ML classifier plus
the adaptive safety overrides, updates shared state, and dispatches the
4-tier block/rate-limit enforcement logic.
"""

import os
import csv
import json
import socket
import struct
import ipaddress
import logging
import grp
import pwd
import time

import joblib

import config
import state
import db
import enforcement
import alerts


def _maybe_alert_block(ip, victim_ip, rate, cfg):
    """Dispatch a block alert the first time this IP is blocked, then
    suppress re-alerts for cfg['block_duration_seconds'], tracks the
    ipset entry's own timeout so "still presumably blocked" doesn't need
    separate cooldown bookkeeping."""
    now = time.time()
    last = state.last_block_alert.get(ip, 0)
    if now - last < cfg["block_duration_seconds"]:
        return
    state.last_block_alert[ip] = now
    alerts.dispatch_alert(
        "FLOD System: IP Blocked",
        f"Blocked {ip} targeting {victim_ip} (sustained ~{rate:.1f} pps)."
    )


def apply_safety_overrides(pred_class, ewma_rate, mean_r, sigma_r, mean_h, sigma_h,
                            dominant_rate, entropy, dominant_ip_ratio, k_multiplier, cfg):
    """Deterministic, non-ML threshold checks that can force pred_class to
    Flash Crowd (1) or DDoS (2). Never skipped, including during Stage 1's
    warm-up: unlike the RandomForest and Isolation Forest, nothing here
    depends on training data, only on mean_r/sigma_r/mean_h/sigma_h, which
    are meaningful, if noisier, from a target's very first window. Skipping
    this during warm-up used to leave a target fully unenforced for its
    first 200 windows after every restart, newly added victim, or
    --clear-baseline recovery, a real, repeatedly reachable gap rather
    than a one-time startup blip.

    Returns (pred_class, extreme_dominant_rate_boundary). The second value
    is also Tier 2's own per-source block bar further down in the caller,
    same formula, same inputs; returned rather than recomputed there so
    the two can never drift apart from each other.
    """
    rate_anomaly_boundary = mean_r + k_multiplier * sigma_r
    extreme_dominant_rate_boundary = max(
        cfg["block_rate_floor_pps"], mean_r + cfg["block_sigma_multiplier"] * sigma_r
    )
    entropy_anomaly_boundary = mean_h - k_multiplier * sigma_h

    if pred_class in (0, 1) and ewma_rate > rate_anomaly_boundary:
        if dominant_rate > extreme_dominant_rate_boundary:
            return 2, extreme_dominant_rate_boundary
        elif entropy < entropy_anomaly_boundary or dominant_ip_ratio > cfg["dominant_ip_ratio_extreme_threshold"]:
            return 2, extreme_dominant_rate_boundary
        else:
            return 1, extreme_dominant_rate_boundary
    return pred_class, extreme_dominant_rate_boundary


ANOMALOUS_CSV_HEADER = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "source_port_entropy", "ttl_variance",
    "fingerprint_diversity", "timestamp", "label", "victim_ip", "if_score", "rf_verdict",
]


def _write_anomalous_row(victim_ip, if_score, rf_verdict, **feature_values):
    """Append one Anomalous window to config.ANOMALOUS_CSV_PATH for later
    review. label is left blank: nothing here knows what this traffic
    actually is, only that it looked unlike anything in training. The
    first 13 columns match training.csv's own order exactly, so a row
    can be copied straight across once a human fills in the label and
    drops the victim_ip/if_score/rf_verdict columns on the end."""
    write_header = not os.path.exists(config.ANOMALOUS_CSV_PATH)
    try:
        with open(config.ANOMALOUS_CSV_PATH, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(ANOMALOUS_CSV_HEADER)
            w.writerow([
                f"{feature_values['entropy']:.6f}", f"{feature_values['ewma_rate']:.6f}",
                f"{feature_values['mean_h']:.6f}", f"{feature_values['mean_r']:.6f}",
                f"{feature_values['sigma_h']:.6f}", f"{feature_values['sigma_r']:.6f}",
                f"{feature_values['proto_ratio']:.6f}", f"{feature_values['dominant_ip_ratio']:.6f}",
                f"{feature_values['source_port_entropy']:.6f}", f"{feature_values['ttl_variance']:.6f}",
                f"{feature_values['fingerprint_diversity']:.6f}", f"{feature_values['timestamp']:.3f}",
                "", victim_ip, f"{if_score:+.4f}", rf_verdict,
            ])
    except OSError as e:
        logging.error(f"[-] Failed to write anomalous_capture.csv row: {e}")


def _peer_uid(conn):
    """The connecting process's real UID, via SO_PEERCRED. Linux only,
    which is the only platform this project targets (systemd, ipset,
    iptables). Returns None if the kernel can't report it, rather than
    raising, so a caller can fail closed on that too."""
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        return uid
    except OSError:
        return None


def decode_ip(ip_bytes):
    try:
        ip_v6 = ipaddress.IPv6Address(ip_bytes)
        if ip_v6.ipv4_mapped:
            return str(ip_v6.ipv4_mapped)
        return str(ip_v6)
    except Exception as e:
        logging.error(f"[-] Failed to parse IP bytes: {e}")
        return "Unknown"


def run_ipc_receiver():
    # Setup ipset
    enforcement.setup_ipset()

    # Load Model
    if not os.path.exists(config.MODEL_PATH):
        logging.error(f"[-] Model not found at '{config.MODEL_PATH}'. UI will run in passive mode.")
        clf = None
    else:
        try:
            clf = joblib.load(config.MODEL_PATH)
            # n_jobs=-1 from training is pickled into the model, but
            # inference here predicts one row at a time; parallelizing a
            # single row costs more in worker setup than it saves.
            clf.n_jobs = 1
            logging.info("[+] ML Classifier loaded successfully.")
        except Exception as e:
            logging.error(f"[-] Failed to load classifier: {e}")
            clf = None

    # V7: the Isolation Forest, trained separately
    # (train_isolation_forest.py) from the RandomForest above, runs
    # alongside it every window rather than as a fallback. The RF says
    # what class a window looks like; the IF says whether it looks like
    # anything either model has seen at all, catching evasive traffic the
    # RF was never trained to recognise. Missing is not fatal, the same as
    # a missing RF model: this just means no Anomalous state gets raised.
    if not os.path.exists(config.IF_MODEL_PATH):
        logging.warning(f"[!] Isolation Forest not found at '{config.IF_MODEL_PATH}'. "
                         "Running without it: Anomalous will never be raised until one is trained.")
        if_clf = None
    else:
        try:
            if_clf = joblib.load(config.IF_MODEL_PATH)
            if_clf.n_jobs = 1
            logging.info("[+] Isolation Forest loaded successfully.")
        except Exception as e:
            logging.error(f"[-] Failed to load Isolation Forest: {e}")
            if_clf = None

    # /run is tmpfs and cleared on every boot, so this can't be assumed to
    # already exist, create it fresh each startup. If the ddos-ipc group
    # exists (install.sh creates it so the de-rooted Stage 1 service
    # account can still reach this socket), share the directory and socket
    # with that group; otherwise fall back to root-only, which is correct
    # when Stage 1 is still running as root.
    ipc_gid = None
    try:
        ipc_gid = grp.getgrnam("ddos-ipc").gr_gid
    except KeyError:
        pass

    # Defence in depth alongside the socket permission bits above: even a
    # process that is somehow able to connect (group membership broader
    # than intended, a permission bug) gets its actual UID checked against
    # who is expected to be on the other end, root, or the de-rooted
    # Stage 1 service account install.sh creates, rather than trusted
    # purely because the connection was accepted at all.
    expected_uids = {0}
    try:
        expected_uids.add(pwd.getpwnam("ddos-stage1").pw_uid)
    except KeyError:
        pass

    os.makedirs(config.RUNTIME_DIR, exist_ok=True)
    os.chmod(config.RUNTIME_DIR, 0o770 if ipc_gid is not None else 0o700)
    if ipc_gid is not None:
        try:
            os.chown(config.RUNTIME_DIR, -1, ipc_gid)
        except OSError as e:
            logging.warning(f"[!] Could not chgrp {config.RUNTIME_DIR} to ddos-ipc: {e}")

    if os.path.exists(config.SOCKET_PATH):
        try:
            os.remove(config.SOCKET_PATH)
        except OSError:
            pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(config.SOCKET_PATH)
        # Root-owned regardless; mode/group control who besides root can
        # connect. 0600 (root-only) unless the ddos-ipc group exists, in
        # which case 0660 lets the de-rooted Stage 1 service account in
        # too, either way, every other local account is still shut out.
        if ipc_gid is not None:
            os.chmod(config.SOCKET_PATH, 0o660)
            try:
                os.chown(config.SOCKET_PATH, -1, ipc_gid)
            except OSError as e:
                logging.warning(f"[!] Could not chgrp {config.SOCKET_PATH} to ddos-ipc: {e}")
        else:
            os.chmod(config.SOCKET_PATH, 0o600)
        server.listen(5)
        logging.info(f"[+] IPC socket listening on: {config.SOCKET_PATH}")
    except Exception as e:
        logging.error(f"[-] Failed to bind socket to {config.SOCKET_PATH}: {e}")
        return

    while True:
        try:
            conn, _ = server.accept()
            peer_uid = _peer_uid(conn)
            if peer_uid not in expected_uids:
                logging.warning(
                    f"[!] Rejected an IPC connection from uid={peer_uid}, "
                    f"expected one of {expected_uids}."
                )
                conn.close()
                continue
            while True:
                data = conn.recv(config.PAYLOAD_SIZE)
                if not data:
                    break
                if len(data) < config.PAYLOAD_SIZE:
                    while len(data) < config.PAYLOAD_SIZE:
                        chunk = conn.recv(config.PAYLOAD_SIZE - len(data))
                        if not chunk:
                            break
                        data += chunk
                    if len(data) < config.PAYLOAD_SIZE:
                        break

                unpacked = struct.unpack(config.FEATURE_VECTOR_FORMAT, data)
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
                # V5: -1.0 means no egress sensor is configured, which is not
                # the same as a measured 0% drop rate, kept as None so the
                # dashboard can show "unavailable" rather than "nothing was
                # dropped".
                egress_rate = unpacked[17] if unpacked[17] >= 0 else None
                drop_ratio = unpacked[18] if unpacked[18] >= 0 else None
                # V7: invariant under source address forgery, unlike entropy
                # above. See docs/detection.md for why that matters against
                # a randomized source flood.
                source_port_entropy = unpacked[19]
                ttl_variance = unpacked[20]
                fingerprint_diversity = unpacked[21]
                # V7: whether this window's mean/sigma came from Stage 1's
                # warm-up period rather than a converged baseline. Warm-up
                # windows are sent so the dashboard updates immediately, but
                # their mean/sigma-derived features (delta_rate, delta_entropy,
                # dominant_rate, and mean_r/sigma_r/mean_h/sigma_h themselves)
                # come from too few samples to mean anything: sigma_r can read
                # far below its own configured floor, something a converged
                # baseline can never produce. The classifiers were trained
                # entirely on converged-baseline data and have never seen
                # values like that, so they read "unfamiliar" as "anomalous"
                # rather than "still warming up". See docs/detection.md.
                is_warmup = unpacked[22] != 0.0
                ip_str = decode_ip(unpacked[23])
                victim_ip_str = decode_ip(unpacked[24])
                victim_ip_str = enforcement.resolve_victim_ip(victim_ip_str)

                # Calculate delta features
                delta_rate = ewma_rate - mean_r
                delta_entropy = entropy - mean_h

                # dominant_rate: estimated pps of the single busiest source in
                # this window. Computed once here, fed to the classifier as
                # an input feature (matches train.py's FEATURE_COLS order
                # exactly), and reused below by the enforcement guards instead
                # of each recomputing it independently.
                dominant_rate = ewma_rate * dominant_ip_ratio

                # 0.0.0.0 is the sentinel for a window with no attributable
                # dominant sender; whether a source was actually identified
                # gates both enforcement below and the incident log rows.
                dominant_ip_known = ip_str not in ("Unknown", "0.0.0.0", "::")

                # Load once per packet, operator-tunable thresholds for
                # everything below (see config.DEFAULT_ENFORCEMENT_CONFIG for
                # what each key means and why it's configurable, not
                # hardcoded).
                cfg = config.get_enforcement_config()

                pred_class = 0
                features_df = None
                if clf or if_clf:
                    import pandas as pd
                    features_df = pd.DataFrame([[
                        entropy, ewma_rate, mean_h, mean_r, sigma_h, sigma_r,
                        proto_ratio, dominant_ip_ratio, delta_rate, delta_entropy,
                        dominant_rate, source_port_entropy, ttl_variance,
                        fingerprint_diversity
                    ]], columns=[
                        "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
                        "proto_ratio", "dominant_ip_ratio", "delta_rate", "delta_entropy",
                        "dominant_rate", "source_port_entropy", "ttl_variance",
                        "fingerprint_diversity"
                    ])
                # The RandomForest does not run on a warm-up window: see the
                # is_warmup unpack comment above for why its mean/sigma
                # derived inputs can't be trusted by a model trained
                # entirely on converged-baseline data. pred_class stays its
                # default (0, Normal) as this model's own opinion.
                if not is_warmup and clf:
                    pred_class = int(clf.predict(features_df)[0])

                # Adaptive safety overrides. Deliberately NOT gated on
                # is_warmup, see apply_safety_overrides' own docstring.
                # extreme_dominant_rate_boundary is Tier 2's own block bar
                # further down, same value, not recomputed there.
                pred_class, extreme_dominant_rate_boundary = apply_safety_overrides(
                    pred_class, ewma_rate, mean_r, sigma_r, mean_h, sigma_h,
                    dominant_rate, entropy, dominant_ip_ratio, k_multiplier, cfg,
                )

                class_names = {0: "Normal", 1: "Flash Crowd", 2: "DDoS"}
                pred_name = class_names.get(pred_class, "Normal")
                rf_verdict_name = pred_name

                # V7: the Isolation Forest's opinion, independent of the
                # RandomForest's class. Only checked when the RF already
                # waved the window through (Normal or Flash Crowd): a DDoS
                # verdict is already escalated, so the IF's opinion would be
                # redundant for enforcement purposes, though it still rides
                # along in features_df/pred_class untouched, both continue
                # to drive every enforcement branch below exactly as before.
                # Anomalous is reporting only in this pass, matching this
                # project's enforcement philosophy of a deterministic,
                # auditable, operator tunable rule rather than an action
                # baked into a classifier: see docs/detection.md.
                is_anomalous = False
                if not is_warmup and if_clf and pred_class in (0, 1):
                    # -1 = outlier, 1 = inlier, IsolationForest's own convention.
                    is_anomalous = int(if_clf.predict(features_df)[0]) == -1
                    if is_anomalous:
                        pred_name = "Anomalous"
                        if_score = if_clf.decision_function(features_df)[0]
                        logging.debug(
                            f"[V7] Anomalous flagged for victim={victim_ip_str}: "
                            f"score={if_score:+.4f} "
                            f"features={features_df.iloc[0].to_dict()}"
                        )
                        _write_anomalous_row(
                            victim_ip_str, if_score, rf_verdict_name,
                            entropy=entropy, ewma_rate=ewma_rate, mean_h=mean_h, mean_r=mean_r,
                            sigma_h=sigma_h, sigma_r=sigma_r, proto_ratio=proto_ratio,
                            dominant_ip_ratio=dominant_ip_ratio, source_port_entropy=source_port_entropy,
                            ttl_variance=ttl_variance, fingerprint_diversity=fingerprint_diversity,
                            timestamp=timestamp,
                        )

                # Alert on DDoS classification transitions only (not every
                # window a victim stays classified DDoS, and not on
                # Normal<->Flash Crowd changes, which aren't malicious).
                prev_class_name = state.last_classification_by_target.get(victim_ip_str)
                if pred_name == "DDoS" and prev_class_name != "DDoS":
                    alerts.dispatch_alert(
                        "FLOD System: DDoS Detected",
                        f"Victim {victim_ip_str} classified DDoS, rate={ewma_rate:.1f}pps, entropy={entropy:.3f}, dominant_ip_ratio={dominant_ip_ratio:.1%}."
                    )
                elif pred_name != "DDoS" and prev_class_name == "DDoS":
                    alerts.dispatch_alert(
                        "FLOD System: DDoS Resolved",
                        f"Victim {victim_ip_str} classification returned to {pred_name}, rate={ewma_rate:.1f}pps, entropy={entropy:.3f}."
                    )
                state.last_classification_by_target[victim_ip_str] = pred_name

                # Update live stats
                state.last_metrics = {
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
                    "egress_rate": egress_rate,
                    "drop_ratio": drop_ratio,
                    "proto_tcp": proto_tcp,
                    "proto_udp": proto_udp,
                    "proto_icmp": proto_icmp,
                    "proto_sctp": proto_sctp,
                    "proto_gre": proto_gre,
                    "proto_esp": proto_esp,
                    "source_port_entropy": source_port_entropy,
                    "ttl_variance": ttl_variance,
                    "fingerprint_diversity": fingerprint_diversity
                }
                state.last_metrics_by_target[victim_ip_str] = state.last_metrics.copy()

                # Save history
                db.log_metrics_history(timestamp, ewma_rate, entropy, mean_h, mean_r, sigma_h, sigma_r, k_multiplier, victim_ip_str)

                # Track consecutive class-2 windows per victim for block
                # hysteresis (rate-limiting is NOT gated by this, only the
                # hard-block tiers below are).
                if pred_class == 2:
                    state.consecutive_ddos_windows[victim_ip_str] = state.consecutive_ddos_windows.get(victim_ip_str, 0) + 1
                else:
                    state.consecutive_ddos_windows[victim_ip_str] = 0

                # Trigger block / rate-limit
                if pred_class == 2:
                    if ip_str not in ("Unknown", "0.0.0.0", "::"):
                        dominant_rate_threshold = mean_r + k_multiplier * sigma_r
                        # Per-source block bar: sustained rate no legitimate
                        # client/flash-crowd participant could produce.
                        # (Same formula/values as extreme_dominant_rate_boundary
                        # above, reuse it directly to guarantee they can't drift
                        # apart from each other.)
                        block_threshold = extreme_dominant_rate_boundary
                        # Softer bar for the rate-limit tier (unchanged from before).
                        flow_threshold = max(cfg["ratelimit_rate_floor_pps"], mean_r + sigma_r)
                        block_ready = state.consecutive_ddos_windows.get(victim_ip_str, 0) >= cfg["block_hysteresis_windows"]

                        # Load and aggregate active flows BY SOURCE IP once, up
                        # front, every tier below reads from this same
                        # aggregation instead of re-parsing the flows file
                        # repeatedly. Aggregating by IP (summed across all of
                        # that source's flow tuples) rather than per-flow means
                        # an attacker spreading across multiple dst ports can't
                        # dodge the per-source thresholds below by fragmenting
                        # its traffic into several smaller-looking flows.
                        per_source_rate = {}
                        if os.path.exists(config.FLOWS_PATH):
                            try:
                                with open(config.FLOWS_PATH, "r") as f:
                                    flow_data = json.load(f)
                                for flow in flow_data.get("active_ips", []):
                                    f_ip = flow.get("ip")
                                    if f_ip and f_ip not in ("Unknown", "0.0.0.0", "::"):
                                        per_source_rate[f_ip] = per_source_rate.get(f_ip, 0.0) + flow.get("rate", 0.0)
                            except Exception as ce:
                                logging.error(f"[-] Failed to parse active flows: {ce}")

                        acted_on = set()

                        # Tier 1, dominant-source fast path: one source
                        # clearly drives the attack (both concentrated AND
                        # fast). Gated by hysteresis like every block action.
                        if block_ready and dominant_ip_ratio >= cfg["dominant_ip_ratio_block_threshold"] and dominant_rate >= dominant_rate_threshold:
                            enforcement.block_ip(ip_str, victim_ip=victim_ip_str, duration=cfg["block_duration_seconds"], src_rate=dominant_rate, entropy=entropy)
                            _maybe_alert_block(ip_str, victim_ip_str, dominant_rate, cfg)
                            acted_on.add(ip_str)

                        # Tier 2, independent per-source-rate escalation.
                        # NOT gated behind dominant_ip_ratio: a source
                        # sustaining an impossible rate gets blocked even if
                        # it's one of many sources and the AGGREGATE looks
                        # distributed. This is what closes the evasion gap,
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
                                    enforcement.block_ip(f_ip, victim_ip=victim_ip_str, duration=cfg["block_duration_seconds"], src_rate=agg_rate, entropy=entropy)
                                    _maybe_alert_block(f_ip, victim_ip_str, agg_rate, cfg)
                                    acted_on.add(f_ip)

                        if not block_ready and per_source_rate:
                            logging.info(
                                f"[i] Class-2 window {state.consecutive_ddos_windows.get(victim_ip_str, 0)}/"
                                f"{cfg['block_hysteresis_windows']} for victim {victim_ip_str}, "
                                f"block actions held pending hysteresis, rate-limiting only this window."
                            )

                        # Tier 3, softer rate-limit for sources elevated but
                        # below the hard-block bar (the original Cluster Block
                        # Mode). NOT gated by hysteresis, this is the
                        # intentionally-immediate, reversible tier.
                        for f_ip, agg_rate in per_source_rate.items():
                            if f_ip in acted_on:
                                continue
                            if agg_rate >= flow_threshold:
                                enforcement.ratelimit_ip(f_ip, victim_ip=victim_ip_str, duration=cfg["ratelimit_duration_seconds"], src_rate=agg_rate, entropy=entropy)
                                acted_on.add(f_ip)

                        # Tier 4, aggregate cap fallback. Class-2 verdict but
                        # nothing above matched any single source individually
                        # (fully distributed at sub-threshold per-source
                        # rates). Previously this meant doing NOTHING at all
                        # despite a confirmed DDoS classification, rate-limit
                        # every currently-active flow to the victim as a last
                        # resort so a class-2 verdict never silently goes
                        # unhandled.
                        if not acted_on and per_source_rate:
                            logging.warning(
                                "[!] Aggregate cap fallback: class-2 verdict but no individual "
                                "source was attributable, rate-limiting all active flows."
                            )
                            alerts.dispatch_alert(
                                "FLOD System: Aggregate Fallback Triggered",
                                f"Victim {victim_ip_str}: DDoS verdict with no individually-attributable source, "
                                f"rate-limited {len(per_source_rate)} active flows as a fallback."
                            )
                            for f_ip, f_rate in per_source_rate.items():
                                enforcement.ratelimit_ip(f_ip, victim_ip=victim_ip_str, duration=cfg["ratelimit_duration_seconds"], src_rate=f_rate, entropy=entropy)
                        elif not per_source_rate and not acted_on:
                            logging.warning("[!] Class-2 verdict but no active flow data available to act on.")
                elif pred_class == 1:
                    # Log flash crowd (or, if the Isolation Forest flagged
                    # it, Anomalous) incident. The row names the dominant
                    # source, so a window with none isn't a source-attributed
                    # event to log; the window itself is already captured,
                    # source-independent, in metrics_history above.
                    if dominant_ip_known:
                        db.log_incident(timestamp, ip_str, pred_name, victim_ip_str,
                                        dominant_rate, entropy)
                    # If the dominant IP rate is highly elevated during a flash crowd, apply rate-limit (not block)
                    # (dominant_rate computed once above, alongside the classifier features.)
                    dominant_rate_threshold = mean_r + k_multiplier * sigma_r
                    if dominant_ip_known and dominant_ip_ratio >= cfg["dominant_ip_ratio_block_threshold"] and dominant_rate >= dominant_rate_threshold:
                        logging.warning(
                            f"[!] Legitimate flash crowd dominant IP {ip_str} rate highly elevated "
                            f"({dominant_rate:.2f} pps). Applying rate-limit ({cfg['ratelimit_hashlimit_pps']}pps cap) as precaution."
                        )
                        # Recorded as a flash crowd cap, not as a DDoS action:
                        # the verdict here was class 1, and the dashboard
                        # separates confirmed attack sources from precautions.
                        enforcement.ratelimit_ip(
                            ip_str,
                            victim_ip=victim_ip_str,
                            duration=cfg["ratelimit_duration_seconds"],
                            src_rate=dominant_rate,
                            classification=enforcement.CLASS_RATELIMITED_FLASH,
                            entropy=entropy,
                        )
                elif pred_class == 0:
                    # Log normal (or Anomalous) traffic. Same reasoning as
                    # Flash Crowd above: no dominant source means nothing
                    # source-attributed to log, not an unnamed one.
                    if dominant_ip_known:
                        db.log_incident(timestamp, ip_str, pred_name, victim_ip_str,
                                        dominant_rate, entropy)

            conn.close()
        except Exception as e:
            logging.error(f"[-] Socket read loop error: {e}")
            time.sleep(1)
