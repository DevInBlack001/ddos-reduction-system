// =============================================================================
// analysis.rs — Stage 1: Three-Layer Analysis Thread
// =============================================================================
//
// PURPOSE
// -------
// This module owns the *analysis thread* — the brain of Stage 1. It receives
// `PacketMeta` records from the capture thread via a crossbeam channel and
// runs the complete three-layer pipeline:
//
//   Layer 1 (per packet)
//   ---------------------
//   • EWMA rate: update exponential smoothing with the new inter-arrival gap.
//   • Entropy accumulator: record the source IP in the current window's HashMap.
//
//   Layer 2 (per 50th packet — window close)
//   -----------------------------------------
//   • Shannon entropy: compute the diversity scalar `h` from the IP HashMap,
//     then clear the HashMap and reset the packet counter.
//   • EWMA snapshot: read the current EWMA value as the rate scalar `r`.
//     (The EWMA is NOT reset — it carries memory across windows by design.)
//
//   Layer 3 (per window, immediately after Layer 2)
//   -------------------------------------------------
//   • Feed `r` into the EWMA Welford accumulator (Welford_rate).
//   • Feed `h` into the Entropy Welford accumulator (Welford_entropy).
//   • Evaluate thresholds:
//       rate anomaly    → `r > Welford_rate.mean + k·σ_rate`
//       entropy anomaly → `h < Welford_entropy.mean − k·σ_entropy`
//   • If either fires AND the accumulators are past warm-up:
//       build a `FeatureVector` and send it to Stage 2 via `IpcSocket`.
//
// ANOMALY THRESHOLD MULTIPLIER (k)
// ----------------------------------
// The specification uses k = 2.0 (two standard deviations) as the default.
// This constant is exposed so you can tune it without recompiling — pass it
// through `AnalysisConfig`. A higher k reduces false positives at the cost
// of slower detection; a lower k is more sensitive but may fire on flash crowds
// before Stage 2 can distinguish them.
//
// WARM-UP PERIOD
// ---------------
// Welford's mean and variance are meaningless until enough windows have been
// seen to build a real baseline (see `welford::WARMUP_WINDOWS`). During warm-up
// Layer 3 will *not* fire even if a threshold is technically breached. The
// gateway logs a "warm-up" message to console so you know when it goes live.
//
// DOMINANT IP RATIO
// ------------------
// On every window close the analysis thread also computes the fraction of
// packets belonging to the single most-frequent source IP. This is included
// in the `FeatureVector` sent to Stage 2 as an additional feature — useful for
// the Random Forest classifier and for operator-level logging.
// =============================================================================

use crate::{
    capture::{Direction, PacketMeta, Protocol},
    entropy::MIN_PACKETS_FOR_ENTROPY,
    ipc::{FeatureVector, IpcSocket, FLAG_ENTROPY_ANOMALY, FLAG_RATE_ANOMALY},
    persistence::{self, PersistedState},
    state::{AnalysisConfig, TargetState},
};
use crossbeam_channel::{Receiver, RecvTimeoutError};
use log::{info, warn};
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH, Instant};

/// How long to wait for a packet before ticking the window-close check anyway.
///
/// Without this the analysis loop only advances when a packet arrives, so a
/// lull means no window ever closes: the EWMA stops decaying, the cooldown
/// counter stops decrementing, and Stage 2 stops receiving telemetry. That is
/// worst immediately after a successful block, when traffic to the victim
/// drops to near zero by design.
const WINDOW_TICK: Duration = Duration::from_millis(250);

/// Cap on distinct flows tracked between flushes. The key is
/// attacker-controlled, so a randomized-source flood would otherwise
/// allocate one entry per packet. Sized well above normal traffic; the
/// whole map is still reported, so the dashboard shows every tracked flow.
const MAX_TRACKED_FLOWS: usize = 8192;

/// How often a target reports even when nothing is wrong.
///
/// The dashboard's per target panels read whatever this last delivered, so
/// this is how stale a quiet target's figures can get. It used to be 10
/// seconds, which combined with the dashboard's own polling to leave a quiet
/// target looking frozen for up to twenty.
const HEARTBEAT_SECS: f64 = 2.0;

/// Whether a window's entropy counts as an anomaly.
///
/// Requires a minimum sample size: `compute_normalized_entropy` returns 0.0
/// for an empty window, which would otherwise look identical to a
/// maximally concentrated single-source flood every time traffic goes quiet.
fn entropy_anomaly_fires(h: f64, boundary: f64, packet_count: usize) -> bool {
    packet_count >= MIN_PACKETS_FOR_ENTROPY && h < boundary
}

// -----------------------------------------------------------------------------
// run_analysis_thread — the analysis thread entry point
// -----------------------------------------------------------------------------

/// Receive `PacketMeta` records from the capture thread and run the three-layer
/// pipeline indefinitely.
///
/// Intended to be called from within `std::thread::spawn()`. Returns when the
/// `rx` channel closes (capture thread exited or an unrecoverable error occurred).
///
/// # Arguments
/// * `cfg` — analysis configuration (k, alpha, socket path).
/// * `rx`  — the receiving end of the crossbeam channel from the capture thread.
pub fn run_analysis_thread(cfg: AnalysisConfig, rx: Receiver<PacketMeta>) {
    info!(
        "Analysis: thread started | targets={:?} | k={} | α={}",
        cfg.victim_targets, cfg.k, cfg.ewma_alpha
    );

    // Defensively ensure /run/ddos_stage1 exists -- this thread writes
    // active_flows.json/.tmp and reads train_label from it, and /run is
    // tmpfs (cleared every boot), so we can't assume install.sh or Stage
    // 2 has already created it this session. Idempotent: if it already
    // exists (usually created root-owned by Stage 2's socket bind path),
    // this only touches the mode bits, not ownership.
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::create_dir_all("/run/ddos_stage1").is_ok() {
            let _ = std::fs::set_permissions("/run/ddos_stage1", std::fs::Permissions::from_mode(0o770));
        }
    }

    // -------------------------------------------------------------------------
    // Open the CSV training file if --train-csv was passed.
    // -------------------------------------------------------------------------
    let mut csv_writer: Option<std::fs::File> = if let Some(ref path) = cfg.train_csv {
        let file_exists = std::path::Path::new(path).exists();
        match std::fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(mut f) => {
                if !file_exists {
                    // Write CSV header only if the file is new.
                    let _ = writeln!(
                        f,
                        "entropy,ewma_rate,mean_h,mean_r,sigma_h,sigma_r,\
                         proto_ratio,dominant_ip_ratio,timestamp,label"
                    );
                }
                info!("Analysis: training mode ON — writing CSV to '{}' with label={}", path, cfg.train_label);
                Some(f)
            }
            Err(e) => {
                warn!("Analysis: failed to open train-csv '{}': {e} — training disabled", path);
                None
            }
        }
    } else {
        None
    };

    // Keep track of target states per destination IP
    let mut targets_map: HashMap<IpAddr, TargetState> = HashMap::new();

    // -------------------------------------------------------------------------
    // V4: load any persisted baseline once at thread start. `None` (missing,
    // corrupt, or past its TTL -- see persistence.rs) is treated identically
    // to "no prior state": every target simply gets a fresh warm-up, same as
    // before V4 existed.
    // -------------------------------------------------------------------------
    let persisted_state = persistence::load(&cfg.baseline_path, cfg.baseline_ttl_secs);
    let mut last_baseline_save = Instant::now();

    // IPC socket to Stage 2 (Python). Connected lazily on first anomaly.
    let mut ipc = IpcSocket::with_path(&cfg.socket_path);

    // Active IP and port flow counters for Web UI telemetry. Keyed by
    // (src_ip, dst_ip, dst_port, proto) -- dst_ip is what lets the dashboard's
    // network map / traffic tab show device-to-device communication instead
    // of just "this source is talking to someone."
    let mut flow_counts: HashMap<(IpAddr, IpAddr, u16, u8), u32> = HashMap::new();
    let mut last_flow_write = Instant::now();

    // Live label state for training
    let mut current_train_label = cfg.train_label;
    let mut last_label_check = Instant::now();

    // -------------------------------------------------------------------------
    // Main loop. Driven by arriving packets, but also ticks on a timeout so
    // window closes keep happening when no traffic is arriving.
    // -------------------------------------------------------------------------
    loop {
        // Which victims to evaluate for a window close this iteration. A
        // packet implicates only its own destination; a timeout tick has to
        // consider every victim being tracked, since any of them could be
        // sitting on an open window with no traffic to close it.
        let victims_to_check: Vec<IpAddr> = match rx.recv_timeout(WINDOW_TICK) {
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => targets_map.keys().copied().collect(),
            Ok(meta) => {
                // Track specific flow for web telemetry
                let proto_num = match meta.protocol {
                    Protocol::Tcp => 6,
                    Protocol::Udp => 17,
                    Protocol::Icmp => 1,
                    Protocol::Sctp => 132,
                    Protocol::Gre => 47,
                    Protocol::Esp => 50,
                    Protocol::Other => 0,
                };
                // Flow telemetry is ingress-only. Counting the egress copy of the
                // same conversation would double every flow's rate.
                if meta.direction == Direction::Ingress {
                    let key = (meta.src_ip, meta.dst_ip, meta.dst_port, proto_num);
                    let at_capacity = flow_counts.len() >= MAX_TRACKED_FLOWS;
                    match flow_counts.get_mut(&key) {
                        Some(count) => *count += 1,
                        None if !at_capacity => {
                            flow_counts.insert(key, 1);
                        }
                        // At capacity. Detection is unaffected; entropy and
                        // the Welford baselines are fed separately below.
                        None => {}
                    }
                }

                // Check if destination IP is one of our victim targets
                let is_target = match &cfg.victim_targets {
                    Some(targets) => targets.contains(&meta.dst_ip),
                    None => true, // In dev/test mode without a BPF filter, track all up to limits
                };

                if !is_target {
                    continue;
                }

                // Initialize state for destination IP if not already present
                if !targets_map.contains_key(&meta.dst_ip) {
                    if cfg.victim_targets.is_none() && targets_map.len() >= 100 {
                        // Prevent memory leak by capping dynamic tracking list size
                        continue;
                    }
                    let restored = persistence::lookup(&persisted_state, &meta.dst_ip);
                    if let Some(ref r) = restored {
                        info!(
                            "Analysis [victim={}]: restored baseline from persisted state (rate n={}, entropy n={}/{}).",
                            meta.dst_ip, r.rate_n, r.entropy_n, crate::welford::WARMUP_WINDOWS
                        );
                    }
                    targets_map.insert(meta.dst_ip, TargetState::new(cfg.ewma_alpha, restored.as_ref()));
                }

                let target_state = targets_map.get_mut(&meta.dst_ip).unwrap();

                // V5: egress packets only answer "how much got through". They never
                // feed entropy, the IP histogram, the Welford baselines or the
                // window-close decision -- detection stays driven purely by what
                // arrived at the gateway, so mitigation can never influence the
                // statistics used to decide on mitigation.
                if meta.direction == Direction::Egress {
                    target_state.egress_packet_count += 1;
                    continue;
                }

                // =====================================================================
                // LAYER 1 — Per-Packet Updates
                // =====================================================================
                target_state.entropy.add_packet(meta.src_ip);
                *target_state.ip_counts.entry(meta.src_ip).or_insert(0) += 1;
                target_state.window_packet_count += 1;

                // Increment the Layer 4 protocol counter for the current window.
                match meta.protocol {
                    Protocol::Tcp  => target_state.tcp_count  += 1,
                    Protocol::Udp  => target_state.udp_count  += 1,
                    Protocol::Icmp => target_state.icmp_count += 1,
                    Protocol::Sctp => target_state.sctp_count += 1,
                    Protocol::Gre  => target_state.gre_count  += 1,
                    Protocol::Esp  => target_state.esp_count  += 1,
                    Protocol::Other => {}
                }

                vec![meta.dst_ip]
            }
        };

        for victim_ip in victims_to_check {
            let target_state = match targets_map.get_mut(&victim_ip) {
                Some(t) => t,
                None => continue,
            };

            // =====================================================================
            // LAYER 2 — Hybrid Window Close
            // =====================================================================
            // Close condition (OR-boundary):
            //   Condition A: ≥0.5s elapsed AND ≥20 packets accumulated
            //   Condition B: OR ≥1.0s elapsed (hard cap — ensures telemetry even in lulls)
            //
            // This prevents the Session-3 artifact (700 windows/sec under floods)
            // while guaranteeing ≥1 row/sec during low-traffic transitions.
            let now_instant = Instant::now();
            let window_elapsed = now_instant.duration_since(target_state.last_window_close).as_secs_f64();
            let packet_count = target_state.entropy.packet_count();

            let should_close = (window_elapsed >= 0.5 && packet_count >= MIN_PACKETS_FOR_ENTROPY)
                            || (window_elapsed >= 1.0);

            if !should_close {
                continue;
            }

            target_state.window_id += 1;
            target_state.last_window_close = now_instant;

            // Rate = actual accumulated packets / measured wall-clock elapsed time.
            // NOT a hardcoded WINDOW_SIZE — uses the real packet count and real duration.
            let window_rate = if window_elapsed > 0.0 {
                packet_count as f64 / window_elapsed
            } else {
                0.0
            };

            // V5: what actually reached the victim this window, and the share of
            // arriving traffic that never made it. Both are -1.0 when no egress
            // sensor is configured, so Stage 2 can tell "unknown" apart from a
            // real 0% drop rate. The ratio is clamped because the two sides are
            // measured independently -- a packet can cross the egress boundary
            // just after the ingress window closed, which would otherwise
            // produce a small negative drop.
            let (egress_rate, drop_ratio) = if cfg.egress_enabled {
                let e_rate = if window_elapsed > 0.0 {
                    target_state.egress_packet_count as f64 / window_elapsed
                } else {
                    0.0
                };
                let ratio = if window_rate > 0.0 {
                    (1.0 - (e_rate / window_rate)).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                (e_rate, ratio)
            } else {
                (-1.0, -1.0)
            };
            target_state.egress_packet_count = 0;


            // Asymmetric decay: 
            // 1. Cliff-drop decay: If we detect a precipitous drop in raw rate (<10% of EWMA)
            //    AND we are not in active cooldown (cooldown_counter == 0), use alpha = 0.8
            //    to instantly flush the rate history (e.g. after a firewall block).
            // 2. Otherwise, if the raw rate is decreasing or we are in a cooldown recovery window,
            //    use a moderately fast alpha (0.5).
            // 3. Otherwise, use the standard configured alpha to avoid reacting to single transient spikes.
            let active_alpha = if window_rate < 0.1 * target_state.ewma.snapshot() && target_state.cooldown_counter == 0 {
                0.8f64.max(cfg.ewma_alpha)
            } else if window_rate < target_state.ewma.snapshot() || target_state.cooldown_counter > 0 {
                0.5f64.max(cfg.ewma_alpha)
            } else {
                cfg.ewma_alpha
            };
            target_state.ewma.update_rate_with_alpha(window_rate, active_alpha);

            // Compute Normalized Shannon Entropy scalar h from the current window's
            // IP distribution.  Returns [0.0, 1.0] — decoupled from window size.
            // This call clears the internal HashMap and resets the packet counter.
            let h = target_state.entropy.compute_and_reset();

            // Read the current EWMA rate as a snapshot scalar r.
            // The EWMA itself is NOT reset — it retains cross-window memory.
            let r = target_state.ewma.snapshot();

            // Compute the dominant-IP ratio: fraction of packets from the busiest IP.
            let (dominant_ip, dominant_count) = target_state.ip_counts.iter()
                .map(|(ip, count)| (*ip, *count))
                .max_by_key(|(_, count)| *count)
                .unwrap_or((std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0));
            let dominant_ip_ratio = if packet_count > 0 {
                dominant_count as f64 / packet_count as f64
            } else {
                0.0
            };

            // Compute proto_ratio: fraction of window packets that were TCP.
            // Range [0.0, 1.0] — a UDP/ICMP flood will push this toward 0.0.
            let total_tracked = (target_state.tcp_count + target_state.udp_count + target_state.icmp_count) as f64;
            let proto_ratio = if total_tracked > 0.0 {
                target_state.tcp_count as f64 / total_tracked
            } else {
                0.0
            };

            let total_packets = target_state.window_packet_count.max(1) as f64;
            let proto_tcp = target_state.tcp_count as f64 / total_packets;
            let proto_udp = target_state.udp_count as f64 / total_packets;
            let proto_icmp = target_state.icmp_count as f64 / total_packets;
            let proto_sctp = target_state.sctp_count as f64 / total_packets;
            let proto_gre = target_state.gre_count as f64 / total_packets;
            let proto_esp = target_state.esp_count as f64 / total_packets;

            // Wall-clock timestamp of this window close (seconds since UNIX epoch).
            // Used by Stage 2 for time-based analysis and logging.
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();

            // Write active flows periodically to JSON for dashboard (every 10s)
            if now_instant.duration_since(last_flow_write).as_secs_f64() >= 10.0 {
                write_active_flows(&flow_counts, timestamp);
                flow_counts.clear();
                last_flow_write = now_instant;
            }

            // Live label check (every 1s). Reads from /run/ddos_stage1, not
            // /tmp -- /tmp is world-writable, which would let any local
            // account silently flip the label written into the training CSV
            // mid-capture and poison the dataset.
            if now_instant.duration_since(last_label_check).as_secs_f64() >= 1.0 {
                if let Ok(content) = std::fs::read_to_string("/run/ddos_stage1/train_label") {
                    if let Ok(parsed) = content.trim().parse::<u8>() {
                        if parsed != current_train_label {
                            info!("Analysis: Live label switch triggered via /run/ddos_stage1/train_label. Changed from {} to {}", current_train_label, parsed);
                            current_train_label = parsed;
                        }
                    }
                }
                last_label_check = now_instant;
            }

            // Reset all per-window accumulators for the next window.
            target_state.ip_counts.clear();
            target_state.window_packet_count = 0;
            target_state.tcp_count  = 0;
            target_state.udp_count  = 0;
            target_state.icmp_count = 0;
            target_state.sctp_count = 0;
            target_state.gre_count  = 0;
            target_state.esp_count  = 0;

            // =====================================================================
            // LAYER 3 — Anomaly Evaluation and Welford Update
            // =====================================================================

            // Do not evaluate thresholds during the warm-up period — the Welford
            // mean and variance are too noisy on a small sample to be trustworthy.
            if !target_state.welford_rate.is_warm() || !target_state.welford_entropy.is_warm() {
                // During warm-up, always update the Welford trackers.
                target_state.welford_rate.update(r);
                target_state.welford_entropy.update(h);

                info!(
                    "Analysis [victim={}]: warm-up window {}/{} | r={r:.1} pps | h={h:.3} bits",
                    victim_ip, target_state.welford_rate.n, crate::welford::WARMUP_WINDOWS
                );

                // Send warmup telemetry updates so that the dashboard updates immediately!
                let fv = FeatureVector {
                    entropy:     h,
                    ewma_rate:   r,
                    mean_h:      target_state.welford_entropy.mean,
                    mean_r:      target_state.welford_rate.mean,
                    sigma_h:     target_state.welford_entropy.std_dev(),
                    sigma_r:     target_state.welford_rate.std_dev(),
                    proto_ratio,
                    dominant_ip_ratio,
                    timestamp,
                    proto_tcp,
                    proto_udp,
                    proto_icmp,
                    proto_sctp,
                    proto_gre,
                    proto_esp,
                    k_multiplier: cfg.k, // no cooldown/entropy scaling applies during warm-up
                    cooldown_counter: target_state.cooldown_counter as f64,
                    egress_rate,
                    drop_ratio,
                    dominant_ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), // No dominant IP during warmup
                    victim_ip:   victim_ip,
                };
                if !ipc.send(&fv) {
                    warn!("Analysis [victim={}]: IPC send failed during warm-up; Stage 2 may be offline", victim_ip);
                }

                continue;
            }

            if !target_state.warmup_completed_logged {
                info!("Analysis [victim={}]: warm-up complete! Active monitoring started.", victim_ip);
                if cfg.train_csv.is_some() {
                    info!("Analysis [victim={}]: training mode active — now appending rows to CSV file.", victim_ip);
                }
                target_state.warmup_completed_logged = true;
            }

            // Get raw standard deviations
            let raw_sigma_r = target_state.welford_rate.std_dev();
            let raw_sigma_h = target_state.welford_entropy.std_dev();

            // 1. Sigma Ceiling & Floor: Cap the standard deviation to prevent the boundaries from drifting too wide,
            // but also enforce a floor to prevent zero-baseline lockout.
            // Cap rate standard deviation at 10000.0 pps or 20% of the mean (whichever is larger), floor at 50.0.
            let ceiling_r = (0.2 * target_state.welford_rate.mean).max(10000.0);
            let sigma_r = raw_sigma_r.max(50.0).min(ceiling_r);

            // Cap entropy standard deviation at 0.15 (normalized scale), floor at 0.02.
            // (Entropy is now normalized [0, 1], so these are proportionally smaller
            // than the raw-entropy-era values of 0.5 ceiling / 0.05 floor.)
            let sigma_h = raw_sigma_h.max(0.02).min(0.15);

            // 2. High-Sensitivity Cooldown Mode & Entropy-Guided Scaling:
            // - If we are within the cooldown recovery window, reduce the baseline multiplier to increase sensitivity.
            // - Scale the rate multiplier up if the entropy is high (indicating high diversity/flash crowd)
            //   to avoid false rate alarms.
            let base_k = if target_state.cooldown_counter > 0 {
                (cfg.k * 0.5).max(1.0)
            } else {
                cfg.k
            };

            // Dynamic k-Scaling: Scale k relative to the running mean of entropy (mean_h)
            // instead of a hardcoded 4.0 divisor. Use 4.0 as a fallback if mean_h is 0.0 (warmup).
            // Also enforce an Emergency Volume Cap: if raw rate exceeds 10 standard deviations above the mean,
            // override entropy scaling to prevent high-entropy botnet floods from evading detection.
            let mean_h = target_state.welford_entropy.mean;
            let rate_k = if r > (target_state.welford_rate.mean + 10.0 * sigma_r) {
                base_k
            } else {
                let divisor = if mean_h > 0.0 { mean_h } else { 0.8 };
                base_k * (h / divisor).max(1.0)
            };
            let entropy_k = base_k;

            // Evaluate the two anomaly thresholds.
            let rate_boundary    = target_state.welford_rate.mean + rate_k * sigma_r;
            let entropy_boundary = target_state.welford_entropy.mean - entropy_k * sigma_h;

            // Build anomaly flags bitmask.
            let mut anomaly_flags: u8 = 0;
            if r > rate_boundary {
                anomaly_flags |= FLAG_RATE_ANOMALY;
            }
            if entropy_anomaly_fires(h, entropy_boundary, packet_count) {
                anomaly_flags |= FLAG_ENTROPY_ANOMALY;
            }

            // Determine if this window breached the original configuration-level threshold (real anomaly).
            // This prevents the system from getting trapped in an infinite cooldown loop due to minor
            // normal fluctuations breaching the tighter active_k.
            let real_rate_k = if r > (target_state.welford_rate.mean + 10.0 * sigma_r) {
                cfg.k
            } else {
                let divisor = if mean_h > 0.0 { mean_h } else { 0.8 };
                cfg.k * (h / divisor).max(1.0)
            };
            let real_rate_boundary = target_state.welford_rate.mean + real_rate_k * sigma_r;
            let real_entropy_boundary = target_state.welford_entropy.mean - cfg.k * sigma_h;
            let is_real_anomaly = r > real_rate_boundary || h < real_entropy_boundary;

            // 3. Conditional Updates: Feed scalars into Welford accumulators ONLY if the window is clean
            // and we are not in cooldown. This keeps the baseline stable and prevents statistical explosion.
            // Captured as a named flag (not just inlined) because V4's baseline
            // persistence reuses this EXACT condition below to decide whether
            // this window is eligible to be snapshotted to disk -- a save must
            // never capture mid-attack state, see persistence.rs's module docs.
            let is_clean_window = anomaly_flags == 0 && target_state.cooldown_counter == 0;
            if is_clean_window {
                // Outlier Rejection: Reject updates if the sample is > 5 standard deviations away.
                // Baseline Capping: Impose a hard ceiling of 10000.0 pps on the Welford mean rate.
                let is_rate_outlier = sigma_r > 0.0 && (r - target_state.welford_rate.mean).abs() > 5.0 * sigma_r;
                if !is_rate_outlier && target_state.welford_rate.mean < 10000.0 {
                    target_state.welford_rate.update(r);
                }

                let is_entropy_outlier = sigma_h > 0.0 && (h - target_state.welford_entropy.mean).abs() > 5.0 * sigma_h;
                if !is_entropy_outlier {
                    target_state.welford_entropy.update(h);
                }

                // Peacetime Reference (Long-Term Drift Detection):
                // Update peacetime references with alpha = 0.001
                let rate_ref = target_state.peacetime_rate_ref.get_or_insert(r);
                *rate_ref = 0.001 * r + 0.999 * (*rate_ref);

                let entropy_ref = target_state.peacetime_entropy_ref.get_or_insert(h);
                *entropy_ref = 0.001 * h + 0.999 * (*entropy_ref);
            
                // Baseline Poisoning Check:
                // Revert running mean if it drifts > 50% from peacetime reference.
                if (*rate_ref) > 0.0 && (target_state.welford_rate.mean - *rate_ref).abs() / (*rate_ref) > 0.50 {
                    warn!(
                        "[!!!] Baseline Poisoning Detected for victim {}! Welford mean rate ({:.2}) deviated >50% from peacetime reference ({:.2}). Reverting mean.",
                        victim_ip, target_state.welford_rate.mean, *rate_ref
                    );
                    target_state.welford_rate.mean = *rate_ref;
                }
            }

            // Manage cooldown counter: if a real anomaly is detected, set to 10. Otherwise decrement.
            if is_real_anomaly {
                target_state.cooldown_counter = 10;
            } else if target_state.cooldown_counter > 0 {
                target_state.cooldown_counter -= 1;
            }

            // Log the current window summary at debug level.
            log::debug!(
                "Window #{}[victim={}]: r={r:.2} pps | h={h:.4} bits | \
                 μ_r={:.2} σ_r={:.2} (active={:.2}) | μ_h={:.4} σ_h={:.4} (active={:.4}) | cooldown={}",
                target_state.window_id, victim_ip,
                target_state.welford_rate.mean, raw_sigma_r, sigma_r,
                target_state.welford_entropy.mean, raw_sigma_h, sigma_h,
                target_state.cooldown_counter
            );

            // Signal Stage 2 on an anomaly, or on the heartbeat so a quiet
            // target keeps reporting.
            let is_heartbeat = (timestamp - target_state.last_sent_time) >= HEARTBEAT_SECS;
            if anomaly_flags != 0 || is_heartbeat {
                if anomaly_flags != 0 {
                    warn!(
                        "ANOMALY window {} [victim={}] | flags={:#04x} | r={:.1} (boundary={:.1}) | \
                         h={:.4} (boundary={:.4}) | proto_ratio={:.3} | dom_ratio={:.3} | dominant_ip={}",
                        target_state.window_id, victim_ip, anomaly_flags, r, rate_boundary, h, entropy_boundary,
                        proto_ratio, dominant_ip_ratio, dominant_ip
                    );
                } else {
                    log::debug!("Window #{}[victim={}]: HEARTBEAT | r={r:.1} | h={h:.4}", target_state.window_id, victim_ip);
                }

                let fv = FeatureVector {
                    entropy:     h,
                    ewma_rate:   r,
                    mean_h:      target_state.welford_entropy.mean,
                    mean_r:      target_state.welford_rate.mean,
                    sigma_h,
                    sigma_r,
                    proto_ratio,
                    dominant_ip_ratio,
                    timestamp,
                    proto_tcp,
                    proto_udp,
                    proto_icmp,
                    proto_sctp,
                    proto_gre,
                    proto_esp,
                    k_multiplier: base_k,
                    cooldown_counter: target_state.cooldown_counter as f64,
                    egress_rate,
                    drop_ratio,
                    dominant_ip,
                    victim_ip:   victim_ip,
                };

                if ipc.send(&fv) {
                    target_state.last_sent_time = timestamp;
                } else {
                    warn!("Analysis: IPC send failed for window #{}[victim={}]; Stage 2 may be offline", target_state.window_id, victim_ip);
                }
            } else {
                // Normal window — no anomaly, no heartbeat. Log at debug level only.
                log::debug!("Window #{}[victim={}]: NORMAL | r={r:.1} | h={h:.4}", target_state.window_id, victim_ip);
            }

            // =====================================================================
            // Training mode: append this window to the CSV regardless of anomaly.
            // =====================================================================
            if let Some(ref mut f) = csv_writer {
                let _ = writeln!(
                    f,
                    "{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.3},{}",
                    h, r,
                    target_state.welford_entropy.mean, target_state.welford_rate.mean,
                    sigma_h, sigma_r,
                    proto_ratio, dominant_ip_ratio,
                    timestamp,
                    current_train_label
                );
            }

            // -------------------------------------------------------------------
            // V4: periodically persist ALL targets' baselines, but only when
            // triggered from a clean window (is_clean_window, captured above --
            // the same gate that decides whether to feed Welford live). That
            // guarantees the file on disk can never be a mid-attack snapshot.
            // Rate-limited to SAVE_INTERVAL_SECS regardless of how many clean
            // windows close in between, to bound both disk I/O and how much
            // state an unannounced power loss could ever cost (worst case: the
            // last SAVE_INTERVAL_SECS of drift, never the baseline itself).
            // Placed at the very end of the loop body (not next to the
            // cooldown-counter update above, where it conceptually belongs)
            // because `target_state` -- a mutable borrow into `targets_map` --
            // is still in use up through the CSV write just above; borrowing
            // `targets_map` immutably here to snapshot every victim has to wait
            // until after target_state's last use in this iteration.
            // -------------------------------------------------------------------
            if is_clean_window && last_baseline_save.elapsed().as_secs_f64() >= persistence::SAVE_INTERVAL_SECS {
                let mut snapshot = PersistedState::new();
                for (ip, state) in targets_map.iter() {
                    snapshot.victims.insert(ip.to_string(), state.to_persisted());
                }
                persistence::save(&cfg.baseline_path, &snapshot);
                last_baseline_save = Instant::now();
            }
            }
        }

        // -------------------------------------------------------------------------
    // The rx channel has closed — the capture thread has exited.
    // -------------------------------------------------------------------------
    info!("Analysis: channel closed. processed windows total. Exiting.");
}

/// Write the active network flows atomically to
/// /run/ddos_stage1/active_flows.json (not /tmp -- same reasoning as
/// ipc::SOCKET_PATH: /tmp is world-writable and this directory isn't).
fn write_active_flows(flow_counts: &HashMap<(IpAddr, IpAddr, u16, u8), u32>, timestamp: f64) {
    // Sort flows by packet count descending
    let mut flows: Vec<_> = flow_counts.iter().collect();
    flows.sort_by(|a, b| b.1.cmp(a.1));

    // Every tracked flow is reported; the map is already bounded by
    // MAX_TRACKED_FLOWS. Sorted busiest-first so the dashboard leads with
    // the flows that matter.
    let all_flows = flows.into_iter();

    let mut json = String::new();
    json.push_str("{\n  \"timestamp\": ");
    json.push_str(&timestamp.to_string());
    json.push_str(",\n  \"active_ips\": [\n");

    let mut first = true;
    for (key, count_ref) in all_flows {
        let (src_ip, dst_ip, port, proto) = *key;
        let count = *count_ref;
        if !first {
            json.push_str(",\n");
        }
        first = false;

        let proto_str = match proto {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => "OTHER",
        };

        // Calculate rate over 10 seconds (count / 10.0)
        let rate = count as f64 / 10.0;

        json.push_str(&format!(
            "    {{\"ip\": \"{}\", \"dst\": \"{}\", \"port\": {}, \"proto\": \"{}\", \"rate\": {:.1}}}",
            src_ip, dst_ip, port, proto_str, rate
        ));
    }
    json.push_str("\n  ]\n}");
    
    // Write atomically
    let tmp_path = "/run/ddos_stage1/active_flows.tmp";
    let final_path = "/run/ddos_stage1/active_flows.json";
    if let Ok(mut file) = std::fs::File::create(tmp_path) {
        use std::io::Write;
        if file.write_all(json.as_bytes()).is_ok() {
            let _ = std::fs::rename(tmp_path, final_path);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Direction, PacketMeta, Protocol};
    use crate::ipc::FEATURE_VECTOR_BYTES;
    use crossbeam_channel::bounded;
    use std::io::Read;
    use std::net::Ipv4Addr;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A quiet window must not be read as an entropy anomaly.
    ///
    /// Entropy is 0.0 both for an empty window and for any window whose
    /// packets all came from one source, so a lull looks identical to a
    /// maximally concentrated flood. Once windows began closing on a
    /// timeout tick, that would flag every quiet second, mark the window
    /// dirty, and stop V4 baseline persistence from saving.
    #[test]
    fn quiet_window_does_not_raise_an_entropy_anomaly() {
        // Derived the same way as production: mean minus k sigma over the
        // learned baseline, not a fixed threshold.
        let (mean_h, sigma_h, k) = (0.92_f64, 0.03_f64, 2.0_f64);
        let boundary = mean_h - k * sigma_h;

        // Empty window.
        assert!(!entropy_anomaly_fires(0.0, boundary, 0));
        // A handful of packets from a single source also scores 0.0.
        assert!(!entropy_anomaly_fires(0.0, boundary, MIN_PACKETS_FOR_ENTROPY - 1));

        // With a real sample behind it, concentration still fires.
        assert!(entropy_anomaly_fires(0.10, boundary, MIN_PACKETS_FOR_ENTROPY));
        // And diverse traffic still does not.
        assert!(!entropy_anomaly_fires(0.95, boundary, MIN_PACKETS_FOR_ENTROPY));
    }

    /// The flow map must stay bounded under a randomized-source flood, and
    /// flows already being tracked must keep counting once it is full.
    #[test]
    fn flow_map_is_bounded() {
        let mut flow_counts: HashMap<(IpAddr, IpAddr, u16, u8), u32> = HashMap::new();
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let established = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), dst, 80u16, 6u8);

        fn insert(map: &mut HashMap<(IpAddr, IpAddr, u16, u8), u32>, key: (IpAddr, IpAddr, u16, u8)) {
            let at_capacity = map.len() >= MAX_TRACKED_FLOWS;
            match map.get_mut(&key) {
                Some(c) => *c += 1,
                None if !at_capacity => {
                    map.insert(key, 1);
                }
                None => {}
            }
        }

        insert(&mut flow_counts, established);

        // Far more unique spoofed sources than the cap allows.
        for i in 0..(MAX_TRACKED_FLOWS as u32 + 5_000) {
            let src = IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + i));
            insert(&mut flow_counts, (src, dst, (i % 65535) as u16, 6u8));
        }

        assert_eq!(
            flow_counts.len(),
            MAX_TRACKED_FLOWS,
            "flow map grew past its cap"
        );

        // The pre-existing flow must still be counting after the cap filled.
        let before = flow_counts[&established];
        insert(&mut flow_counts, established);
        assert_eq!(
            flow_counts[&established],
            before + 1,
            "an already-tracked flow stopped counting once the map filled"
        );
    }

    fn packet() -> PacketMeta {
        PacketMeta {
            direction: Direction::Ingress,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            arrived_at: Instant::now(),
            protocol: Protocol::Tcp,
            dst_port: 80,
        }
    }

    /// Windows must keep closing when no packets are arriving.
    ///
    /// Regression test. The loop used to be `for meta in rx`, so the
    /// window-close check only ran when a packet arrived and a lull meant no
    /// window ever closed. That bit hardest right after a successful block,
    /// when traffic to the victim drops to near zero by design: the EWMA
    /// stopped decaying, the cooldown counter stopped decrementing, and the
    /// V5 drop-rate metric went silent at exactly the moment it should have
    /// been reporting near-total mitigation.
    ///
    /// Counts feature vectors arriving over the real IPC socket rather than
    /// CSV rows, because warm-up windows send telemetry and then skip the
    /// CSV write.
    #[test]
    fn window_closes_during_a_traffic_lull() {
        let sock_path =
            std::env::temp_dir().join(format!("flod_tick_{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).expect("bind test socket");

        let received = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&received);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; FEATURE_VECTOR_BYTES];
                while stream.read_exact(&mut buf).is_ok() {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        let cfg = AnalysisConfig {
            socket_path: sock_path.to_string_lossy().into_owned(),
            baseline_path: std::env::temp_dir()
                .join(format!("flod_tick_baseline_{}.json", std::process::id()))
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        };

        let (tx, rx) = bounded(1024);
        let handle = std::thread::spawn(move || run_analysis_thread(cfg, rx));

        // Enough packets to satisfy MIN_PACKETS_FOR_ENTROPY, then stop sending.
        for _ in 0..25 {
            tx.send(packet()).expect("send");
        }
        std::thread::sleep(Duration::from_millis(900));
        let after_traffic = received.load(Ordering::SeqCst);

        // Go completely silent for well over the 1.0s hard cap. Any further
        // vectors can only have come from a timeout tick.
        std::thread::sleep(Duration::from_millis(1800));
        let after_silence = received.load(Ordering::SeqCst);

        drop(tx);
        let _ = handle.join();
        let _ = std::fs::remove_file(&sock_path);

        assert!(
            after_traffic > 0,
            "expected a window to close while packets were flowing, got none"
        );
        assert!(
            after_silence > after_traffic,
            "no window closed during the lull: {after_traffic} vectors before, \
             {after_silence} after 1.8s of silence. The analysis loop is only \
             advancing on packet arrival."
        );
    }
}
