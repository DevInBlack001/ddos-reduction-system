//! The analysis thread.
//!
//! Receives packet metadata from capture and runs three layers per protected
//! host:
//!
//!   1. Per packet: record the source address in this window's histogram.
//!   2. Per window: compute normalized entropy `h`, and the smoothed rate `r`
//!      from the window's own elapsed time. Entropy resets each window, the
//!      rate does not.
//!   3. Per window: feed both into their accumulators and flag the window if
//!      `r` is above its boundary or `h` below its.
//!
//! A flagged window, or the heartbeat, sends a feature vector to Stage 2.
//!
//! Nothing fires during warm-up, since mean and variance are meaningless on a
//! handful of samples. `k` sets how far from the mean a boundary sits and is
//! configurable: higher is less sensitive, lower fires on flash crowds.

use crate::{
    capture::{Direction, PacketMeta, Protocol},
    entropy::MIN_PACKETS_TO_CLOSE,
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

/// Whether this window may update the baseline and be saved to disk.
///
/// A flagged window normally freezes the baseline, which is what stops a slow
/// ramp attacker from teaching the sensor that their flood is normal.
///
/// The exception is a window flagged only on entropy, at a normal rate, with
/// traffic spread across many sources. That combination cannot be a
/// concentrated flood: low entropy means concentration, and concentration
/// would show up as a high dominant ratio. Without the exception, an entropy
/// boundary sitting too close to the mean freezes the baseline permanently,
/// so the standard deviation can never grow to reflect real variation and the
/// false positives sustain themselves.
fn window_is_clean(
    anomaly_flags: u8,
    cooldown_counter: usize,
    dominant_ip_ratio: f64,
    distributed_dominance: f64,
    rate: f64,
    rate_ceiling: f64,
) -> bool {
    if cooldown_counter > 0 {
        return false;
    }
    if anomaly_flags == 0 {
        return true;
    }
    anomaly_flags == FLAG_ENTROPY_ANOMALY
        && dominant_ip_ratio < distributed_dominance
        && rate <= rate_ceiling
}

/// How far the running mean may sit from the peacetime reference before it is
/// treated as poisoned and reverted.
const MAX_BASELINE_DRIFT: f64 = 0.50;

/// Whether the running mean has drifted far enough from the slow reference to
/// look like poisoning rather than ordinary variation.
fn baseline_has_drifted(mean: f64, reference: f64) -> bool {
    reference > 0.0 && (mean - reference).abs() / reference > MAX_BASELINE_DRIFT
}

/// Rate multiplier after entropy-guided scaling and the emergency volume
/// override.
///
/// A raw rate `cfg.emergency_volume_sigma` standard deviations above the mean
/// bypasses entropy scaling entirely, so a high-entropy flood cannot raise
/// its own detection threshold without bound. Shared by the live boundary
/// and the cooldown-triggering "real anomaly" check, which apply the same
/// scaling against different `k` values.
fn scaled_rate_k(cfg: &AnalysisConfig, base_k: f64, r: f64, mean_rate: f64, sigma_r: f64, h: f64, mean_h: f64) -> f64 {
    if r > mean_rate + cfg.emergency_volume_sigma * sigma_r {
        base_k
    } else {
        let divisor = if mean_h > 0.0 { mean_h } else { cfg.entropy_k_fallback };
        base_k * (h / divisor).max(1.0)
    }
}

/// Where per window observations come from.
///
/// Both arms end up filling the same accumulators on `TargetState`, so the
/// window close below is identical either way and cannot tell them apart.
pub enum PacketSource {
    /// One `PacketMeta` per packet, from the libpcap capture threads.
    Channel(Receiver<PacketMeta>),
    /// Counts already totalled in kernel maps, drained once per tick.
    Kernel(Box<crate::kernel::KernelCapture>),
}

/// Get the state for a protected host, creating it and restoring any saved
/// baseline on first sight.
///
/// Returns `None` when dynamic tracking is capped, which only applies without
/// a configured target list.
fn ensure_target<'a>(
    targets_map: &'a mut HashMap<IpAddr, TargetState>,
    victim: IpAddr,
    cfg: &AnalysisConfig,
    persisted: &Option<PersistedState>,
) -> Option<&'a mut TargetState> {
    if !targets_map.contains_key(&victim) {
        if cfg.victim_targets.is_none() && targets_map.len() >= 100 {
            return None;
        }
        let restored = persistence::lookup(persisted, &victim);
        if let Some(ref r) = restored {
            info!(
                "Analysis [victim={}]: restored baseline from persisted state (rate n={}, entropy n={}/{}).",
                victim, r.rate_n, r.entropy_n, crate::welford::WARMUP_WINDOWS
            );
        }
        targets_map.insert(victim, TargetState::new(cfg.ewma_alpha, restored.as_ref()));
    }
    targets_map.get_mut(&victim)
}

/// Whether a window's entropy counts as an anomaly.
///
/// Requires a minimum sample size, because entropy is 0.0 both for an empty
/// window and for one where a single client happened to be the only one
/// active. Neither is a flood, and both are indistinguishable from one on the
/// entropy figure alone.
fn entropy_anomaly_fires(h: f64, boundary: f64, packet_count: usize, min_packets: usize) -> bool {
    packet_count >= min_packets && h < boundary
}

/// Print every tuning value in force, and warn about ones set where they
/// would stop detection working.
///
/// Detection tuning fails asymmetrically. Too sensitive announces itself in
/// the log within minutes; too insensitive is silent until an attack lands and
/// nothing fires. Printing the effective values makes a typo visible at
/// startup instead of during an incident.
pub fn log_effective_tuning(cfg: &AnalysisConfig) {
    info!(
        "Analysis: tuning | entropy sigma {}..{} | rate sigma floor {} | \
         entropy min packets {} | distributed dominance {} | emergency {}σ | \
         cooldown {} windows",
        cfg.entropy_sigma_floor,
        cfg.entropy_sigma_ceiling,
        cfg.rate_sigma_floor,
        cfg.entropy_min_packets,
        cfg.distributed_dominance,
        cfg.emergency_volume_sigma,
        cfg.cooldown_windows,
    );

    // Bounds are advisory. An operator who means it can still pass anything;
    // the point is that a mistake is not silent.
    if cfg.entropy_sigma_floor >= cfg.entropy_sigma_ceiling {
        warn!(
            "Analysis: the entropy sigma floor ({}) is not below its ceiling ({}), \
             so the boundary cannot adapt at all.",
            cfg.entropy_sigma_floor, cfg.entropy_sigma_ceiling
        );
    }
    if cfg.entropy_sigma_ceiling >= 1.0 {
        warn!(
            "Analysis: an entropy sigma ceiling of {} is at or above the full range \
             of normalized entropy, so the entropy alarm will effectively never fire.",
            cfg.entropy_sigma_ceiling
        );
    }
    if cfg.entropy_min_packets > 10_000 {
        warn!(
            "Analysis: --entropy-min-packets is {}, so windows below that size can \
             never raise an entropy anomaly. Check this is what you meant.",
            cfg.entropy_min_packets
        );
    }
    if cfg.k > 10.0 {
        warn!(
            "Analysis: k is {}, which puts both boundaries far from the mean. \
             Detection will be very hard to trip.",
            cfg.k
        );
    }
    if cfg.distributed_dominance >= 1.0 {
        warn!(
            "Analysis: --distributed-dominance is {}, so every entropy only window \
             updates the baseline. That weakens the slow ramp poisoning defence.",
            cfg.distributed_dominance
        );
    }
}

/// Run the three layer pipeline against `source` indefinitely.
///
/// Returns when a channel source closes. The kernel source never closes, so
/// that arm runs until the process does.
pub fn run_analysis_thread(cfg: AnalysisConfig, mut source: PacketSource) {
    info!(
        "Analysis: thread started | targets={:?} | k={} | α={}",
        cfg.victim_targets, cfg.k, cfg.ewma_alpha
    );

    // The runtime directory lives on tmpfs and is cleared every boot, so it
    // cannot be assumed to exist. Only the mode is set, never ownership.
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::create_dir_all("/run/ddos_stage1").is_ok() {
            let _ = std::fs::set_permissions("/run/ddos_stage1", std::fs::Permissions::from_mode(0o770));
        }
    }

    // Open the CSV training file if --train-csv was passed.
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
                info!("Analysis: training mode on, writing CSV to '{}' with label={}", path, cfg.train_label);
                Some(f)
            }
            Err(e) => {
                warn!("Analysis: failed to open train-csv '{}': {e}. Training disabled", path);
                None
            }
        }
    } else {
        None
    };

    // Keep track of target states per destination IP
    let mut targets_map: HashMap<IpAddr, TargetState> = HashMap::new();

    // A missing, corrupt, or expired baseline is treated as no prior state:
    // the target gets a fresh warm-up.
    let persisted_state = persistence::load(&cfg.baseline_path, cfg.baseline_ttl_secs);
    let mut last_baseline_save = Instant::now();

    // IPC socket to Stage 2 (Python). Connected lazily on first anomaly.
    let mut ipc = IpcSocket::with_path(&cfg.socket_path);

    // Flow counters for the dashboard. The destination is part of the key so
    // the network map can show which host is talking to which.
    let mut flow_counts: HashMap<(IpAddr, IpAddr, u16, u8), u32> = HashMap::new();
    let mut last_flow_write = Instant::now();

    // Live label state for training
    let mut current_train_label = cfg.train_label;
    let mut last_label_check = Instant::now();

    // Main loop. Driven by arriving packets, but also ticks on a timeout so
    // window closes keep happening when no traffic is arriving.
    loop {
        // Which victims to evaluate for a window close this iteration. A
        // packet implicates only its own destination; a timeout tick has to
        // consider every victim being tracked, since any of them could be
        // sitting on an open window with no traffic to close it.
        let victims_to_check: Vec<IpAddr> = match source {
            // The kernel counted everything already. One drain per tick
            // replaces the per packet loop entirely.
            PacketSource::Kernel(ref mut capture) => {
                std::thread::sleep(WINDOW_TICK);
                capture.log_status_if_due();
                match capture.drain() {
                    Ok(samples) => {
                        for (victim_ip, sample) in samples {
                            for ((src, dst, port, proto), count) in &sample.flows {
                                let key = (*src, *dst, *port, *proto);
                                let at_capacity = flow_counts.len() >= MAX_TRACKED_FLOWS;
                                match flow_counts.get_mut(&key) {
                                    Some(existing) => *existing += *count as u32,
                                    None if !at_capacity => {
                                        flow_counts.insert(key, *count as u32);
                                    }
                                    None => {}
                                }
                            }

                            let target_state =
                                match ensure_target(&mut targets_map, victim_ip, &cfg, &persisted_state) {
                                    Some(t) => t,
                                    None => continue,
                                };

                            for (src_ip, count) in &sample.sources {
                                target_state.entropy.add_packets(*src_ip, *count as u32);
                                *target_state.ip_counts.entry(*src_ip).or_insert(0) += *count as u32;
                            }
                            target_state.window_packet_count += sample.ingress_packets as usize;
                            target_state.egress_packet_count += sample.egress_packets;
                            target_state.tcp_count += sample.tcp as u32;
                            target_state.udp_count += sample.udp as u32;
                            target_state.icmp_count += sample.icmp as u32;
                            target_state.sctp_count += sample.sctp as u32;
                            target_state.gre_count += sample.gre as u32;
                            target_state.esp_count += sample.esp as u32;
                        }
                    }
                    Err(e) => warn!("Analysis: could not read the kernel maps: {e}"),
                }
                targets_map.keys().copied().collect()
            }

            PacketSource::Channel(ref rx) => match rx.recv_timeout(WINDOW_TICK) {
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

                let target_state =
                    match ensure_target(&mut targets_map, meta.dst_ip, &cfg, &persisted_state) {
                        Some(t) => t,
                        None => continue,
                    };

                // Egress packets only answer how much got through. Keeping
                // them out of the statistics stops past mitigation from
                // shaping future decisions.
                if meta.direction == Direction::Egress {
                    target_state.egress_packet_count += 1;
                    continue;
                }

                // Layer 1: per packet.
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
            },
        };

        for victim_ip in victims_to_check {
            let target_state = match targets_map.get_mut(&victim_ip) {
                Some(t) => t,
                None => continue,
            };

            // Layer 2: close the window.
            // Closes on 0.5s and 20 packets, or on 1.0s regardless. The
            // packet condition stops a flood producing hundreds of windows a
            // second; the time cap keeps telemetry flowing when traffic is
            // light.
            let now_instant = Instant::now();
            let window_elapsed = now_instant.duration_since(target_state.last_window_close).as_secs_f64();
            let packet_count = target_state.entropy.packet_count();

            let should_close = (window_elapsed >= 0.5 && packet_count >= MIN_PACKETS_TO_CLOSE)
                            || (window_elapsed >= 1.0);

            if !should_close {
                continue;
            }

            target_state.window_id += 1;
            target_state.last_window_close = now_instant;

            // Rate = actual accumulated packets / measured wall-clock elapsed time.
            // Uses the real packet count and duration, not a fixed window size.
            let window_rate = if window_elapsed > 0.0 {
                packet_count as f64 / window_elapsed
            } else {
                0.0
            };

            // V5: what actually reached the victim this window, and the share of
            // arriving traffic that never made it. Both are -1.0 when no egress
            // sensor is configured, so Stage 2 can tell "unknown" apart from a
            // real 0% drop rate. The ratio is clamped because the two sides are
            // measured independently: a packet can cross the egress boundary
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
            // address distribution, normalized to [0.0, 1.0].
            // This call clears the internal HashMap and resets the packet counter.
            let h = target_state.entropy.compute_and_reset();

            // Read the current EWMA rate as a snapshot scalar r.
            // The rate is not reset: it carries memory across windows.
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
            // A UDP or ICMP flood pushes this toward 0.0.
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

            // The label file sits in a root owned directory so a local
            // account cannot flip it mid capture and poison the dataset.
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

            // Layer 3: evaluate and update the baseline.

            // Nothing is evaluated during warm-up, because the
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
                // The IPC layer reports the connection going down and coming
                // back. Repeating it here would be one line per window.
                if !ipc.send(&fv) {
                    log::debug!("Analysis [victim={victim_ip}]: warm-up window not delivered");
                }

                continue;
            }

            if !target_state.warmup_completed_logged {
                info!("Analysis [victim={}]: warm-up complete! Active monitoring started.", victim_ip);
                if cfg.train_csv.is_some() {
                    info!("Analysis [victim={}]: training mode active, appending rows to the CSV.", victim_ip);
                }
                target_state.warmup_completed_logged = true;
            }

            let raw_sigma_r = target_state.welford_rate.std_dev();
            let raw_sigma_h = target_state.welford_entropy.std_dev();

            // Bounded so the boundary can neither collapse onto the mean nor
            // drift so wide that nothing ever trips it.
            let ceiling_r = (cfg.rate_sigma_ceiling_ratio * target_state.welford_rate.mean)
                .max(cfg.rate_sigma_ceiling_floor);
            let sigma_r = raw_sigma_r.max(cfg.rate_sigma_floor).min(ceiling_r);
            let sigma_h = raw_sigma_h.clamp(cfg.entropy_sigma_floor, cfg.entropy_sigma_ceiling);

            // Cooldown reduces k, floored at 1.0, so a target stays easier to
            // re-detect right after a resolved anomaly.
            let base_k = if target_state.cooldown_counter > 0 {
                (cfg.k * cfg.cooldown_k_factor).max(1.0)
            } else {
                cfg.k
            };

            let mean_h = target_state.welford_entropy.mean;
            let rate_k = scaled_rate_k(&cfg, base_k, r, target_state.welford_rate.mean, sigma_r, h, mean_h);
            let entropy_k = base_k;

            let rate_boundary    = target_state.welford_rate.mean + rate_k * sigma_r;
            let entropy_boundary = target_state.welford_entropy.mean - entropy_k * sigma_h;

            let mut anomaly_flags: u8 = 0;
            if r > rate_boundary {
                anomaly_flags |= FLAG_RATE_ANOMALY;
            }
            if entropy_anomaly_fires(h, entropy_boundary, packet_count, cfg.entropy_min_packets) {
                anomaly_flags |= FLAG_ENTROPY_ANOMALY;
            }

            // Recomputed against cfg.k rather than the cooldown-tightened
            // base_k, so a minor fluctuation cannot keep refilling its own
            // cooldown window.
            let real_rate_k = scaled_rate_k(&cfg, cfg.k, r, target_state.welford_rate.mean, sigma_r, h, mean_h);
            let real_rate_boundary = target_state.welford_rate.mean + real_rate_k * sigma_r;
            let real_entropy_boundary = target_state.welford_entropy.mean - cfg.k * sigma_h;
            let is_real_anomaly = r > real_rate_boundary || h < real_entropy_boundary;

            // Named because the baseline snapshot below reuses the same
            // condition. A save must never capture mid attack state.
            let is_clean_window = window_is_clean(
                anomaly_flags,
                target_state.cooldown_counter,
                dominant_ip_ratio,
                cfg.distributed_dominance,
                r,
                target_state.welford_rate.mean + sigma_r,
            );
            if is_clean_window {
                let is_rate_outlier = sigma_r > 0.0
                    && (r - target_state.welford_rate.mean).abs() > cfg.outlier_sigma * sigma_r;
                if !is_rate_outlier && target_state.welford_rate.mean < cfg.rate_mean_cap {
                    target_state.welford_rate.update(r);
                }

                let is_entropy_outlier = sigma_h > 0.0
                    && (h - target_state.welford_entropy.mean).abs() > cfg.outlier_sigma * sigma_h;
                if !is_entropy_outlier {
                    target_state.welford_entropy.update(h);
                }

                // A very slow average, used below to notice the baseline
                // drifting somewhere it should not. Seeded from the mean it
                // will be compared against: seeding from one window instead
                // disagrees with a two hundred sample mean immediately and
                // reports ordinary variation as drift.
                let mean_rate_now = target_state.welford_rate.mean;
                let mean_entropy_now = target_state.welford_entropy.mean;
                let w = cfg.peacetime_ewma_weight;

                let rate_ref = target_state.peacetime_rate_ref.get_or_insert(mean_rate_now);
                *rate_ref = w * r + (1.0 - w) * (*rate_ref);

                let entropy_ref = target_state
                    .peacetime_entropy_ref
                    .get_or_insert(mean_entropy_now);
                *entropy_ref = w * h + (1.0 - w) * (*entropy_ref);

                // Revert the running mean if it has drifted away from the
                // slow reference, which is what a poisoning attempt looks like.
                if baseline_has_drifted(target_state.welford_rate.mean, *rate_ref) {
                    warn!(
                        "Analysis [victim={}]: baseline poisoning suspected, mean rate ({:.2}) deviated >{:.0}% from the peacetime reference ({:.2}); reverting.",
                        victim_ip, target_state.welford_rate.mean, MAX_BASELINE_DRIFT * 100.0, *rate_ref
                    );
                    target_state.welford_rate.mean = *rate_ref;
                }
            }

            // A real anomaly (re)starts the cooldown window; otherwise it
            // counts down.
            if is_real_anomaly {
                target_state.cooldown_counter = cfg.cooldown_windows as usize;
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
                    // See the warm-up send above: the IPC layer owns reporting
                    // that Stage 2 is unreachable.
                    log::debug!(
                        "Analysis: window #{} [victim={victim_ip}] not delivered",
                        target_state.window_id
                    );
                }
            } else {
                // Nothing to report.
                log::debug!("Window #{}[victim={}]: NORMAL | r={r:.1} | h={h:.4}", target_state.window_id, victim_ip);
            }

            // Training mode: append this window to the CSV regardless of anomaly.
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

            // V4: periodically persist ALL targets' baselines, but only when
            // triggered from a clean window (is_clean_window, captured above):
            // the same gate that decides whether to feed Welford live. That
            // guarantees the file on disk can never be a mid-attack snapshot.
            // Rate-limited to SAVE_INTERVAL_SECS regardless of how many clean
            // windows close in between, to bound both disk I/O and how much
            // state an unannounced power loss could ever cost (worst case: the
            // last SAVE_INTERVAL_SECS of drift, never the baseline itself).
            // At the end of the loop body because snapshotting every target
            // needs to borrow the map, which cannot happen while the mutable
            // borrow above is still live.
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

    // The channel closed, so capture has exited.
    info!("Analysis: channel closed. processed windows total. Exiting.");
}

/// Write the active flows atomically. The directory is root owned, so a
/// local account cannot feed the dashboard fabricated flows.
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
    // Production code reads these from AnalysisConfig; only the tests need the
    // defaults themselves.
    use crate::state::{
        DEFAULT_DISTRIBUTED_DOMINANCE, DEFAULT_ENTROPY_MIN_PACKETS,
        DEFAULT_ENTROPY_SIGMA_CEILING, DEFAULT_ENTROPY_SIGMA_FLOOR,
    };
    use crossbeam_channel::bounded;
    use std::io::Read;
    use std::net::Ipv4Addr;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn a_baseline_matching_its_reference_has_not_drifted() {
        assert!(!baseline_has_drifted(100.0, 100.0));
        assert!(!baseline_has_drifted(120.0, 100.0));
    }

    #[test]
    fn a_baseline_far_from_its_reference_has_drifted() {
        assert!(baseline_has_drifted(200.0, 100.0));
        assert!(baseline_has_drifted(40.0, 100.0));
    }

    #[test]
    fn an_unset_reference_never_reports_drift() {
        // Division by zero would otherwise make this fire on every window.
        assert!(!baseline_has_drifted(50.0, 0.0));
    }

    #[test]
    fn seeding_the_reference_from_the_mean_reports_no_immediate_drift() {
        // The reference used to be seeded from a single window. A quiet
        // moment right after warm-up then set it far below a mean built from
        // two hundred windows, and ordinary variation was reported as
        // poisoning. Seeding from the mean starts them in agreement.
        let learned_mean = 18.32;
        let one_quiet_window = 8.50;

        assert!(baseline_has_drifted(learned_mean, one_quiet_window));
        assert!(!baseline_has_drifted(learned_mean, learned_mean));
    }

    #[test]
    fn a_flagged_window_normally_freezes_the_baseline() {
        // The poisoning defence: a slow ramp attacker must not be able to
        // teach the sensor that their flood is normal.
        assert!(!window_is_clean(FLAG_RATE_ANOMALY, 0, 0.1, DEFAULT_DISTRIBUTED_DOMINANCE, 10.0, 100.0));
        assert!(!window_is_clean(
            FLAG_RATE_ANOMALY | FLAG_ENTROPY_ANOMALY,
            0,
            0.1,
            DEFAULT_DISTRIBUTED_DOMINANCE,
            10.0,
            100.0
        ));
    }

    #[test]
    fn a_cooldown_window_is_never_clean() {
        assert!(!window_is_clean(0, 3, 0.1, DEFAULT_DISTRIBUTED_DOMINANCE, 10.0, 100.0));
    }

    #[test]
    fn an_unflagged_window_is_clean() {
        assert!(window_is_clean(0, 0, 0.9, DEFAULT_DISTRIBUTED_DOMINANCE, 10.0, 100.0));
    }

    #[test]
    fn a_distributed_entropy_only_flag_still_updates_the_baseline() {
        // The false positive case. Without this the boundary freezes at its
        // warm-up value and the false positives sustain themselves.
        assert!(window_is_clean(FLAG_ENTROPY_ANOMALY, 0, 0.2, DEFAULT_DISTRIBUTED_DOMINANCE, 10.0, 100.0));
    }

    #[test]
    fn a_concentrated_entropy_flag_still_freezes_the_baseline() {
        // Concentration is what a real flood looks like, so this one has to
        // keep freezing.
        assert!(!window_is_clean(FLAG_ENTROPY_ANOMALY, 0, 0.85, DEFAULT_DISTRIBUTED_DOMINANCE, 10.0, 100.0));
    }

    #[test]
    fn an_entropy_flag_at_an_elevated_rate_freezes_the_baseline(){
        assert!(!window_is_clean(FLAG_ENTROPY_ANOMALY, 0, 0.2, DEFAULT_DISTRIBUTED_DOMINANCE, 500.0, 100.0));
    }

    #[test]
    fn the_entropy_sigma_floor_keeps_the_boundary_off_the_mean() {
        // A baseline built on uniform traffic produces a near zero standard
        // deviation, which would put the boundary on top of the mean and flag
        // about half of all ordinary windows.
        let raw_sigma_h = 0.0001_f64;
        let sigma_h = raw_sigma_h.clamp(DEFAULT_ENTROPY_SIGMA_FLOOR, DEFAULT_ENTROPY_SIGMA_CEILING);
        let mean_h = 0.98;
        let boundary = mean_h - 2.0 * sigma_h;
        // Compared against the floor itself rather than a literal, so this
        // keeps testing the intent if the floor is retuned.
        let gap = mean_h - boundary;
        assert!(
            gap >= 2.0 * DEFAULT_ENTROPY_SIGMA_FLOOR - f64::EPSILON,
            "boundary sat {gap:.4} below the mean, too close to be meaningful"
        );
    }

    #[test]
    fn the_entropy_sigma_ceiling_still_applies() {
        assert_eq!(0.9_f64.clamp(DEFAULT_ENTROPY_SIGMA_FLOOR, DEFAULT_ENTROPY_SIGMA_CEILING),
            DEFAULT_ENTROPY_SIGMA_CEILING);
    }

    /// A quiet window must not be read as an entropy anomaly.
    ///
    /// Entropy is 0.0 both for an empty window and for any window whose
    /// packets all came from one source, so a lull looks identical to a
    /// maximally concentrated flood. Once windows began closing on a
    /// timeout tick, that would flag every quiet second, mark the window
    /// dirty, and stop baseline persistence from saving.
    #[test]
    fn quiet_window_does_not_raise_an_entropy_anomaly() {
        // Derived the same way as production: mean minus k sigma over the
        // learned baseline, not a fixed threshold.
        let (mean_h, sigma_h, k) = (0.92_f64, 0.03_f64, 2.0_f64);
        let boundary = mean_h - k * sigma_h;

        let gate = DEFAULT_ENTROPY_MIN_PACKETS;

        // Empty window.
        assert!(!entropy_anomaly_fires(0.0, boundary, 0, gate));
        // A handful of packets from a single source also scores 0.0.
        assert!(!entropy_anomaly_fires(0.0, boundary, gate - 1, gate));

        // With a real sample behind it, concentration still fires.
        assert!(entropy_anomaly_fires(0.10, boundary, gate, gate));
        // And diverse traffic still does not.
        assert!(!entropy_anomaly_fires(0.95, boundary, gate, gate));
    }

    #[test]
    fn a_quiet_single_client_window_does_not_look_like_a_flood() {
        // The residual false positive the gate exists for. One client sending
        // a burst while the others are idle scores total concentration, which
        // is true and meaningless: there was only one participant.
        let boundary = 0.9417;
        let one_busy_client = 31; // packets, seen on the sensor VM

        assert!(!entropy_anomaly_fires(
            0.0,
            boundary,
            one_busy_client,
            DEFAULT_ENTROPY_MIN_PACKETS
        ));
        // The old gate of 20 let exactly this through.
        assert!(entropy_anomaly_fires(0.0, boundary, one_busy_client, MIN_PACKETS_TO_CLOSE));
    }

    #[test]
    fn a_real_flood_still_fires_through_the_gate() {
        // The flood seen on the VM: six figures of pps, so the packet count
        // clears any sane gate.
        assert!(entropy_anomaly_fires(0.0007, 0.9417, 50_000, DEFAULT_ENTROPY_MIN_PACKETS));
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
        let handle = std::thread::spawn(move || run_analysis_thread(cfg, PacketSource::Channel(rx)));

        // Enough packets to satisfy MIN_PACKETS_TO_CLOSE, then stop sending.
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
