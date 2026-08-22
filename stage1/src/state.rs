//! Analysis configuration and the per target running state.
//!
//! Separate from analysis.rs so the data lives apart from the pipeline that
//! operates on it. Fields are crate visible: this is internal wiring, not a
//! public API.

use crate::{
    entropy::EntropyAccumulator,
    ewma::EwmaState,
    persistence::{self, PersistedBaseline},
    welford::WelfordAccumulator,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

// AnalysisConfig

/// Defaults for the tuning values on `AnalysisConfig`. Starting points, not
/// values proven optimal: the right floor depends on how much a given
/// network's traffic naturally varies.
pub const DEFAULT_ENTROPY_SIGMA_FLOOR: f64 = 0.05;
pub const DEFAULT_ENTROPY_SIGMA_CEILING: f64 = 0.15;
pub const DEFAULT_RATE_SIGMA_FLOOR: f64 = 50.0;
pub const DEFAULT_DISTRIBUTED_DOMINANCE: f64 = 0.40;
/// Five times the window close threshold. Sized so that "every packet came
/// from one source" is a statement about the traffic rather than about a
/// window that happened to be quiet. Not a measured value: raise it if quiet
/// single client windows are being flagged on your network.
pub const DEFAULT_ENTROPY_MIN_PACKETS: usize = 100;

/// Matches the kernel backend's FLOWS map, so both backends bound the flow
/// table the same way and stay comparable.
pub const DEFAULT_MAX_TRACKED_FLOWS: usize = 8192;
pub const DEFAULT_EMERGENCY_VOLUME_SIGMA: f64 = 10.0;
pub const DEFAULT_ENTROPY_K_FALLBACK: f64 = 0.8;
pub const DEFAULT_RATE_SIGMA_CEILING_RATIO: f64 = 0.2;
pub const DEFAULT_RATE_SIGMA_CEILING_FLOOR: f64 = 10000.0;
pub const DEFAULT_OUTLIER_SIGMA: f64 = 5.0;
pub const DEFAULT_RATE_MEAN_CAP: f64 = 10000.0;
pub const DEFAULT_COOLDOWN_WINDOWS: u64 = 10;
pub const DEFAULT_COOLDOWN_K_FACTOR: f64 = 0.5;
pub const DEFAULT_PEACETIME_EWMA_WEIGHT: f64 = 0.001;

/// Runtime parameters for the analysis thread.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Anomaly detection multiplier (k in `μ ± k·σ`).
    /// Default: 2.0 (two standard deviations, as per the project specification).
    pub k: f64,
    /// EWMA smoothing factor α. Default: 0.125 (RFC 6298 TCP RTT constant).
    pub ewma_alpha: f64,
    /// Socket path for IPC to Stage 2. Default: `/run/ddos_stage1/stage1.sock`.
    pub socket_path: String,
    /// Monitored victim targets.
    pub victim_targets: Option<crate::VictimTargets>,
    /// If Some, write every post-warmup feature vector to this CSV file.
    /// The file is created (or appended) at thread start.
    pub train_csv: Option<String>,
    /// Integer class label written into every CSV row.
    /// 0 = normal, 1 = flash_crowd, 2 = ddos
    pub train_label: u8,
    /// V4: where to persist/reload per-victim Welford/EWMA baselines across
    /// restarts. Default: `persistence::DEFAULT_BASELINE_PATH`
    /// (`/var/lib/ddos_stage1/baselines.json`, chosen to survive a reboot).
    pub baseline_path: String,
    /// V4: reject a persisted baseline older than this many seconds rather
    /// than trusting it. Default: `persistence::DEFAULT_TTL_SECS` (1 hour).
    pub baseline_ttl_secs: f64,
    /// V5: true when `--egress-interface` was supplied. Distinguishes "no
    /// egress sensor, drop rate unknown" from a genuine 0% drop rate.
    pub egress_enabled: bool,
    /// Floor under the entropy standard deviation.
    ///
    /// The single most important tuning value after `k`. A baseline learned
    /// on uniform traffic produces a standard deviation near zero, which puts
    /// the boundary on top of the mean and flags roughly half of ordinary
    /// windows. Raise it when normal traffic varies more than the default
    /// assumes.
    pub entropy_sigma_floor: f64,
    /// Ceiling on the entropy standard deviation, so the boundary cannot
    /// drift so wide that nothing ever trips it.
    pub entropy_sigma_ceiling: f64,
    /// Floor under the rate standard deviation, for the same reason as the
    /// entropy floor.
    pub rate_sigma_floor: f64,
    /// Dominance below which traffic is too spread out to be a concentrated
    /// flood, whatever the entropy figure says.
    ///
    /// Stage 2 has its own copy of this idea in
    /// `dominant_ip_ratio_block_threshold`. They are separate processes and
    /// this one cannot read that file, so if you change one, change both.
    pub distributed_dominance: f64,
    /// Packets a window needs before its entropy is allowed to raise an
    /// anomaly.
    ///
    /// Concentration is only meaningful when there were enough packets for it
    /// to be surprising. A quiet window where one client happened to be the
    /// only one active reads as total concentration and is not an attack.
    /// Separate from the window close threshold on purpose: raising this must
    /// not change when windows close.
    pub entropy_min_packets: usize,
    /// Cap on distinct flows tracked per window. The key is attacker
    /// controlled, so a randomized source flood would otherwise allocate an
    /// entry per packet. Raise it on a gateway that legitimately carries more
    /// concurrent flows than the default allows.
    pub max_tracked_flows: usize,
    /// Rate deviation, in standard deviations above the mean, past which
    /// entropy-based k scaling is bypassed and the plain multiplier applies.
    /// Stops a high-entropy botnet flood from raising its own threshold
    /// without bound.
    pub emergency_volume_sigma: f64,
    /// Divisor used for entropy-guided k scaling when the learned mean
    /// entropy is still 0.0, i.e. during warm-up.
    pub entropy_k_fallback: f64,
    /// The rate standard deviation's ceiling is this fraction of the mean,
    /// or `rate_sigma_ceiling_floor`, whichever is larger.
    pub rate_sigma_ceiling_ratio: f64,
    /// Floor under the rate sigma ceiling; see `rate_sigma_ceiling_ratio`.
    pub rate_sigma_ceiling_floor: f64,
    /// A sample this many standard deviations from the mean is rejected as
    /// an outlier rather than folded into the baseline.
    pub outlier_sigma: f64,
    /// Hard ceiling on the learned mean rate, in packets per second.
    pub rate_mean_cap: f64,
    /// How many windows of heightened sensitivity follow a real anomaly.
    pub cooldown_windows: u64,
    /// How much a window inside the cooldown window reduces k, floored at
    /// 1.0 so it can never fall below one standard deviation.
    pub cooldown_k_factor: f64,
    /// EWMA weight used for the peacetime reference. Deliberately much
    /// smaller than `ewma_alpha`: the reference needs to move slower than
    /// the mean it guards, or it cannot tell drift from ordinary variation.
    pub peacetime_ewma_weight: f64,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            k:           2.0,
            ewma_alpha:  crate::ewma::DEFAULT_ALPHA,
            socket_path: crate::ipc::SOCKET_PATH.to_string(),
            victim_targets: None,
            train_csv:   None,
            train_label: 0,
            baseline_path: persistence::DEFAULT_BASELINE_PATH.to_string(),
            baseline_ttl_secs: persistence::DEFAULT_TTL_SECS,
            egress_enabled: false,
            entropy_sigma_floor:   DEFAULT_ENTROPY_SIGMA_FLOOR,
            entropy_sigma_ceiling: DEFAULT_ENTROPY_SIGMA_CEILING,
            rate_sigma_floor:      DEFAULT_RATE_SIGMA_FLOOR,
            distributed_dominance: DEFAULT_DISTRIBUTED_DOMINANCE,
            entropy_min_packets:   DEFAULT_ENTROPY_MIN_PACKETS,
            max_tracked_flows:     DEFAULT_MAX_TRACKED_FLOWS,
            emergency_volume_sigma: DEFAULT_EMERGENCY_VOLUME_SIGMA,
            entropy_k_fallback:     DEFAULT_ENTROPY_K_FALLBACK,
            rate_sigma_ceiling_ratio: DEFAULT_RATE_SIGMA_CEILING_RATIO,
            rate_sigma_ceiling_floor: DEFAULT_RATE_SIGMA_CEILING_FLOOR,
            outlier_sigma:          DEFAULT_OUTLIER_SIGMA,
            rate_mean_cap:          DEFAULT_RATE_MEAN_CAP,
            cooldown_windows:       DEFAULT_COOLDOWN_WINDOWS,
            cooldown_k_factor:      DEFAULT_COOLDOWN_K_FACTOR,
            peacetime_ewma_weight:  DEFAULT_PEACETIME_EWMA_WEIGHT,
        }
    }
}


/// Per-victim accumulated state: EWMA rate, entropy accumulator, protocol
/// counters, and the Welford baselines both metrics feed into.
#[derive(Debug)]
pub struct TargetState {
    pub(crate) ewma: EwmaState,
    pub(crate) entropy: EntropyAccumulator,
    pub(crate) tcp_count: u32,
    pub(crate) udp_count: u32,
    pub(crate) icmp_count: u32,
    pub(crate) sctp_count: u32,
    pub(crate) gre_count: u32,
    pub(crate) esp_count: u32,
    pub(crate) welford_rate: WelfordAccumulator,
    pub(crate) welford_entropy: WelfordAccumulator,
    pub(crate) peacetime_rate_ref: Option<f64>,
    pub(crate) peacetime_entropy_ref: Option<f64>,
    pub(crate) window_id: u64,
    pub(crate) ip_counts: HashMap<IpAddr, u32>,
    pub(crate) window_packet_count: usize,
    /// V5: packets seen on the egress side for this victim in the current
    /// window, i.e. what survived filtering. Reset at every window close.
    /// Absent from `to_persisted()` because this is a measurement,
    /// not a statistical baseline, so it must not survive a restart.
    pub(crate) egress_packet_count: u64,
    pub(crate) last_window_close: Instant,
    pub(crate) cooldown_counter: usize,
    pub(crate) last_sent_time: f64,
    pub(crate) warmup_completed_logged: bool,
}

impl TargetState {
    /// Create a fresh target state, or restore the accumulators, rate,
    /// cooldown, and peacetime references from `persisted` when a baseline
    /// for this address was loaded and is still within its TTL.
    ///
    /// Everything NOT restored here (window_id, ip_counts, timing fields)
    /// is intentionally transient and correctly starts fresh regardless;
    /// see persistence.rs's module docs for why only the statistical
    /// baseline itself is worth carrying across a restart.
    pub fn new(ewma_alpha: f64, persisted: Option<&PersistedBaseline>) -> Self {
        let mut welford_rate = WelfordAccumulator::default();
        let mut welford_entropy = WelfordAccumulator::default();
        let mut ewma = EwmaState::with_alpha(ewma_alpha);
        let mut cooldown_counter = 0;
        let mut peacetime_rate_ref = None;
        let mut peacetime_entropy_ref = None;

        if let Some(p) = persisted {
            welford_rate.n = p.rate_n;
            welford_rate.mean = p.rate_mean;
            welford_rate.m2 = p.rate_m2;
            welford_entropy.n = p.entropy_n;
            welford_entropy.mean = p.entropy_mean;
            welford_entropy.m2 = p.entropy_m2;
            ewma.set_value(p.ewma_rate);
            cooldown_counter = p.cooldown_counter;
            peacetime_rate_ref = p.peacetime_rate_ref;
            peacetime_entropy_ref = p.peacetime_entropy_ref;
        }

        Self {
            ewma,
            entropy: EntropyAccumulator::new(),
            tcp_count: 0,
            udp_count: 0,
            icmp_count: 0,
            sctp_count: 0,
            gre_count: 0,
            esp_count: 0,
            welford_rate,
            welford_entropy,
            peacetime_rate_ref,
            peacetime_entropy_ref,
            window_id: 0,
            ip_counts: HashMap::new(),
            window_packet_count: 0,
            egress_packet_count: 0,
            last_window_close: Instant::now(),
            cooldown_counter,
            last_sent_time: 0.0,
            warmup_completed_logged: false,
        }
    }

    /// Snapshot this target's current baseline for persistence (V4). Called
    /// only from a clean window (see the save-trigger site in
    /// `run_analysis_thread`) so a snapshot can never capture mid-attack
    /// state.
    pub fn to_persisted(&self) -> PersistedBaseline {
        PersistedBaseline {
            rate_n: self.welford_rate.n,
            rate_mean: self.welford_rate.mean,
            rate_m2: self.welford_rate.m2,
            entropy_n: self.welford_entropy.n,
            entropy_mean: self.welford_entropy.mean,
            entropy_m2: self.welford_entropy.m2,
            ewma_rate: self.ewma.snapshot(),
            cooldown_counter: self.cooldown_counter,
            peacetime_rate_ref: self.peacetime_rate_ref,
            peacetime_entropy_ref: self.peacetime_entropy_ref,
        }
    }
}
