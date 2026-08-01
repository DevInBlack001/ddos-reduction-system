// =============================================================================
// state.rs — Analysis-thread configuration and per-victim running state
// =============================================================================
//
// Split out of analysis.rs so the data structures (what's tracked per
// victim, and what the thread is configured with) live separately from the
// three-layer pipeline logic that operates on them (run_analysis_thread,
// still in analysis.rs). Fields are `pub(crate)` rather than fully `pub`:
// this is internal wiring between analysis.rs and this module, not a
// public API of the crate.
// =============================================================================

use crate::{
    entropy::EntropyAccumulator,
    ewma::EwmaState,
    persistence::{self, PersistedBaseline},
    welford::WelfordAccumulator,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

// -----------------------------------------------------------------------------
// AnalysisConfig
// -----------------------------------------------------------------------------

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
    /// (`/var/lib/ddos_stage1/baselines.json` -- deliberately not /tmp).
    pub baseline_path: String,
    /// V4: reject a persisted baseline older than this many seconds rather
    /// than trusting it. Default: `persistence::DEFAULT_TTL_SECS` (1 hour).
    pub baseline_ttl_secs: f64,
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
        }
    }
}

// -----------------------------------------------------------------------------
// TargetState — per-victim running state
// -----------------------------------------------------------------------------

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
    pub(crate) last_window_close: Instant,
    pub(crate) cooldown_counter: usize,
    pub(crate) last_sent_time: f64,
    pub(crate) warmup_completed_logged: bool,
}

impl TargetState {
    /// Create a fresh target state, or -- if `persisted` is `Some` (a
    /// baseline was found for this victim's IP in the loaded persistence
    /// file, still within its TTL) -- restore the Welford/EWMA/cooldown/
    /// peacetime-reference state from it instead of starting at zero.
    ///
    /// Everything NOT restored here (window_id, ip_counts, timing fields)
    /// is intentionally transient and correctly starts fresh regardless --
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
