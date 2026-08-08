//! Smoothed packet rate.
//!
//! `ewma_new = alpha * window_rate + (1 - alpha) * ewma_old`, where the window
//! rate is the packet count over the window's measured elapsed time. Higher
//! alpha reacts faster and is noisier.
//!
//! Updated once per window close, never per packet: sub microsecond gaps
//! between packets are dominated by scheduling jitter.
//!
//! It never resets. Carrying memory across windows is what catches a flood
//! that ramps up gradually.
//!
//! State is a single f64, so cost does not grow with uptime.

pub const DEFAULT_ALPHA: f64 = 0.125;

// EwmaState

/// Maintains the running EWMA packet-rate estimate.
///
/// Instantiate once per analysis session.  At each window close, call
/// `update_rate_with_alpha(window_rate, alpha)` with the measured rate.
/// Read `snapshot()` to obtain the current smoothed scalar for Welford.
#[derive(Debug, Clone)]
pub struct EwmaState {
    /// Current smoothed rate estimate in packets per second.
    value: f64,
    /// Smoothing factor α ∈ (0, 1).
    alpha: f64,
}

impl EwmaState {
    /// Create a new EWMA state with the default alpha (`DEFAULT_ALPHA`).
    pub fn new() -> Self {
        Self {
            value: 0.0,
            alpha: DEFAULT_ALPHA,
        }
    }

    /// Create a new EWMA state with a custom smoothing factor.
    ///
    /// # Panics
    /// Panics if `alpha` is not in the open interval (0, 1).
    pub fn with_alpha(alpha: f64) -> Self {
        assert!(
            alpha > 0.0 && alpha < 1.0,
            "alpha must be in (0, 1), got {alpha}"
        );
        Self {
            value: 0.0,
            alpha,
        }
    }

    /// Return the current smoothed rate estimate (packets per second).
    ///
    /// Called once per window close by the analysis thread to produce the
    /// scalar `x_rate` that feeds `WelfordAccumulator::update()`.
    ///
    /// Reading does not reset it. It keeps its memory
    /// across windows so that flood ramp-ups spanning multiple windows are
    /// still detected.
    pub fn snapshot(&self) -> f64 {
        self.value
    }

    /// Update the EWMA rate directly with a pre-calculated rate sample.
    #[allow(dead_code)]
    pub fn update_rate(&mut self, rate: f64) {
        self.value = self.alpha * rate + (1.0 - self.alpha) * self.value;
    }

    /// Update the EWMA rate directly with a pre-calculated rate sample and custom alpha.
    pub fn update_rate_with_alpha(&mut self, rate: f64, alpha: f64) {
        self.value = alpha * rate + (1.0 - alpha) * self.value;
    }

    /// Set the smoothed value directly, used only to restore a persisted
    /// baseline (V4) on startup. Not part of the normal per-window update
    /// path, which always goes through `update_rate_with_alpha()`.
    pub fn set_value(&mut self, value: f64) {
        self.value = value;
    }

    /// Expose the current alpha for logging / debugging.
    #[allow(dead_code)]
    pub fn alpha(&self) -> f64 {
        self.alpha
    }
}

impl Default for EwmaState {
    fn default() -> Self {
        Self::new()
    }
}

// Unit Tests

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: simulate `n` window-close rate updates at a fixed rate.
    fn simulate_fixed_rate(alpha: f64, rate_pps: f64, n: usize) -> EwmaState {
        let mut ewma = EwmaState::with_alpha(alpha);
        for _ in 0..n {
            ewma.update_rate_with_alpha(rate_pps, alpha);
        }
        ewma
    }

    /// After many windows at a fixed rate, the EWMA should converge
    /// close to that true rate.
    ///
    /// At 100 pps for 200 windows the EWMA should be within 1% of 100 pps.
    #[test]
    fn convergence_to_steady_state() {
        let ewma = simulate_fixed_rate(DEFAULT_ALPHA, 100.0, 200);
        let expected = 100.0;
        let got      = ewma.snapshot();
        let err_pct  = ((got - expected) / expected).abs() * 100.0;
        assert!(
            err_pct < 1.0,
            "EWMA did not converge: expected ~{expected} pps, got {got:.2} pps ({err_pct:.1}% error)"
        );
    }

    /// A fresh EWMA starts at 0.0.
    #[test]
    fn initial_value_is_zero() {
        let ewma = EwmaState::new();
        assert_eq!(ewma.snapshot(), 0.0);
    }

    /// The EWMA reacts upward when the window rate spikes.
    #[test]
    fn rate_spike_increases_ewma() {
        // First 100 windows at 100 pps.
        let mut ewma = simulate_fixed_rate(DEFAULT_ALPHA, 100.0, 100);
        let before = ewma.snapshot();

        // Next 20 windows at 1000 pps (a 10× spike).
        for _ in 0..20 {
            ewma.update_rate_with_alpha(1000.0, DEFAULT_ALPHA);
        }
        let after = ewma.snapshot();

        assert!(
            after > before,
            "EWMA should increase during a rate spike (before={before:.2}, after={after:.2})"
        );
    }

    /// alpha = 0.5 should converge faster than alpha = 0.125.
    #[test]
    fn higher_alpha_converges_faster() {
        let slow = simulate_fixed_rate(0.125, 100.0, 50).snapshot();
        let fast = simulate_fixed_rate(0.500, 100.0, 50).snapshot();
        let target = 100.0;

        // Both should be heading toward 100 pps; fast alpha should be closer.
        let slow_err = (slow - target).abs();
        let fast_err = (fast - target).abs();
        assert!(
            fast_err <= slow_err,
            "higher alpha should converge faster (slow_err={slow_err:.2}, fast_err={fast_err:.2})"
        );
    }

    /// A zero-rate window should not corrupt the EWMA.
    #[test]
    fn zero_rate_is_safe() {
        let mut ewma = simulate_fixed_rate(DEFAULT_ALPHA, 100.0, 50);
        ewma.update_rate_with_alpha(0.0, DEFAULT_ALPHA);
        assert!(
            ewma.snapshot().is_finite(),
            "EWMA became non-finite after zero-rate update"
        );
        assert!(
            ewma.snapshot() < 100.0,
            "EWMA should decrease after a zero-rate window"
        );
    }
}
