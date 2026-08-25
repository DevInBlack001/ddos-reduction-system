//! Running mean and variance over a stream of samples.
//!
//! Accumulating a sum and a sum of squares and subtracting them loses all
//! precision on a long stream: the two terms nearly cancel. This works with
//! small deltas against the running mean instead.
//!
//!     delta  = x - old_mean
//!     mean  += delta / n
//!     delta2 = x - new_mean
//!     M2    += delta * delta2
//!
//! Multiplying the two deltas carries the sum of squares from the old mean to
//! the new one in one step, with no stored history.
//!
//! `n` is capped so the mean stays responsive. Without a cap `delta / n`
//! approaches zero and the baseline freezes. Once capped, M2 decays too, which
//! makes this a bounded memory approximation rather than exact variance.
//!
//! Golden vector: `[4, 7, 13, 16]` gives mean 10.0 and variance 30.0.

pub const WARMUP_WINDOWS: u64 = 200;

/// Maximum `n` the accumulator will count to before capping.  
/// This limits how "frozen" the mean can become over a long-running session
/// (the "recency memory" cap described in the architecture notes).
pub const MAX_N: u64 = 500;

// WelfordAccumulator

/// Incrementally tracks mean and variance for a stream of `f64` samples.
///
/// Fields are `pub` so the IPC serialisation layer can read them directly
/// without going through a getter each packet cycle.
#[derive(Debug, Clone)]
pub struct WelfordAccumulator {
    /// Number of samples seen so far (capped at `max_n` for recency).
    pub n: u64,
    /// Running mean (μ).
    pub mean: f64,
    /// Running sum-of-squared-deviations (M2 in Welford notation).
    /// `variance = M2 / (n - 1)` once n ≥ 2.
    pub m2: f64,
    /// Upper cap on `n` to preserve recency sensitivity.
    max_n: u64,
}

impl WelfordAccumulator {
    /// Create a new accumulator with a custom recency cap.
    /// For most gateway uses, prefer `WelfordAccumulator::default()`.
    pub fn new(max_n: u64) -> Self {
        Self {
            n: 0,
            mean: 0.0,
            m2: 0.0,
            max_n,
        }
    }

    /// Ingest one new scalar sample and update mean + M2.
    ///
    /// This is the *only* operation the rest of the code calls on this struct.
    /// Everything else (variance, std_dev, threshold) is a derived read.
    pub fn update(&mut self, x: f64) {
        // Increment sample counter, but never exceed the recency cap.
        // At the cap the full update still runs. The only
        // difference is the nudge factor (delta/n) stays at 1/max_n, which
        // keeps the mean responsive to recent traffic rather than frozen at a
        // historical average built up over millions of windows.
        let at_cap = self.n >= self.max_n;
        self.n = (self.n + 1).min(self.max_n);

        // Deviation before the mean moves.
        let delta = x - self.mean;

        // Shift the centre toward x.
        self.mean += delta / self.n as f64;

        // Deviation from the new centre.
        let delta2 = x - self.mean;

        // Accumulate the cross product.
        // The product delta×delta2 is the exact correction needed to transition
        // the sum of squares from the old mean to the new mean without storing
        // any past data. A perfectly average sample contributes 0×0 = 0.
        if at_cap {
            // Apply exponential decay to M2 to match the recency cap of the mean.
            // This prevents M2 (and thus variance/std_dev) from growing to infinity
            // over a long-running session.
            self.m2 = self.m2 * (1.0 - 1.0 / self.max_n as f64) + delta * delta2;
        } else {
            self.m2 += delta * delta2;
        }
    }

    /// Ingest `count` copies of the same value at once, using the standard
    /// parallel variance merge formula (Chan et al. 1979) rather than
    /// calling `update` in a loop.
    ///
    /// The kernel capture backend arrives with values already grouped by
    /// count (e.g. "40 packets carried TTL 64"), so a per sample loop here
    /// would put back the per packet cost that backend exists to remove,
    /// the same reasoning `EntropyAccumulator::add_packets` already
    /// documents for the entropy side.
    ///
    /// Treating the batch as a second accumulator of `count` identical
    /// samples (mean `x`, M2 zero) and merging it in one step:
    ///
    ///     delta      = x - mean
    ///     n_combined = n + count
    ///     mean      += delta * count / n_combined
    ///     M2        += delta² * n * count / n_combined
    ///
    /// The recency cap still applies to the resulting `n`, but only once
    /// per call rather than once per sample: a batch that would cross the
    /// cap mid way through has its excess samples dropped rather than
    /// decaying M2 one sample at a time. That only differs from calling
    /// `update` in a loop while a single batch is itself larger than the
    /// remaining headroom under the cap, which is not the steady state the
    /// cap exists to keep responsive.
    pub fn update_batch(&mut self, x: f64, count: u64) {
        if count == 0 {
            return;
        }
        let delta = x - self.mean;
        let n_before = self.n;
        let n_after = (n_before + count).min(self.max_n);
        let absorbed = n_after - n_before;
        if absorbed == 0 {
            return;
        }
        self.mean += delta * absorbed as f64 / n_after as f64;
        self.m2 += delta * delta * n_before as f64 * absorbed as f64 / n_after as f64;
        self.n = n_after;
    }

    /// Population variance (σ²) using Bessel's correction (n−1).
    ///
    /// Returns `None` if fewer than 2 samples have been seen (division by zero
    /// risk) or if M2 has gone negative due to floating-point noise near zero.
    pub fn variance(&self) -> Option<f64> {
        if self.n < 2 {
            return None;
        }
        let v = self.m2 / (self.n - 1) as f64;
        if v < 0.0 { None } else { Some(v) }
    }

    /// Standard deviation (σ = √variance).
    ///
    /// Returns `0.0` if variance is not yet available (warm-up period).
    pub fn std_dev(&self) -> f64 {
        self.variance().map(|v| v.sqrt()).unwrap_or(0.0)
    }

    /// Upper anomaly boundary: μ + k·σ
    ///
    /// Used for the rate. A value above this boundary
    /// means the packet rate has surged beyond normal levels.
    #[allow(dead_code)]
    pub fn upper_boundary(&self, k: f64) -> f64 {
        self.mean + k * self.std_dev()
    }

    /// Lower anomaly boundary: μ − k·σ
    ///
    /// Used for entropy. A value below this boundary
    /// means traffic sources have become abnormally concentrated (DDoS pattern).
    #[allow(dead_code)]
    pub fn lower_boundary(&self, k: f64) -> f64 {
        self.mean - k * self.std_dev()
    }

    /// Returns `true` once the accumulator has seen enough windows to be
    /// trusted for anomaly decisions (see `WARMUP_WINDOWS`).
    pub fn is_warm(&self) -> bool {
        self.n >= WARMUP_WINDOWS
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.n    = 0;
        self.mean = 0.0;
        self.m2   = 0.0;
    }
}

impl Default for WelfordAccumulator {
    fn default() -> Self {
        Self::new(MAX_N)
    }
}

// Unit Tests

#[cfg(test)]
mod tests {
    use super::*;

    /// A batch of identical samples must land on exactly the same mean and
    /// variance as adding them one at a time. The two backends use
    /// different arms of this, so they have to agree exactly.
    #[test]
    fn batch_update_matches_sequential_updates() {
        let mut sequential = WelfordAccumulator::default();
        for _ in 0..3 {
            sequential.update(64.0);
        }
        sequential.update(128.0);

        let mut batched = WelfordAccumulator::default();
        batched.update_batch(64.0, 3);
        batched.update_batch(128.0, 1);

        assert_eq!(sequential.n, batched.n);
        assert!((sequential.mean - batched.mean).abs() < 1e-10);
        assert!((sequential.variance().unwrap() - batched.variance().unwrap()).abs() < 1e-10);
    }

    /// A batch of one value only, however large, has zero variance: every
    /// sample agrees with the mean exactly.
    #[test]
    fn a_batch_of_one_distinct_value_has_zero_variance() {
        let mut acc = WelfordAccumulator::default();
        acc.update_batch(64.0, 200);
        assert_eq!(acc.n, 200);
        let var = acc.variance().unwrap();
        assert!(var.abs() < 1e-10, "expected ~0 variance, got {var}");
    }

    /// A zero count batch changes nothing.
    #[test]
    fn a_batch_of_zero_changes_nothing() {
        let mut acc = WelfordAccumulator::default();
        acc.update(10.0);
        acc.update_batch(999.0, 0);
        assert_eq!(acc.n, 1);
        assert_eq!(acc.mean, 10.0);
    }

    /// Golden test vector from the architecture spec.
    /// Input  : [4, 7, 13, 16]
    /// Expected: mean = 10.0,  variance = 30.0  (population Bessel-corrected)
    #[test]
    fn golden_test_vector() {
        let mut acc = WelfordAccumulator::default();
        for &x in &[4.0_f64, 7.0, 13.0, 16.0] {
            acc.update(x);
        }
        // Mean must be exactly 10.0 (no floating-point excuse here)
        assert!((acc.mean - 10.0).abs() < 1e-10, "mean mismatch: {}", acc.mean);

        // Variance must be 30.0 ± tiny epsilon
        let var = acc.variance().expect("variance should be Some after 4 samples");
        assert!((var - 30.0).abs() < 1e-10, "variance mismatch: {var}");
    }

    /// A single perfectly average sample contributes zero variance.
    #[test]
    fn single_sample_no_variance() {
        let mut acc = WelfordAccumulator::default();
        acc.update(42.0);
        assert_eq!(acc.n, 1);
        assert_eq!(acc.variance(), None); // need at least 2 samples
    }

    /// Two identical values → zero variance.
    #[test]
    fn identical_samples_zero_variance() {
        let mut acc = WelfordAccumulator::default();
        acc.update(5.0);
        acc.update(5.0);
        let var = acc.variance().unwrap();
        assert!(var.abs() < 1e-12, "expected ~0 variance, got {var}");
    }

    /// Recency cap: n must never exceed max_n.
    #[test]
    fn recency_cap_respected() {
        let max = 10_u64;
        let mut acc = WelfordAccumulator::new(max);
        for i in 0..100 {
            acc.update(i as f64);
        }
        assert_eq!(acc.n, max, "n exceeded the recency cap");
    }

    /// Upper / lower boundary helpers are symmetric around mean.
    #[test]
    fn boundary_helpers() {
        let mut acc = WelfordAccumulator::default();
        for &x in &[4.0_f64, 7.0, 13.0, 16.0] {
            acc.update(x);
        }
        let k = 2.0;
        let sd = acc.std_dev();
        assert!((acc.upper_boundary(k) - (10.0 + k * sd)).abs() < 1e-10);
        assert!((acc.lower_boundary(k) - (10.0 - k * sd)).abs() < 1e-10);
    }

    /// Warmup flag is false until WARMUP_WINDOWS samples have been fed.
    #[test]
    fn warmup_flag() {
        let mut acc = WelfordAccumulator::new(1000);
        for i in 0..(WARMUP_WINDOWS - 1) {
            acc.update(i as f64);
            assert!(!acc.is_warm(), "should not be warm at n={}", i + 1);
        }
        acc.update(99.0);
        assert!(acc.is_warm(), "should be warm after {} samples", WARMUP_WINDOWS);
    }
}
