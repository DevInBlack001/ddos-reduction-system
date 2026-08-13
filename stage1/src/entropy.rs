//! Normalized Shannon entropy of the source address distribution in one
//! window.
//!
//!     H      = -sum( p(x) * log2(p(x)) )
//!     H_norm = H / log2(unique_sources)
//!
//! Normalizing matters because window size varies with traffic rate, and the
//! number of sources observable depends on it. The normalized value measures
//! concentration on a [0, 1] scale regardless: 0.0 is all packets from one
//! address, 1.0 is a perfectly even spread.
//!
//! Counting unique addresses would not do. Ten addresses where one appears 41
//! times and ten where each appears five times have the same cardinality and
//! completely different shapes.
//!
//! Recomputed from scratch each window, then cleared. Entropy describes this
//! window, not a trend; the trend lives in the accumulator upstream.
//!
//! Returns 0.0 when there is at most one source, which avoids dividing by
//! log2(1).

use std::{collections::HashMap, net::IpAddr};

/// Minimum number of packets required for a statistically meaningful entropy
/// calculation.  Windows closing with fewer packets than this (e.g. during
/// the 1.0s hard-cap in very low traffic) should be treated with caution.
pub const MIN_PACKETS_FOR_ENTROPY: usize = 20;

// EntropyAccumulator

/// Accumulates source IPs over one window and computes Normalized Shannon
/// Entropy on close.
///
/// Lifecycle per window:
///   1. Call `add_packet(src_ip)` for each arriving packet (no cap).
///   2. When the analysis loop's close condition fires, call
///      `compute_and_reset()`.
///   3. The returned `f64` is the normalized entropy scalar `h` ∈ [0, 1].
///   4. The HashMap and counter are cleared internally by `compute_and_reset()`.
#[derive(Debug, Default)]
pub struct EntropyAccumulator {
    /// Frequency count of each unique source IP seen in the current window.
    /// Cleared after every `compute_and_reset()` call.
    counts: HashMap<IpAddr, u32>,
    /// Number of packets accumulated in the current window (unbounded).
    packet_count: usize,
}

impl EntropyAccumulator {
    /// Create a new, empty accumulator (window not started yet).
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one packet's source IP in the current window.
    ///
    /// Must be called per-packet from the analysis thread's main loop.
    /// The accumulator grows as needed. The close
    /// decision is made by the analysis loop based on elapsed time and
    /// minimum packet count, not by this accumulator.
    pub fn add_packet(&mut self, src_ip: IpAddr) {
        self.add_packets(src_ip, 1);
    }

    /// Record `count` packets from one source at once.
    ///
    /// The kernel backend arrives with counts already totalled per source, so
    /// adding them one at a time would put a per packet loop back into user
    /// space, which is the cost the backend exists to remove.
    pub fn add_packets(&mut self, src_ip: IpAddr, count: u32) {
        if count == 0 {
            return;
        }
        *self.counts.entry(src_ip).or_insert(0) += count;
        self.packet_count += count as usize;
    }

    /// Compute Normalized Shannon Entropy over the current window, then
    /// reset state.
    ///
    /// # Returns
    /// The normalized entropy scalar `h` in range `[0.0, 1.0]`.
    /// Returns `0.0` if the window has ≤1 unique source (guard against
    /// division by log₂(1) = 0).
    ///
    /// # Side Effect
    /// Clears `self.counts` and resets `self.packet_count` to zero so the
    /// accumulator is ready for the next window immediately.
    pub fn compute_and_reset(&mut self) -> f64 {
        let h = compute_normalized_entropy(&self.counts, self.packet_count);
        // Clearing rather than reallocating keeps the allocation
        // alive to avoid repeated heap allocations across windows.
        self.counts.clear();
        self.packet_count = 0;
        h
    }

    /// Peek at the current packet count without consuming the window.
    /// Useful for the analysis thread's progress logging and close decisions.
    pub fn packet_count(&self) -> usize {
        self.packet_count
    }
}


/// Compute Normalized Shannon Entropy from a frequency map and total packet
/// count.
///
/// H_norm = H(X) / log₂(|unique IPs|)
///
/// where H(X) = −Σ p(xᵢ) · log₂(p(xᵢ))
///       p(xᵢ) = count(xᵢ) / total_packets
///
/// This is a standalone pure function so unit tests can drive it directly
/// with crafted frequency maps without needing an `EntropyAccumulator`.
///
/// # Arguments
/// `counts` maps each address to its frequency, `total_packets` is their sum.
///
/// # Returns
/// Normalized entropy in [0.0, 1.0].
/// Returns `0.0` if `total_packets` is 0 or if there is only 1 unique source.
pub fn compute_normalized_entropy(counts: &HashMap<IpAddr, u32>, total_packets: usize) -> f64 {
    if total_packets == 0 {
        return 0.0;
    }

    let unique_sources = counts.len();

    // Guard: ≤1 unique source → entropy is definitionally 0.0.
    // Also avoids log₂(1) = 0.0 → division by zero.
    if unique_sources <= 1 {
        return 0.0;
    }

    let n = total_packets as f64;

    let raw_entropy: f64 = counts
        .values()
        .filter(|&&c| c > 0) // defensive: skip zero-count entries
        .map(|&c| {
            // Probability of this IP class in the current window.
            let p = c as f64 / n;
            // Each term of the Shannon sum: −p · log₂(p).
            // log₂(0) would be −∞, but p > 0 is guaranteed by the filter above.
            -p * p.log2()
        })
        .sum();

    // Normalize by maximum achievable entropy for this many unique sources.
    let max_entropy = (unique_sources as f64).log2();

    raw_entropy / max_entropy
}

// Unit Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};


    #[test]
    fn adding_in_bulk_matches_adding_one_at_a_time() {
        // The two backends use different arms of this, so they have to agree
        // exactly or the same traffic would score different entropy.
        let mut one_at_a_time = EntropyAccumulator::new();
        for _ in 0..40 {
            one_at_a_time.add_packet(ip(198, 51, 100, 1));
        }
        for _ in 0..10 {
            one_at_a_time.add_packet(ip(198, 51, 100, 2));
        }

        let mut bulk = EntropyAccumulator::new();
        bulk.add_packets(ip(198, 51, 100, 1), 40);
        bulk.add_packets(ip(198, 51, 100, 2), 10);

        assert_eq!(one_at_a_time.packet_count(), bulk.packet_count());
        assert_eq!(one_at_a_time.compute_and_reset(), bulk.compute_and_reset());
    }

    #[test]
    fn a_bulk_add_of_zero_changes_nothing() {
        let mut acc = EntropyAccumulator::new();
        acc.add_packets(ip(198, 51, 100, 1), 5);
        acc.add_packets(ip(198, 51, 100, 2), 0);
        // A source contributing no packets must not become a bucket, which
        // would raise the unique count and change the normalisation.
        assert_eq!(acc.packet_count(), 5);
        assert_eq!(acc.compute_and_reset(), 0.0);
    }

    #[test]
    fn bulk_adds_accumulate_across_calls() {
        let mut acc = EntropyAccumulator::new();
        acc.add_packets(ip(198, 51, 100, 1), 3);
        acc.add_packets(ip(198, 51, 100, 1), 4);
        assert_eq!(acc.packet_count(), 7);
    }

    /// Helper to build an IpAddr::V4 quickly in tests.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // compute_normalized_entropy pure function tests

    /// All packets from a single IP → entropy must be exactly 0.0.
    #[test]
    fn single_source_zero_entropy() {
        let mut counts = HashMap::new();
        counts.insert(ip(1, 0, 0, 1), 50);
        let h = compute_normalized_entropy(&counts, 50);
        assert!(
            h.abs() < 1e-10,
            "single-source entropy should be 0.0, got {h}"
        );
    }

    /// All 50 packets from 50 unique IPs → maximum normalized entropy = 1.0.
    #[test]
    fn uniform_distribution_maximum_entropy() {
        let mut counts = HashMap::new();
        for i in 0..50_u8 {
            counts.insert(ip(10, 0, 0, i), 1);
        }
        let h = compute_normalized_entropy(&counts, 50);
        assert!(
            (h - 1.0).abs() < 1e-6,
            "uniform normalized entropy should be 1.0, got {h:.6}"
        );
    }

    /// Two equally likely IPs → normalized entropy = 1.0 (maximum for 2 sources).
    #[test]
    fn two_equal_sources_normalized_one() {
        let mut counts = HashMap::new();
        counts.insert(ip(192, 168, 1, 1), 25);
        counts.insert(ip(192, 168, 1, 2), 25);
        let h = compute_normalized_entropy(&counts, 50);
        assert!(
            (h - 1.0).abs() < 1e-10,
            "expected normalized 1.0 for 2 equal sources, got {h}"
        );
    }

    /// Two sources, one dominant (49 vs 1) → low normalized entropy.
    #[test]
    fn two_sources_skewed_low_entropy() {
        let mut counts = HashMap::new();
        counts.insert(ip(10, 0, 0, 1), 49);
        counts.insert(ip(10, 0, 0, 2), 1);
        let h = compute_normalized_entropy(&counts, 50);
        assert!(
            h > 0.0 && h < 0.2,
            "skewed 2-source entropy should be low but non-zero, got {h}"
        );
    }

    /// Empty map → 0.0 (no divide-by-zero).
    #[test]
    fn empty_window_returns_zero() {
        let counts = HashMap::new();
        let h = compute_normalized_entropy(&counts, 0);
        assert_eq!(h, 0.0);
    }

    /// Large window (15,000 packets) from 50 uniform sources → still 1.0.
    /// This verifies normalization decouples entropy from window size.
    #[test]
    fn large_window_uniform_still_one() {
        let mut counts = HashMap::new();
        for i in 0..50_u8 {
            counts.insert(ip(10, 0, 0, i), 300); // 50 × 300 = 15,000
        }
        let h = compute_normalized_entropy(&counts, 15_000);
        assert!(
            (h - 1.0).abs() < 1e-6,
            "large-window uniform normalized entropy should be 1.0, got {h:.6}"
        );
    }

    /// Same 50 sources in small (50-pkt) and large (15,000-pkt) windows
    /// must produce the same normalized entropy, which is rate independence.
    #[test]
    fn entropy_is_rate_independent() {
        let mut counts_small = HashMap::new();
        let mut counts_large = HashMap::new();
        for i in 0..50_u8 {
            counts_small.insert(ip(10, 0, 0, i), 1);
            counts_large.insert(ip(10, 0, 0, i), 300);
        }
        let h_small = compute_normalized_entropy(&counts_small, 50);
        let h_large = compute_normalized_entropy(&counts_large, 15_000);
        assert!(
            (h_small - h_large).abs() < 1e-6,
            "entropy should be rate-independent: small={h_small:.6}, large={h_large:.6}"
        );
    }

    // EntropyAccumulator integration tests

    /// Window fills and compute_and_reset returns expected scalar.
    #[test]
    fn accumulator_fills_and_resets() {
        let mut acc = EntropyAccumulator::new();

        // Feed 50 packets from 2 IPs (25 each) → normalized = 1.0 for 2 sources.
        for i in 0..50 {
            let src = if i < 25 { ip(10, 0, 0, 1) } else { ip(10, 0, 0, 2) };
            acc.add_packet(src);
        }

        let h = acc.compute_and_reset();
        assert!((h - 1.0).abs() < 1e-10, "expected 1.0, got {h}");

        // After reset: window must be empty and ready for next window.
        assert_eq!(acc.packet_count(), 0);
    }

    /// Accumulator accepts more than 50 packets (no cap).
    #[test]
    fn no_packet_cap() {
        let mut acc = EntropyAccumulator::new();
        let src = ip(172, 16, 0, 1);
        for _ in 0..200 {
            acc.add_packet(src);
        }
        // All 200 packets should be counted.
        assert_eq!(acc.packet_count(), 200);
    }

    /// Back-to-back windows work correctly (reset clears state fully).
    #[test]
    fn two_consecutive_windows() {
        let mut acc = EntropyAccumulator::new();

        // Window 1: all from one IP → entropy = 0.
        for _ in 0..50 {
            acc.add_packet(ip(1, 1, 1, 1));
        }
        let h1 = acc.compute_and_reset();
        assert!(h1.abs() < 1e-10, "window 1 entropy should be 0.0, got {h1}");

        // Window 2: uniform 50 unique IPs → entropy = 1.0.
        for i in 0..50_u8 {
            acc.add_packet(ip(2, 0, 0, i));
        }
        let h2 = acc.compute_and_reset();
        assert!(
            (h2 - 1.0).abs() < 1e-6,
            "window 2 normalized entropy should be 1.0, got {h2}"
        );
    }
}
