//! Saving and restoring each protected host's baseline across restarts.
//!
//! The point is not avoiding a fresh warm-up. It is that a restart during an
//! attack would otherwise build "normal" out of attack traffic, with no
//! peacetime reference to anchor it.
//!
//! Only clean windows are saved. The call site is the same gate that decides
//! whether to feed a sample into the accumulator live, so the file on disk can
//! never be a mid attack snapshot.
//!
//! Loading enforces a TTL. The live recency cap already treats anything older
//! than a few minutes of traffic as not fully trustworthy, and a baseline
//! hours old risks belonging to a different part of the daily cycle.
//!
//! Writes are atomic, a temporary file then a rename, so an interrupted write
//! leaves the previous complete file. A missing, corrupt, or expired file is
//! treated as no prior baseline.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default location. Under /var/lib because this file exists
/// specifically to survive a reboot, and /tmp is not guaranteed to.
pub const DEFAULT_BASELINE_PATH: &str = "/var/lib/ddos_stage1/baselines.json";

/// Default staleness cutoff: 1 hour. See module docs for why this is much
/// shorter than keeping it forever, sized for realistic restarts
/// (crash loops, redeploys, brief reboots) without risking a stale or
/// diurnally-mismatched baseline being trusted as current.
pub const DEFAULT_TTL_SECS: f64 = 3600.0;

/// Minimum wall-clock gap between saves, regardless of how many clean
/// windows close in between. Bounds disk I/O; also bounds how much state
/// could ever be lost to an unannounced power loss (worst case: this many
/// seconds of drift, never the whole baseline).
pub const SAVE_INTERVAL_SECS: f64 = 45.0;

/// One victim's persisted baseline. Field names intentionally mirror
/// `WelfordAccumulator`'s public fields directly so restoring is a plain
/// struct-literal assignment, not a translation layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedBaseline {
    pub rate_n: u64,
    pub rate_mean: f64,
    pub rate_m2: f64,
    pub entropy_n: u64,
    pub entropy_mean: f64,
    pub entropy_m2: f64,
    pub ewma_rate: f64,
    pub cooldown_counter: usize,
    pub peacetime_rate_ref: Option<f64>,
    pub peacetime_entropy_ref: Option<f64>,
}

/// The full on-disk file: one timestamp for the whole snapshot (simpler and
/// sufficient, since every target is saved on the same tick)
/// plus a map of victim IP (as a string; IpAddr isn't a valid JSON object
/// key without a custom serializer) to that victim's baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    /// UNIX timestamp (seconds) this snapshot was written.
    pub saved_at: f64,
    pub victims: HashMap<String, PersistedBaseline>,
}

impl PersistedState {
    pub fn new() -> Self {
        Self {
            saved_at: now_unix(),
            victims: HashMap::new(),
        }
    }
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Atomically write `state` to `path`, a temporary file then a rename (see
/// for why). Best-effort: logs and returns on any I/O error rather than
/// panicking, since a failed save should never take down the analysis
/// thread.
pub fn save(path: &str, state: &PersistedState) {
    let json = match serde_json::to_string_pretty(state) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("Persistence: failed to serialise baseline state: {e}");
            return;
        }
    };

    let tmp_path = format!("{path}.tmp");
    match std::fs::File::create(&tmp_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(json.as_bytes()) {
                log::warn!("Persistence: failed to write '{tmp_path}': {e}");
                return;
            }
            if let Err(e) = std::fs::rename(&tmp_path, path) {
                log::warn!("Persistence: failed to rename '{tmp_path}' -> '{path}': {e}");
            } else {
                log::debug!("Persistence: saved baseline snapshot ({} victims) to '{path}'", state.victims.len());
            }
        }
        Err(e) => {
            log::warn!(
                "Persistence: failed to open '{tmp_path}' for writing: {e}. Does the parent \
                 directory exist and is it writable? (default: /var/lib/ddos_stage1/)"
            );
        }
    }
}

/// Load a persisted baseline file, applying the TTL cutoff. Returns `None`
/// (with an explanatory log line) if the file doesn't exist, fails to parse,
/// or is older than `ttl_secs`. All three are treated identically: fall
/// back to a fresh warm-up, never error out.
pub fn load(path: &str, ttl_secs: f64) -> Option<PersistedState> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            log::info!("Persistence: no baseline file at '{path}' ({e}). Starting fresh.");
            return None;
        }
    };

    let state: PersistedState = match serde_json::from_str(&contents) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Persistence: '{path}' exists but failed to parse ({e}). Starting fresh.");
            return None;
        }
    };

    let age = now_unix() - state.saved_at;
    if age > ttl_secs {
        log::info!(
            "Persistence: baseline in '{path}' is {age:.0}s old, older than the {ttl_secs:.0}s TTL \
             Starting fresh rather than trusting a stale baseline."
        );
        return None;
    }

    log::info!(
        "Persistence: loaded baseline for {} victim(s) from '{path}' (age {age:.0}s).",
        state.victims.len()
    );
    Some(state)
}

/// Look up one victim's persisted baseline by IP, if present in a loaded
/// `PersistedState`. Keyed by string since that's how it's stored on disk.
pub fn lookup(state: &Option<PersistedState>, ip: &IpAddr) -> Option<PersistedBaseline> {
    state.as_ref()?.victims.get(&ip.to_string()).cloned()
}

// Unit Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_baseline() -> PersistedBaseline {
        PersistedBaseline {
            rate_n: 250,
            rate_mean: 842.3,
            rate_m2: 1200.5,
            entropy_n: 250,
            entropy_mean: 0.91,
            entropy_m2: 0.02,
            ewma_rate: 850.1,
            cooldown_counter: 0,
            peacetime_rate_ref: Some(840.0),
            peacetime_entropy_ref: Some(0.90),
        }
    }

    /// Round-trip: save then load must reproduce the same values.
    #[test]
    fn round_trip_save_and_load() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ddos_baseline_test_{}.json", std::process::id()));
        let path_str = path.to_str().unwrap();

        let mut state = PersistedState::new();
        state.victims.insert("10.0.0.3".to_string(), sample_baseline());

        save(path_str, &state);
        let loaded = load(path_str, 3600.0).expect("should load what was just saved");

        let restored = loaded.victims.get("10.0.0.3").expect("victim should be present");
        assert_eq!(restored.rate_n, 250);
        assert!((restored.rate_mean - 842.3).abs() < 1e-9);
        assert_eq!(restored.peacetime_rate_ref, Some(840.0));

        let _ = std::fs::remove_file(path_str);
    }

    /// A file older than the TTL must be rejected, not silently trusted.
    #[test]
    fn stale_file_is_rejected() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ddos_baseline_test_stale_{}.json", std::process::id()));
        let path_str = path.to_str().unwrap();

        let mut state = PersistedState::new();
        state.saved_at = now_unix() - 7200.0; // 2 hours old
        state.victims.insert("10.0.0.3".to_string(), sample_baseline());
        save(path_str, &state);

        let loaded = load(path_str, DEFAULT_TTL_SECS); // 1h TTL
        assert!(loaded.is_none(), "a 2-hour-old file must be rejected by a 1-hour TTL");

        let _ = std::fs::remove_file(path_str);
    }

    /// Missing file must return None, not panic or error.
    #[test]
    fn missing_file_returns_none() {
        let loaded = load("/nonexistent/path/that/should/never/exist.json", 3600.0);
        assert!(loaded.is_none());
    }

    /// Corrupt/non-JSON file must return None, not panic.
    #[test]
    fn corrupt_file_returns_none() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ddos_baseline_test_corrupt_{}.json", std::process::id()));
        let path_str = path.to_str().unwrap();
        std::fs::write(path_str, b"not valid json {{{").unwrap();

        let loaded = load(path_str, 3600.0);
        assert!(loaded.is_none());

        let _ = std::fs::remove_file(path_str);
    }
}
