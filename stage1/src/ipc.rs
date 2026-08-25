//! The feature vector sent to Stage 2 over a Unix domain socket.
//!
//! 208 bytes, little endian, unpacked in Python with `<22d16s16s`. The full
//! field table is in docs/ipc.md, and any change to it is a change to both
//! stages in the same commit.
//!
//! Fields are written one at a time rather than by transmuting the struct.
//! Rust may insert alignment padding that the Python side cannot know about,
//! and the result would be wrong numbers rather than an error.
//!
//! Stage 2 must be listening before Stage 1 connects, which it does after
//! warm-up.

use byteorder::{LittleEndian, WriteBytesExt};
use log::{debug, info, warn};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

// Constants

/// Default socket path. Stage 2 (Python) must listen on this path.
///
/// The directory is root owned and shared through a group, so a local
/// account cannot race to bind this path ahead of Stage 2 and receive live
/// telemetry or inject fabricated windows.
pub const SOCKET_PATH: &str = "/run/ddos_stage1/stage1.sock";

/// Wire size of one serialised `FeatureVector` in bytes.
/// 22 fields × 8 bytes (f64) = 176 bytes + 16 bytes for dominant IP + 16 bytes for victim IP = 208 bytes.
/// Python format: `struct.unpack('<22d16s16s', data)`
pub const FEATURE_VECTOR_BYTES: usize = 208;

/// Anomaly flag: EWMA rate exceeded upper boundary (volume flood).
/// Kept for logging. Not sent on the wire.
pub const FLAG_RATE_ANOMALY: u8 = 0x01;

/// Anomaly flag: Shannon entropy dropped below lower boundary (concentrated source).
/// Kept for logging. Not sent on the wire.
pub const FLAG_ENTROPY_ANOMALY: u8 = 0x02;

// FeatureVector

/// The data payload handed to Stage 2 after every anomalous window.
///
/// Wire format: 22 × f64 (little-endian) + 16 bytes dominant IP + 16 bytes victim IP = 208 bytes total.
/// Python unpacks with: `struct.unpack('<22d16s16s', data)`
///
/// Field order matches the Python unpack string. Do not reorder.
#[derive(Debug, Clone)]
pub struct FeatureVector {
    /// Shannon entropy of source IPs in the closed window (bits, 0.0–5.64).
    pub entropy: f64,
    /// Current EWMA rate snapshot (packets per second).
    pub ewma_rate: f64,
    /// Running mean of entropy.
    pub mean_h: f64,
    /// Running mean of the rate.
    pub mean_r: f64,
    /// Entropy standard deviation (Welford).
    pub sigma_h: f64,
    /// Rate standard deviation (Welford).
    pub sigma_r: f64,
    /// Legacy/ML proto_ratio: fraction of window packets that were TCP.
    pub proto_ratio: f64,
    /// Fraction of packets from the busiest IP.
    pub dominant_ip_ratio: f64,
    /// Wall-clock time of this window close (seconds since UNIX epoch).
    pub timestamp: f64,
    /// Ratio of TCP packets in window.
    pub proto_tcp: f64,
    /// Ratio of UDP packets in window.
    pub proto_udp: f64,
    /// Ratio of ICMP packets in window.
    pub proto_icmp: f64,
    /// Ratio of SCTP packets in window.
    pub proto_sctp: f64,
    /// Ratio of GRE packets in window.
    pub proto_gre: f64,
    /// Ratio of ESP packets in window.
    pub proto_esp: f64,
    /// Operative anomaly-boundary multiplier for this window (`cfg.k`,
    /// halved during cooldown recovery).
    pub k_multiplier: f64,
    /// Windows remaining in the cooldown recovery period (0..10).
    pub cooldown_counter: f64,
    /// V5: packets per second measured on the egress side for this victim,
    /// i.e. what survived filtering. `-1.0` when no egress sensor is
    /// configured.
    pub egress_rate: f64,
    /// V5: share of arriving traffic that did not reach the victim,
    /// `1 - (egress_rate / ewma_rate)`, clamped to 0.0..1.0. `-1.0` when no
    /// egress sensor is configured, so unknown stays distinguishable from a
    /// genuine 0% drop rate.
    pub drop_ratio: f64,
    /// V7: normalized Shannon entropy of source ports in the closed window.
    /// Invariant under source address forgery, unlike `entropy` above: a
    /// randomized source flood raises `entropy` toward 1.0 and is
    /// undetectable on it alone, but has no reason to touch the port
    /// distribution the same way.
    pub source_port_entropy: f64,
    /// V7: variance of TTL / hop limit values seen in the closed window. A
    /// single real host's traffic clusters on one or two TTLs; a forged or
    /// mixed source flood tends not to.
    pub ttl_variance: f64,
    /// V7: normalized Shannon entropy of TCP SYN fingerprint buckets
    /// (option ordering + window size range, p0f style) in the closed
    /// window. `0.0` when the window had no SYNs to fingerprint, which is
    /// not distinguishable on this field alone from "very low diversity";
    /// see docs/detection.md.
    pub fingerprint_diversity: f64,
    /// The dominant IP address in this window (used for mitigation blocks).
    pub dominant_ip: std::net::IpAddr,
    /// The victim destination IP address.
    pub victim_ip: std::net::IpAddr,
}

impl FeatureVector {
    /// Serialise the feature vector into a fixed-size byte buffer.
    ///
    /// All numeric fields are written as **little-endian f64** to match
    /// Python's `struct.unpack('<22d16s16s', data)` format string exactly.
    ///
    /// # Returns
    /// Exactly 208 bytes, no padding.
    pub fn to_bytes(&self) -> [u8; FEATURE_VECTOR_BYTES] {
        let mut buf = Vec::with_capacity(FEATURE_VECTOR_BYTES);

        // Fields written in the exact order Python expects them.
        buf.write_f64::<LittleEndian>(self.entropy)
            .expect("write entropy");
        buf.write_f64::<LittleEndian>(self.ewma_rate)
            .expect("write ewma_rate");
        buf.write_f64::<LittleEndian>(self.mean_h)
            .expect("write mean_h");
        buf.write_f64::<LittleEndian>(self.mean_r)
            .expect("write mean_r");
        buf.write_f64::<LittleEndian>(self.sigma_h)
            .expect("write sigma_h");
        buf.write_f64::<LittleEndian>(self.sigma_r)
            .expect("write sigma_r");
        buf.write_f64::<LittleEndian>(self.proto_ratio)
            .expect("write proto_ratio");
        buf.write_f64::<LittleEndian>(self.dominant_ip_ratio)
            .expect("write dom_ratio");
        buf.write_f64::<LittleEndian>(self.timestamp)
            .expect("write timestamp");
        buf.write_f64::<LittleEndian>(self.proto_tcp)
            .expect("write proto_tcp");
        buf.write_f64::<LittleEndian>(self.proto_udp)
            .expect("write proto_udp");
        buf.write_f64::<LittleEndian>(self.proto_icmp)
            .expect("write proto_icmp");
        buf.write_f64::<LittleEndian>(self.proto_sctp)
            .expect("write proto_sctp");
        buf.write_f64::<LittleEndian>(self.proto_gre)
            .expect("write proto_gre");
        buf.write_f64::<LittleEndian>(self.proto_esp)
            .expect("write proto_esp");
        buf.write_f64::<LittleEndian>(self.k_multiplier)
            .expect("write k_multiplier");
        buf.write_f64::<LittleEndian>(self.cooldown_counter)
            .expect("write cooldown_counter");
        buf.write_f64::<LittleEndian>(self.egress_rate)
            .expect("write egress_rate");
        buf.write_f64::<LittleEndian>(self.drop_ratio)
            .expect("write drop_ratio");
        buf.write_f64::<LittleEndian>(self.source_port_entropy)
            .expect("write source_port_entropy");
        buf.write_f64::<LittleEndian>(self.ttl_variance)
            .expect("write ttl_variance");
        buf.write_f64::<LittleEndian>(self.fingerprint_diversity)
            .expect("write fingerprint_diversity");

        // Serialize dominant_ip as 16 bytes (IPv6 or IPv6-mapped IPv4 address)
        let ip_v6 = match self.dominant_ip {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            std::net::IpAddr::V6(v6) => v6,
        };
        buf.write_all(&ip_v6.octets())
            .expect("write dominant_ip");

        // Serialize victim_ip as 16 bytes (IPv6 or IPv6-mapped IPv4 address)
        let vic_v6 = match self.victim_ip {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            std::net::IpAddr::V6(v6) => v6,
        };
        buf.write_all(&vic_v6.octets())
            .expect("write victim_ip");

        debug_assert_eq!(buf.len(), FEATURE_VECTOR_BYTES, "serialisation size mismatch");
        buf.try_into().expect("buf has exactly FEATURE_VECTOR_BYTES")
    }
}

// IpcSocket

/// Manages the outbound Unix Domain Socket connection to Stage 2 (Python).
///
/// Stage 1 is the *client*: it connects to a socket that Python has already
/// created and is listening on.  The socket is created lazily on first send
/// so Stage 1 can start capturing before Python is ready.
pub struct IpcSocket {
    /// Underlying connected stream, or `None` if not yet connected.
    stream: Option<UnixStream>,
    /// File-system path of the Unix domain socket.
    path: String,
    /// Whether the last connection attempt already reported a failure.
    ///
    /// Stage 2 being down means every window fails, and a warning per window
    /// buries everything else in the log. The first failure is reported, then
    /// nothing until a connection succeeds again.
    reported_down: bool,
}

impl IpcSocket {
    /// Create a new IPC handle pointing at the default socket path.
    pub fn new() -> Self {
        Self {
            stream: None,
            path: SOCKET_PATH.to_string(),
            reported_down: false,
        }
    }

    /// Create a new IPC handle pointing at a custom socket path (useful for
    /// tests and non-default deployments).
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            stream: None,
            path: path.as_ref().to_string_lossy().into_owned(),
            reported_down: false,
        }
    }

    /// Attempt to connect to the socket if not already connected.
    ///
    /// Returns `true` if the socket is ready to use (already connected, or
    /// just connected now), `false` if it failed. A failure is retried on the
    /// next event rather than blocking.
    pub fn ensure_connected(&mut self) -> bool {
        if self.stream.is_some() {
            return true;
        }

        match UnixStream::connect(&self.path) {
            Ok(stream) => {
                // Set a write timeout so a slow Python process can't stall
                // the Stage 1 analysis thread indefinitely.
                let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                self.stream = Some(stream);
                if self.reported_down {
                    info!("IPC: Stage 2 is back, connected at {}", self.path);
                    self.reported_down = false;
                } else {
                    debug!("IPC: connected to Stage 2 at {}", self.path);
                }
                true
            }
            Err(e) => {
                if !self.reported_down {
                    warn!(
                        "IPC: cannot connect to Stage 2 at {}: {e}. Windows will \
                         keep being analysed but not classified. Further attempts \
                         are not logged until it reconnects.",
                        self.path
                    );
                    self.reported_down = true;
                }
                false
            }
        }
    }

    /// Serialise and send one `FeatureVector` to Stage 2.
    ///
    /// If the send fails (broken pipe, Python crashed, etc.) the socket is
    /// dropped so the next call to `ensure_connected()` will attempt reconnect.
    ///
    /// Returns `true` on success, `false` on any I/O error.
    pub fn send(&mut self, fv: &FeatureVector) -> bool {
        if !self.ensure_connected() {
            return false;
        }

        let bytes = fv.to_bytes();

        if let Some(ref mut stream) = self.stream {
            if let Err(e) = stream.write_all(&bytes) {
                warn!("IPC: write failed: {e}. Dropping connection to reconnect");
                self.stream = None;
                return false;
            }
            debug!(
                "IPC: sent rate={:.1} entropy={:.3} proto_ratio={:.3} ts={:.0}",
                fv.ewma_rate, fv.entropy, fv.proto_ratio, fv.timestamp
            );
            true
        } else {
            false // should not happen given ensure_connected above
        }
    }
}

impl Default for IpcSocket {
    fn default() -> Self {
        Self::new()
    }
}

// Unit Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fv() -> FeatureVector {
        FeatureVector {
            entropy:     4.321,
            ewma_rate:   1234.5,
            mean_h:      4.800,
            mean_r:      900.0,
            sigma_h:     0.250,
            sigma_r:     120.0,
            proto_ratio: 0.72,
            dominant_ip_ratio: 0.66,
            timestamp:   1_700_000_000.0,
            proto_tcp:   0.60,
            proto_udp:   0.20,
            proto_icmp:  0.10,
            proto_sctp:  0.05,
            proto_gre:   0.03,
            proto_esp:   0.02,
            k_multiplier: 1.5,
            cooldown_counter: 7.0,
            egress_rate: 210.5,
            drop_ratio:  0.83,
            source_port_entropy: 0.91,
            ttl_variance: 3.7,
            fingerprint_diversity: 0.44,
            dominant_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 4)),
            victim_ip:   std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 3)),
        }
    }

    /// Serialisation produces exactly FEATURE_VECTOR_BYTES bytes.
    #[test]
    fn serialised_size_is_correct() {
        let bytes = sample_fv().to_bytes();
        assert_eq!(bytes.len(), FEATURE_VECTOR_BYTES);
        assert_eq!(FEATURE_VECTOR_BYTES, 208);
    }

    /// Round-trip: serialise then re-parse with byteorder.
    /// The alignment check, matching what Python does.
    #[test]
    fn round_trip_byte_layout() {
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let fv    = sample_fv();
        let bytes = fv.to_bytes();
        let mut cur = Cursor::new(bytes);

        let entropy           = cur.read_f64::<LittleEndian>().unwrap();
        let ewma_rate         = cur.read_f64::<LittleEndian>().unwrap();
        let mean_h            = cur.read_f64::<LittleEndian>().unwrap();
        let mean_r            = cur.read_f64::<LittleEndian>().unwrap();
        let sigma_h           = cur.read_f64::<LittleEndian>().unwrap();
        let sigma_r           = cur.read_f64::<LittleEndian>().unwrap();
        let proto_ratio       = cur.read_f64::<LittleEndian>().unwrap();
        let dominant_ip_ratio = cur.read_f64::<LittleEndian>().unwrap();
        let timestamp         = cur.read_f64::<LittleEndian>().unwrap();
        let proto_tcp         = cur.read_f64::<LittleEndian>().unwrap();
        let proto_udp         = cur.read_f64::<LittleEndian>().unwrap();
        let proto_icmp        = cur.read_f64::<LittleEndian>().unwrap();
        let proto_sctp        = cur.read_f64::<LittleEndian>().unwrap();
        let proto_gre         = cur.read_f64::<LittleEndian>().unwrap();
        let proto_esp         = cur.read_f64::<LittleEndian>().unwrap();
        let k_multiplier      = cur.read_f64::<LittleEndian>().unwrap();
        let cooldown_counter  = cur.read_f64::<LittleEndian>().unwrap();
        let egress_rate       = cur.read_f64::<LittleEndian>().unwrap();
        let drop_ratio        = cur.read_f64::<LittleEndian>().unwrap();
        let source_port_entropy   = cur.read_f64::<LittleEndian>().unwrap();
        let ttl_variance          = cur.read_f64::<LittleEndian>().unwrap();
        let fingerprint_diversity = cur.read_f64::<LittleEndian>().unwrap();

        let mut ip_bytes = [0u8; 16];
        std::io::Read::read_exact(&mut cur, &mut ip_bytes).unwrap();
        let dominant_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes));

        let mut vic_bytes = [0u8; 16];
        std::io::Read::read_exact(&mut cur, &mut vic_bytes).unwrap();
        let victim_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(vic_bytes));

        assert!((entropy           - 4.321           ).abs() < 1e-9);
        assert!((ewma_rate         - 1234.5          ).abs() < 1e-9);
        assert!((mean_h            - 4.800           ).abs() < 1e-9);
        assert!((mean_r            - 900.0           ).abs() < 1e-9);
        assert!((sigma_h           - 0.250           ).abs() < 1e-9);
        assert!((sigma_r           - 120.0           ).abs() < 1e-9);
        assert!((proto_ratio       - 0.72            ).abs() < 1e-9);
        assert!((dominant_ip_ratio - 0.66            ).abs() < 1e-9);
        assert!((timestamp         - 1_700_000_000.0 ).abs() < 1e-3);
        assert!((proto_tcp         - 0.60            ).abs() < 1e-9);
        assert!((proto_udp         - 0.20            ).abs() < 1e-9);
        assert!((proto_icmp        - 0.10            ).abs() < 1e-9);
        assert!((proto_sctp        - 0.05            ).abs() < 1e-9);
        assert!((proto_gre         - 0.03            ).abs() < 1e-9);
        assert!((proto_esp         - 0.02            ).abs() < 1e-9);
        assert!((k_multiplier     - 1.5              ).abs() < 1e-9);
        assert!((cooldown_counter - 7.0              ).abs() < 1e-9);
        assert!((egress_rate      - 210.5            ).abs() < 1e-9);
        assert!((drop_ratio       - 0.83             ).abs() < 1e-9);
        assert!((source_port_entropy   - 0.91).abs() < 1e-9);
        assert!((ttl_variance          - 3.7 ).abs() < 1e-9);
        assert!((fingerprint_diversity - 0.44).abs() < 1e-9);
        assert_eq!(dominant_ip, std::net::IpAddr::V6(std::net::Ipv4Addr::new(192, 168, 1, 4).to_ipv6_mapped()));
        assert_eq!(victim_ip, std::net::IpAddr::V6(std::net::Ipv4Addr::new(10, 0, 0, 3).to_ipv6_mapped()));
    }

    /// FLAG constants must not overlap.
    #[test]
    fn flag_constants_are_disjoint() {
        assert_ne!(FLAG_RATE_ANOMALY & FLAG_ENTROPY_ANOMALY, 0xFF);
        assert_eq!(FLAG_RATE_ANOMALY & FLAG_ENTROPY_ANOMALY, 0x00);
    }
}
