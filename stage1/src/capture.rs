//! Packet capture.
//!
//! Opens a pcap handle on an interface, applies a BPF filter so the kernel
//! discards anything not addressed to a protected host, parses the headers,
//! and sends the result to the analysis thread over a bounded channel.
//!
//! Capture runs in its own thread so a window close never stalls it. The
//! channel is bounded, so a slow analysis thread blocks capture rather than
//! growing memory without limit.
//!
//! Only header fields are read. The payload is never copied into user space.

use crossbeam_channel::Sender;
use etherparse::{LaxNetSlice, LaxSlicedPacket, TcpOptionElement, TcpSlice, TransportSlice};
use log::{debug, error, info, warn};
use pcap::{Capture, Device};
use std::{net::IpAddr, time::Instant};

/// Depth of the channel between capture and analysis. Once full, capture
/// blocks instead of queueing without limit.
pub const CHANNEL_CAPACITY: usize = 1024;

/// Layer 4 protocol from the IP header. Anything not tracked separately
/// folds into `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Sctp,
    Gre,
    Esp,
    Other,
}

/// Which side of the gateway a packet was seen on. Only ingress feeds
/// detection; egress exists to measure how much traffic was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Ingress,
    Egress,
}

/// What the capture thread sends to the analysis thread. Kept small: it
/// crosses the channel once per packet.
#[derive(Debug, Clone)]
pub struct PacketMeta {
    /// Which capture thread produced this record.
    pub direction: Direction,
    /// Source address from the IP header.
    pub src_ip: IpAddr,
    /// Destination address from the IP header.
    pub dst_ip: IpAddr,
    /// Monotonic timestamp taken as soon as pcap hands the frame over.
    #[allow(dead_code)]
    pub arrived_at: Instant,
    /// Layer 4 protocol, used to build the protocol ratios.
    pub protocol: Protocol,
    /// Destination port, 0 when the protocol has none.
    pub dst_port: u16,
    /// Source port, 0 when the protocol has none. V7's port entropy feature.
    pub source_port: u16,
    /// IPv4 TTL or IPv6 hop limit. V7's TTL variance feature.
    pub ttl: u8,
    /// V7's TCP fingerprint diversity feature. `None` for anything that
    /// is not a TCP SYN: fingerprinting is a SYN only technique (p0f
    /// style), and forcing every other packet into some bucket would mix
    /// "not applicable" with a real, if unusual, all zero fingerprint.
    pub fingerprint_bucket: Option<u8>,
}

/// Number of buckets in `FINGERPRINT_HIST` / `stage1-ebpf`'s
/// `FINGERPRINT_HIST` map. Matched on both backends so a fingerprint
/// bucket means the same thing regardless of which one produced it.
pub const FINGERPRINT_BUCKETS: usize = 64;

/// Which non padding TCP options were present on a SYN, order insensitive.
///
/// Order alone would need a much larger table for a modest diversity gain
/// over presence, and this codebase's own precedent (the sigma floor, the
/// entropy floor) is to start with the simplest thing that is not obviously
/// wrong and revisit once there is real data to justify more. NOP is
/// padding, not a distinguishing option, and is not counted.
const OPT_MSS: u8 = 1 << 0;
const OPT_WSCALE: u8 = 1 << 1;
const OPT_SACK: u8 = 1 << 2;
const OPT_TIMESTAMP: u8 = 1 << 3;

/// Reduce a TCP SYN's options and window size to one of `FINGERPRINT_BUCKETS`
/// small fixed buckets: 4 bits of option presence, 2 bits of window size
/// range, one number, no unbounded hashing of raw option bytes.
fn fingerprint_bucket(tcp: &TcpSlice) -> u8 {
    let mut presence = 0u8;
    for opt in tcp.options_iterator().flatten() {
        presence |= match opt {
            TcpOptionElement::MaximumSegmentSize(_) => OPT_MSS,
            TcpOptionElement::WindowScale(_) => OPT_WSCALE,
            TcpOptionElement::SelectiveAcknowledgementPermitted
            | TcpOptionElement::SelectiveAcknowledgement(..) => OPT_SACK,
            TcpOptionElement::Timestamp(..) => OPT_TIMESTAMP,
            TcpOptionElement::Noop => 0,
        };
    }

    let window_bucket = match tcp.window_size() {
        0 => 0u8,
        1..=8192 => 1,
        8193..=32768 => 2,
        _ => 3,
    };

    let bucket = presence | (window_bucket << 4);
    // Guards the invariant this function's bit widths exist to keep: the
    // result must fit stage1-ebpf's FINGERPRINT_HIST map, sized to
    // FINGERPRINT_BUCKETS on the other backend.
    debug_assert!((bucket as usize) < FINGERPRINT_BUCKETS);
    bucket
}

/// Runtime parameters for one capture thread.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Network interface to capture on (e.g., `"br0"`, `"eth0"`, `"ens3"`).
    pub interface: String,
    /// BPF filter string applied at the kernel level.
    /// Should be `"dst host <victim_ip> and ip"` in production.
    /// The `and ip` clause restricts capture to IPv4 frames only, preventing
    /// ARP, IPv6, and other non-IPv4 frames from reaching etherparse.
    /// Set to `""` (empty string) to disable filtering (dev/test only).
    pub bpf_filter: String,
    /// How many bytes of each frame are copied to user space. 256 covers
    /// Ethernet, VLAN tags, IPv6 with extension headers, and a TCP header.
    /// The payload is cut off, which is why parsing is lax.
    pub snaplen: i32,
    /// pcap buffer flush timeout in milliseconds.
    /// Lower values reduce latency between packet arrival and delivery to Rust.
    /// Higher values allow the kernel to batch more packets per wakeup.
    pub timeout_ms: i32,
    /// Set to `true` to enable pcap promiscuous mode (capture all frames,
    /// not just those addressed to this interface's MAC).
    /// Required when running on a bridge (`br0`) that sees others' traffic.
    pub promiscuous: bool,
    /// Which side this capture thread is watching. Stamped onto every
    /// `PacketMeta` it emits.
    pub direction: Direction,
}

impl CaptureConfig {
    /// Production-ready defaults for a bridge interface.
    ///
    /// `interface` is the bridge name, `victim_ip` the protected host.
    #[allow(dead_code)]
    pub fn for_bridge(interface: &str, victim_ip: &str) -> Self {
        Self {
            interface:   interface.to_string(),
            // Restrict to IPv4 frames destined for the victim.
            // 'and ip' blocks ARP, IPv6, and other non-IPv4 frames before they
            // reach etherparse, eliminating the skip storm seen under Locust load.
            // VLAN branch handles environments with 802.1Q-tagged frames.
            bpf_filter:  format!("(dst host {victim_ip} and ip) or (vlan and dst host {victim_ip} and ip)"),
            snaplen:     256,   // Headers only; payload is not read.
            timeout_ms:  100,   // 100 ms flush window (prevents Linux TPACKET ring buffer packet drops)
            promiscuous: true,  // bridge must see all passing frames
            direction:   Direction::Ingress,
        }
    }

    /// Minimal config for local testing without a BPF filter.
    pub fn for_test(interface: &str) -> Self {
        Self {
            interface:   interface.to_string(),
            bpf_filter:  String::new(),
            snaplen:     256,   // Headers only; payload is not read.
            timeout_ms:  100,
            promiscuous: true,  // Enable promiscuous mode to capture bridged transit traffic
            direction:   Direction::Ingress,
        }
    }

    /// Build BPF filter and capture configuration for multiple victim targets.
    ///
    /// Called once per side: the ingress and egress threads use the same
    /// victim filter, since the traffic of interest is what is headed to
    /// those victims either way.
    pub fn for_targets(interface: &str, targets: &crate::VictimTargets, direction: Direction) -> Self {
        let filter = match targets {
            crate::VictimTargets::List(ips) => {
                let hosts = ips.iter().map(|ip| format!("dst host {ip}")).collect::<Vec<_>>().join(" or ");
                format!("(({hosts}) and ip) or (vlan and ({hosts}) and ip)")
            }
            crate::VictimTargets::Subnet { ip, prefix } => {
                let net = format!("{ip}/{prefix}");
                format!("(dst net {net} and ip) or (vlan and dst net {net} and ip)")
            }
        };
        Self {
            interface:   interface.to_string(),
            bpf_filter:  filter,
            snaplen:     256,
            timeout_ms:  100,
            promiscuous: true,
            direction,
        }
    }
}

/// Open a pcap capture on `cfg.interface`, apply the BPF filter, and forward
/// parsed `PacketMeta` records into `tx` indefinitely.
///
/// This function *blocks forever* and is intended to be called from within a
/// dedicated `std::thread::spawn()` closure. It returns only if:
///   • A fatal pcap error occurs (logged at ERROR level).
///   • The `tx` sender is dropped (analysis thread exited).
///
/// Returns early on a pcap open or filter failure. Malformed packets are
/// counted and skipped.
pub fn run_capture_thread(cfg: CaptureConfig, tx: Sender<PacketMeta>) {
    // Open the pcap capture handle on the specified interface.
    info!("Capture: opening interface '{}' (promiscuous={})", cfg.interface, cfg.promiscuous);

    let mut cap = match Capture::from_device(cfg.interface.as_str()) {
        Ok(inactive) => {
            // Configure before activating.
            let inactive = inactive
                .snaplen(cfg.snaplen)
                .timeout(cfg.timeout_ms)
                .promisc(cfg.promiscuous)
                .immediate_mode(true) // Deliver packets immediately instead of batching to prevent delay
                .buffer_size(128 * 1024 * 1024); // 128MB buffer to prevent OS packet drops under flood

            match inactive.open() {
                Ok(c) => c,
                Err(e) => {
                    error!("Capture: failed to open device '{}': {e}", cfg.interface);
                    return;
                }
            }
        }
        Err(e) => {
            error!("Capture: device '{}' not found: {e}", cfg.interface);
            // List available devices to help with diagnostics.
            if let Ok(devices) = Device::list() {
                let names: Vec<_> = devices.iter().map(|d| d.name.as_str()).collect();
                error!("Capture: available interfaces: {}", names.join(", "));
            }
            return;
        }
    };

    // Apply the BPF filter (kernel-level, before Rust sees anything).
    if !cfg.bpf_filter.is_empty() {
        info!("Capture: applying BPF filter: '{}'", cfg.bpf_filter);
        if let Err(e) = cap.filter(&cfg.bpf_filter, true) {
            error!("Capture: BPF filter '{}' failed: {e}", cfg.bpf_filter);
            return;
        }
    } else {
        warn!("Capture: no BPF filter applied, all traffic will be processed (dev mode)");
    }

    // Log the datalink type (e.g. ETHERNET, LINUX_SLL) to detect parsing issues
    let linktype = cap.get_datalink();
    info!("Capture: interface '{}' datalink type is {:?}", cfg.interface, linktype);
    if linktype != pcap::Linktype::ETHERNET {
        warn!("Capture: interface linktype is NOT Ethernet. Packet parsing will fail unless standard Ethernet headers are present.");
    }

    info!("Capture: capture loop started on '{}'", cfg.interface);

    // Runs until the channel closes or pcap errors.
    let mut packet_count: u64 = 0;
    let mut total_raw_packets: u64 = 0;
    let mut total_timeouts: u64 = 0;
    // Split out why frames never reach analysis, so a gap between
    // raw_captured and forwarded points at a cause instead of a mystery.
    let mut parse_failed: u64 = 0;
    let mut non_ip: u64 = 0;
    // Frames whose payload was cut short by snaplen. Counted, not discarded.
    let mut truncated: u64 = 0;
    let mut last_status_time = Instant::now();

    loop {
        // Periodic progress status update (every 5 seconds)
        let now = Instant::now();
        if now.duration_since(last_status_time).as_secs() >= 5 {
            info!(
                "Capture: status | interface={} | raw_captured={} | timeouts={} | parse_failed={} | non_ip={} | truncated={} | forwarded={}",
                cfg.interface, total_raw_packets, total_timeouts, parse_failed, non_ip, truncated, packet_count
            );
            last_status_time = now;
        }

        // Retrieve the next raw frame from the pcap ring buffer.
        let raw = match cap.next_packet() {
            Ok(p) => {
                total_raw_packets += 1;
                p
            }
            Err(pcap::Error::TimeoutExpired) => {
                total_timeouts += 1;
                // Nothing arrived within the flush window. Normal when quiet.
                continue;
            }
            Err(e) => {
                error!("Capture: pcap read error: {e}");
                break;
            }
        };

        // Record arrival time as early as possible after the kernel hands us
        // the frame, before parsing adds any latency.
        let arrived_at = Instant::now();

        // Parse Ethernet frame headers with etherparse (zero-copy).
        // Lax parsing: snaplen cuts the payload off, so the length recorded in
        // the IP header is larger than the bytes we hold. A strict parse rejects
        // the whole frame for that; a lax one keeps the headers and reports the
        // shortfall in `stop_err`. Headers are all this sensor reads.
        let sliced = match LaxSlicedPacket::from_ethernet(raw.data) {
            Ok(s)  => s,
            Err(_) => {
                // Too short to hold an Ethernet header at all.
                parse_failed += 1;
                debug!("Capture: etherparse failed on packet #{packet_count}; skipping");
                continue;
            }
        };

        // `incomplete` means the IP header declared more bytes than the slice
        // holds, i.e. snaplen cut the payload. Expected, and counted only to
        // show the headers still parsed.
        if sliced.net.as_ref().and_then(|n| n.ip_payload_ref()).is_some_and(|p| p.incomplete) {
            truncated += 1;
        }

        // Extract source and destination IPs, and the TTL / hop limit, from
        // the IP header. V7's TTL variance feature reads the same header
        // this already parses, no new parsing.
        let (src_ip, dst_ip, ip_num, ttl) = match sliced.net {
            Some(LaxNetSlice::Ipv4(ref ipv4)) => {
                (IpAddr::from(ipv4.header().source_addr()), IpAddr::from(ipv4.header().destination_addr()), ipv4.header().protocol(), ipv4.header().ttl())
            }
            Some(LaxNetSlice::Ipv6(ref ipv6)) => {
                (IpAddr::from(ipv6.header().source_addr()), IpAddr::from(ipv6.header().destination_addr()), ipv6.header().next_header(), ipv6.header().hop_limit())
            }
            // Not an IP frame.
            _ => {
                non_ip += 1;
                continue;
            }
        };

        // V7's port entropy and TCP fingerprint diversity features read the
        // same already parsed transport slice `dst_port` already reads.
        let (dst_port, source_port, fingerprint_bucket) = match sliced.transport {
            Some(TransportSlice::Tcp(ref slice)) => (
                slice.destination_port(),
                slice.source_port(),
                slice.syn().then(|| fingerprint_bucket(slice)),
            ),
            Some(TransportSlice::Udp(ref slice)) => (slice.destination_port(), slice.source_port(), None),
            _ => (0, 0, None),
        };

        let protocol = match ip_num.0 {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 | 58 => Protocol::Icmp,
            132 => Protocol::Sctp,
            47 => Protocol::Gre,
            50 => Protocol::Esp,
            _ => Protocol::Other,
        };

        packet_count += 1;

        // Forward metadata to the analysis thread via the bounded channel.
        let meta = PacketMeta {
            direction: cfg.direction, src_ip, dst_ip, arrived_at, protocol, dst_port,
            source_port, ttl, fingerprint_bucket,
        };

        // Blocks when the channel is full, which is what keeps memory bounded
        // under a flood.
        if tx.send(meta).is_err() {
            // The analysis thread is gone.
            info!("Capture: analysis channel closed; capture thread exiting after {packet_count} packets");
            break;
        }

        // Progress at debug level.
        if packet_count.is_multiple_of(10_000) {
            debug!("Capture: {} packets forwarded to analysis thread", packet_count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    /// Builds a full Ethernet frame around one TCP segment, so it can be fed
    /// straight through `LaxSlicedPacket::from_ethernet`, the same entry
    /// point the real capture loop uses.
    fn synthetic_tcp_frame(
        ttl: u8,
        source_port: u16,
        window_size: u16,
        syn: bool,
        options: &[TcpOptionElement],
    ) -> Vec<u8> {
        let mut builder = PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([198, 51, 100, 9], [192, 0, 2, 3], ttl)
            .tcp(source_port, 443, 0, window_size)
            .options(options)
            .expect("valid TCP options");
        if syn {
            builder = builder.syn();
        }
        let mut raw = Vec::with_capacity(builder.size(0));
        builder.write(&mut raw, &[]).expect("serialise synthetic frame");
        raw
    }

    fn parsed_tcp(raw: &[u8]) -> (u8, u16, Option<u8>) {
        let sliced = LaxSlicedPacket::from_ethernet(raw).expect("parses");
        let ttl = match sliced.net.as_ref().expect("ip header") {
            LaxNetSlice::Ipv4(ipv4) => ipv4.header().ttl(),
            LaxNetSlice::Ipv6(ipv6) => ipv6.header().hop_limit(),
        };
        match sliced.transport.as_ref().expect("tcp header") {
            TransportSlice::Tcp(slice) => (
                ttl,
                slice.source_port(),
                slice.syn().then(|| fingerprint_bucket(slice)),
            ),
            _ => panic!("expected a TCP transport slice"),
        }
    }

    /// A SYN carrying the common Linux-shaped option set gets a fingerprint
    /// bucket built from presence of each option group plus a window size
    /// range, not from hashing the raw option bytes.
    #[test]
    fn a_syn_with_common_options_extracts_port_ttl_and_a_fingerprint_bucket() {
        let raw = synthetic_tcp_frame(
            64,
            51_000,
            65_535,
            true,
            &[
                TcpOptionElement::MaximumSegmentSize(1460),
                TcpOptionElement::SelectiveAcknowledgementPermitted,
                TcpOptionElement::Timestamp(1, 0),
                TcpOptionElement::Noop,
                TcpOptionElement::WindowScale(7),
            ],
        );
        let (ttl, source_port, bucket) = parsed_tcp(&raw);
        assert_eq!(ttl, 64);
        assert_eq!(source_port, 51_000);
        assert_eq!(
            bucket,
            Some(OPT_MSS | OPT_WSCALE | OPT_SACK | OPT_TIMESTAMP | (3 << 4)),
            "window 65535 falls in the top window bucket, all four option groups present"
        );
        assert!(
            (bucket.unwrap() as usize) < FINGERPRINT_BUCKETS,
            "a real fingerprint must fit in the fixed table FINGERPRINT_HIST is sized for"
        );
    }

    /// A NOP carries no diagnostic weight on its own: a SYN with only NOPs
    /// has the same fingerprint bucket as one with no options at all.
    #[test]
    fn noop_only_options_do_not_change_the_fingerprint_bucket() {
        let bare = synthetic_tcp_frame(64, 51_000, 512, true, &[]);
        let padded = synthetic_tcp_frame(64, 51_000, 512, true, &[TcpOptionElement::Noop, TcpOptionElement::Noop]);
        assert_eq!(parsed_tcp(&bare).2, parsed_tcp(&padded).2);
    }

    /// Fingerprinting is a SYN only technique. A non SYN TCP segment must
    /// not get a fingerprint bucket at all, not even a zero one: zero is a
    /// real, if unusual, fingerprint, and would be indistinguishable from
    /// "not applicable" if this returned it instead of `None`.
    #[test]
    fn a_non_syn_segment_has_no_fingerprint_bucket() {
        let raw = synthetic_tcp_frame(64, 51_000, 65_535, false, &[TcpOptionElement::MaximumSegmentSize(1460)]);
        let (_, _, bucket) = parsed_tcp(&raw);
        assert_eq!(bucket, None);
    }
}
