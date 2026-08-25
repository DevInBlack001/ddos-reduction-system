//! Types shared between the BPF programs and the user space loader.
//!
//! Every type here crosses the kernel boundary as raw bytes in a map, so all
//! of them are `repr(C)` with explicit padding. A field added on one side and
//! not the other reads as garbage rather than as an error.
//!
//! Addresses are always 16 bytes. IPv4 is stored IPv4 mapped, matching what
//! the feature vector already puts on the wire, so one key type covers both
//! families.

#![no_std]

/// An address in the 16 byte form used everywhere in this crate.
pub type Addr = [u8; 16];

/// Build the IPv4 mapped form of an IPv4 address.
///
/// `octets` are in wire order. A header field holding the address as a `u32`
/// already stores those bytes, so `to_ne_bytes` is the correct way to recover
/// them, not `to_be_bytes`.
/// Written as one literal rather than zeroing an array and then filling it.
/// The zero and fill form compiles to a `memset`, which BPF has no
/// implementation of, so the program fails to link.
#[inline(always)]
pub fn v4_mapped(octets: [u8; 4]) -> Addr {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
        octets[0], octets[1], octets[2], octets[3],
    ]
}

/// How many leading bits of an IPv4 prefix become in the mapped form.
pub const V4_MAPPED_PREFIX_OFFSET: u32 = 96;

/// Which side a counter belongs to. Ingress drives detection; egress only
/// answers how much traffic got through.
pub const DIR_INGRESS: u8 = 0;
pub const DIR_EGRESS: u8 = 1;

/// One protected host's counters for the current window.
///
/// Both programs update this. User space drains and zeroes it when the window
/// closes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    /// Packets that arrived for this host.
    pub ingress_packets: u64,
    /// Packets forwarded on toward it, counted on the egress hook.
    pub egress_packets: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub sctp: u64,
    pub gre: u64,
    pub esp: u64,
    pub other: u64,
}

/// Key for the per source histogram that entropy is computed from.
///
/// Entropy is per protected host, so the host is part of the key rather than
/// having one map per host.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceKey {
    pub victim: Addr,
    pub source: Addr,
}

/// Key for the flow table behind the dashboard's network map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub source: Addr,
    pub victim: Addr,
    pub dst_port: u16,
    pub proto: u8,
    /// Explicit, so the struct has no implicit padding to leak stack bytes
    /// into the map.
    pub _pad: u8,
}

/// Key for the per source port histogram, V7's port entropy feature.
///
/// Keyed by the port value itself, not by source address: port space is 16
/// bit and fixed regardless of how many addresses or packets a flood uses,
/// unlike `SourceKey`, which an attacker can fill by spreading across
/// addresses.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortKey {
    pub victim: Addr,
    pub port: u16,
}

/// Key for the per TTL histogram, V7's TTL variance feature. Same value
/// keyed reasoning as `PortKey`: TTL is an 8 bit field, fixed regardless of
/// attacker address or packet volume.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TtlKey {
    pub victim: Addr,
    pub ttl: u8,
}

/// Key for the per TCP fingerprint bucket histogram, V7's fingerprint
/// diversity feature. The bucket is a small fixed table index (option
/// ordering, p0f style), not a hash of arbitrary option bytes, so it needs
/// no larger a key space than `TtlKey`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FingerprintKey {
    pub victim: Addr,
    pub bucket: u8,
}

// Safety: all key types are plain data with no padding and no invalid bit
// patterns, which is what aya requires to move them through a map.
#[cfg(feature = "user")]
unsafe impl aya::Pod for Counters {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SourceKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PortKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TtlKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FingerprintKey {}
