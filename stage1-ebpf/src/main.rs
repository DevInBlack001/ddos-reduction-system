//! The in kernel half of Stage 1.
//!
//! Two programs share one object file and one set of maps:
//!
//!   `ingress` runs on XDP, in the driver path before the kernel builds an
//!   skb. It counts packets, protocols, sources, and flows for traffic headed
//!   to a protected host.
//!
//!   `egress` runs on TC, because XDP cannot observe the egress path at all.
//!   It only increments a counter, which is what the drop measurement needs.
//!
//! Nothing is decided here. There is no floating point and no `log2` in BPF,
//! so entropy, the rate, and every boundary stay in user space. This side only
//! accumulates; user space drains the maps when a window closes.
//!
//! Both programs return pass unconditionally. Dropping happens later, once the
//! telemetry path is proven against the existing one.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE},
    macros::{classifier, map, xdp},
    maps::{HashMap, LpmTrie},
    programs::{TcContext, XdpContext},
};
use core::mem;
use ddos_stage1_common::{v4_mapped, Addr, Counters, FlowKey, SourceKey};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

/// Protected hosts, as a prefix trie so a single lookup serves both an
/// explicit address list and a subnet. An address list is stored as full
/// length prefixes.
#[map]
static PROTECTED: LpmTrie<Addr, u8> = LpmTrie::with_max_entries(1024, 0);

/// Per host counters for the current window.
#[map]
static COUNTERS: HashMap<Addr, Counters> = HashMap::with_max_entries(256, 0);

/// Per host, per source packet counts. User space computes entropy from this.
///
/// Bounded because the key is attacker controlled: a randomized source flood
/// would otherwise try to allocate an entry per packet.
#[map]
static SOURCES: HashMap<SourceKey, u64> = HashMap::with_max_entries(65_536, 0);

/// Flow table behind the dashboard's network map.
#[map]
static FLOWS: HashMap<FlowKey, u64> = HashMap::with_max_entries(8192, 0);

#[xdp]
pub fn ingress(ctx: XdpContext) -> u32 {
    // A packet that could not be parsed, or is not headed to a protected
    // host, is simply not counted. Either way it passes.
    let _ = observe_ingress(&ctx);
    xdp_action::XDP_PASS
}

#[classifier]
pub fn egress(ctx: TcContext) -> i32 {
    let _ = observe_egress(&ctx);
    TC_ACT_PIPE
}

/// Read `T` at `offset`, refusing to read past the end of the packet.
///
/// The verifier rejects any load it cannot prove is in bounds, so this check
/// is what makes the program loadable at all, not a defensive extra.
#[inline(always)]
unsafe fn ptr_at<T>(start: usize, end: usize, offset: usize) -> Option<*const T> {
    if start + offset + mem::size_of::<T>() > end {
        return None;
    }
    Some((start + offset) as *const T)
}

/// The addresses and protocol of one packet, once the headers are parsed.
struct Parsed {
    source: Addr,
    dest: Addr,
    proto: IpProto,
    /// Offset of the transport header, if the packet has one to read.
    l4_offset: usize,
}

/// Parse Ethernet and IP. Returns `None` for anything that is not IPv4 or
/// IPv6, and for anything truncated.
#[inline(always)]
unsafe fn parse(start: usize, end: usize) -> Option<Parsed> {
    let eth: *const EthHdr = ptr_at(start, end, 0)?;

    match (*eth).ether_type {
        EtherType::Ipv4 => {
            let ip: *const Ipv4Hdr = ptr_at(start, end, EthHdr::LEN)?;
            Some(Parsed {
                source: v4_mapped((*ip).src_addr.to_ne_bytes()),
                dest: v4_mapped((*ip).dst_addr.to_ne_bytes()),
                proto: (*ip).proto,
                l4_offset: EthHdr::LEN + Ipv4Hdr::LEN,
            })
        }
        EtherType::Ipv6 => {
            let ip: *const Ipv6Hdr = ptr_at(start, end, EthHdr::LEN)?;
            Some(Parsed {
                source: (*ip).src_addr.in6_u.u6_addr8,
                dest: (*ip).dst_addr.in6_u.u6_addr8,
                proto: (*ip).next_hdr,
                l4_offset: EthHdr::LEN + Ipv6Hdr::LEN,
            })
        }
        _ => None,
    }
}

/// Destination port, or 0 for protocols that have none.
#[inline(always)]
unsafe fn dest_port(start: usize, end: usize, p: &Parsed) -> u16 {
    match p.proto {
        IpProto::Tcp => match ptr_at::<TcpHdr>(start, end, p.l4_offset) {
            Some(h) => u16::from_be((*h).dest),
            None => 0,
        },
        IpProto::Udp => match ptr_at::<UdpHdr>(start, end, p.l4_offset) {
            Some(h) => u16::from_be((*h).dest),
            None => 0,
        },
        _ => 0,
    }
}

/// Whether this address is one of the hosts being protected.
#[inline(always)]
fn is_protected(addr: &Addr) -> bool {
    let key = aya_ebpf::maps::lpm_trie::Key::new(128, *addr);
    PROTECTED.get(&key).is_some()
}

#[inline(always)]
fn bump_counters(victim: &Addr, proto: IpProto, ingress_side: bool) {
    let mut c = match unsafe { COUNTERS.get(victim) } {
        Some(existing) => *existing,
        None => Counters::default(),
    };

    if ingress_side {
        c.ingress_packets += 1;
        match proto {
            IpProto::Tcp => c.tcp += 1,
            IpProto::Udp => c.udp += 1,
            IpProto::Icmp | IpProto::Ipv6Icmp => c.icmp += 1,
            IpProto::Sctp => c.sctp += 1,
            IpProto::Gre => c.gre += 1,
            IpProto::Esp => c.esp += 1,
            _ => c.other += 1,
        }
    } else {
        c.egress_packets += 1;
    }

    let _ = COUNTERS.insert(victim, &c, 0);
}

#[inline(always)]
fn bump(map: &HashMap<SourceKey, u64>, key: &SourceKey) {
    let next = match unsafe { map.get(key) } {
        Some(n) => *n + 1,
        None => 1,
    };
    let _ = map.insert(key, &next, 0);
}

#[inline(always)]
fn bump_flow(key: &FlowKey) {
    let next = match unsafe { FLOWS.get(key) } {
        Some(n) => *n + 1,
        None => 1,
    };
    let _ = FLOWS.insert(key, &next, 0);
}

fn observe_ingress(ctx: &XdpContext) -> Option<()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let parsed = unsafe { parse(start, end) }?;
    if !is_protected(&parsed.dest) {
        return None;
    }

    bump_counters(&parsed.dest, parsed.proto, true);
    bump(
        &SOURCES,
        &SourceKey {
            victim: parsed.dest,
            source: parsed.source,
        },
    );
    bump_flow(&FlowKey {
        source: parsed.source,
        victim: parsed.dest,
        dst_port: unsafe { dest_port(start, end, &parsed) },
        proto: parsed.proto as u8,
        _pad: 0,
    });

    Some(())
}

fn observe_egress(ctx: &TcContext) -> Option<()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let parsed = unsafe { parse(start, end) }?;
    if !is_protected(&parsed.dest) {
        return None;
    }

    // Egress answers how much got through and nothing else, so it touches no
    // map that feeds detection.
    bump_counters(&parsed.dest, parsed.proto, false);
    Some(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
