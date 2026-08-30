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
    maps::{LpmTrie, PerCpuArray, PerCpuHashMap},
    programs::{TcContext, XdpContext},
};
use core::mem;
use ddos_stage1_common::{v4_mapped, Addr, Counters, FingerprintKey, FlowKey, PortKey, SourceKey, TtlKey};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

/// Ethertypes, read as raw bytes rather than through an enum.
///
/// Loading arbitrary wire bytes into an enum with a fixed set of variants is
/// undefined behaviour the moment traffic carries anything else, and VLAN
/// tagged frames do exactly that.
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;

/// Bytes a VLAN tag adds: the ethertype that introduced it plus the tag.
const VLAN_HDR_LEN: usize = 4;

/// How many stacked VLAN tags to walk. Two covers 802.1Q and QinQ, and a fixed
/// bound is what lets the verifier accept this at all.
const MAX_VLAN_DEPTH: usize = 2;

/// V7: TCP option kind numbers this program weighs for the fingerprint
/// bucket. Matches `stage1/src/capture.rs`'s pcap side exactly, so both
/// backends mean the same thing by the same bucket number.
const TCP_OPT_EOL: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;
const TCP_OPT_WSCALE: u8 = 3;
const TCP_OPT_SACK_PERM: u8 = 4;
const TCP_OPT_SACK: u8 = 5;
const TCP_OPT_TIMESTAMP: u8 = 8;

const OPT_MSS: u8 = 1 << 0;
const OPT_WSCALE: u8 = 1 << 1;
const OPT_SACK: u8 = 1 << 2;
const OPT_TIMESTAMP: u8 = 1 << 3;

/// How many TCP option entries to walk. A SYN's data offset caps total
/// option bytes at 40 (max data offset 15 x 4 minus the 20 byte fixed
/// header), and every common OS stack's SYN carries at most 5 to 7 options,
/// so this covers every real signature with headroom, the same
/// "as deep as this needs to go" reasoning `MAX_VLAN_DEPTH` above already
/// uses. Only the iteration count needs to be compile time bounded for the
/// verifier; each read still goes through `ptr_at`'s checked access.
const MAX_TCP_OPTION_STEPS: usize = 10;

// The sizes below are compiled in defaults, not fixed limits. User space
// overrides each one at load time from a CLI flag (see kernel.rs), so a
// deployment with more hosts, more sources, or more memory does not need a
// rebuilt object. The values here are what a modest gateway needs.

/// Protected hosts, as a prefix trie so a single lookup serves both an
/// explicit address list and a subnet. An address list is stored as full
/// length prefixes.
///
/// Sized by `--max-protected-hosts`.
#[map]
static PROTECTED: LpmTrie<Addr, u8> = LpmTrie::with_max_entries(1024, 0);

/// Addresses carved out of PROTECTED, most often the gateway's own address
/// falling inside a --victim-subnet range. Checked in addition to PROTECTED,
/// never instead of it: a destination must match PROTECTED and not match
/// this trie to be treated as protected. Empty, and therefore free, when no
/// exclusion is configured.
///
/// Sized by `--max-protected-hosts`, the same knob PROTECTED uses: an
/// exclusion list is always a small subset of the hosts it carves an
/// address out of, so it does not need a flag of its own.
#[map]
static EXCLUDED: LpmTrie<Addr, u8> = LpmTrie::with_max_entries(1024, 0);

/// Per host counters for the current window.
/// Per CPU so concurrent receive queues cannot lose an increment. Each CPU
/// updates only its own slot, and user space sums them when draining.
///
/// Sized by `--max-protected-hosts`. This is the map that binds first when
/// protecting many hosts, since the trie above stores a subnet as one entry.
#[map]
static COUNTERS: PerCpuHashMap<Addr, Counters> = PerCpuHashMap::with_max_entries(256, 0);

/// Per host, per source packet counts. User space computes entropy from this.
///
/// Bounded because the key is attacker controlled: a randomized source flood
/// would otherwise try to allocate an entry per packet. Raising the bound
/// buys accuracy under a wider flood, it does not remove the exposure.
///
/// Sized by `--max-sources`.
#[map]
static SOURCES: PerCpuHashMap<SourceKey, u64> = PerCpuHashMap::with_max_entries(65_536, 0);

/// Flow table behind the dashboard's network map.
///
/// Fills before SOURCES does, because a source with several destination ports
/// occupies one entry per port here and one entry in total there.
///
/// Sized by `--max-flows`.
#[map]
static FLOWS: PerCpuHashMap<FlowKey, u64> = PerCpuHashMap::with_max_entries(8192, 0);

/// V7: per host, per source port packet counts. User space computes source
/// port entropy from this, invariant under source address forgery unlike
/// `SOURCES` above.
///
/// Port space is 16 bit and fixed regardless of how many addresses or
/// packets a flood uses, so unlike `SOURCES` this needs no operator
/// configurable cap: 65,536 is the whole space, not a budget.
#[map]
static PORT_HIST: PerCpuHashMap<PortKey, u64> = PerCpuHashMap::with_max_entries(65_536, 0);

/// V7: per host, per TTL / hop limit packet counts. User space computes TTL
/// variance from this. TTL is 8 bit, so 256 is the whole space.
#[map]
static TTL_HIST: PerCpuHashMap<TtlKey, u64> = PerCpuHashMap::with_max_entries(256, 0);

/// V7: per host, per TCP fingerprint bucket SYN counts. User space computes
/// fingerprint diversity from this. The bucket is a small fixed table index
/// (option ordering plus a window size range, p0f style), not a hash of
/// arbitrary bytes, so it needs no larger a key space than `TTL_HIST`.
#[map]
static FINGERPRINT_HIST: PerCpuHashMap<FingerprintKey, u64> = PerCpuHashMap::with_max_entries(64, 0);

/// A single zeroed `Counters`, used only to seed a new entry.
///
/// The kernel zero initialises array maps, and nothing here ever writes to
/// this one, so reading index 0 always yields zeros. That is the way to get a
/// zeroed struct without a stack allocation, which would compile to a memset.
#[map]
static ZEROED: PerCpuArray<Counters> = PerCpuArray::with_max_entries(1, 0);

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
    /// V7: IPv4 TTL or IPv6 hop limit.
    ttl: u8,
}

/// Parse Ethernet, any VLAN tags, and IP.
///
/// Returns `None` for anything that is not IPv4 or IPv6, and for anything too
/// short to read. VLAN tagged frames are followed rather than skipped: the
/// pcap backend's filter has always accepted them, so ignoring them here would
/// make the two backends disagree on the same traffic.
#[inline(always)]
unsafe fn parse(start: usize, end: usize) -> Option<Parsed> {
    // The ethertype sits after the two MAC addresses. Read as raw bytes,
    // because a frame can carry any value here and only some are known.
    let mut offset = EthHdr::LEN - mem::size_of::<u16>();
    let mut ether_type = u16::from_be(*(ptr_at::<u16>(start, end, offset)?));
    offset += mem::size_of::<u16>();

    // Walk stacked tags. Bounded rather than looping until a non VLAN type,
    // both because QinQ is as deep as this needs to go and because the
    // verifier rejects a loop it cannot bound.
    for _ in 0..MAX_VLAN_DEPTH {
        if ether_type != ETH_P_8021Q && ether_type != ETH_P_8021AD {
            break;
        }
        // The tag is two bytes of control data followed by the real ethertype.
        ether_type = u16::from_be(*(ptr_at::<u16>(start, end, offset + 2)?));
        offset += VLAN_HDR_LEN;
    }

    match ether_type {
        ETH_P_IPV4 => {
            let ip: *const Ipv4Hdr = ptr_at(start, end, offset)?;
            Some(Parsed {
                source: v4_mapped((*ip).src_addr.to_ne_bytes()),
                dest: v4_mapped((*ip).dst_addr.to_ne_bytes()),
                proto: (*ip).proto,
                l4_offset: offset + Ipv4Hdr::LEN,
                ttl: (*ip).ttl,
            })
        }
        ETH_P_IPV6 => {
            let ip: *const Ipv6Hdr = ptr_at(start, end, offset)?;
            Some(Parsed {
                source: (*ip).src_addr.in6_u.u6_addr8,
                dest: (*ip).dst_addr.in6_u.u6_addr8,
                proto: (*ip).next_hdr,
                l4_offset: offset + Ipv6Hdr::LEN,
                ttl: (*ip).hop_limit,
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

/// V7: source port, or 0 for protocols that have none. Mirrors `dest_port`
/// exactly, reading `.source` instead of `.dest` on the same already parsed
/// header.
#[inline(always)]
unsafe fn source_port(start: usize, end: usize, p: &Parsed) -> u16 {
    match p.proto {
        IpProto::Tcp => match ptr_at::<TcpHdr>(start, end, p.l4_offset) {
            Some(h) => u16::from_be((*h).source),
            None => 0,
        },
        IpProto::Udp => match ptr_at::<UdpHdr>(start, end, p.l4_offset) {
            Some(h) => u16::from_be((*h).source),
            None => 0,
        },
        _ => 0,
    }
}

/// V7: reduce a TCP SYN's options and window size to one of
/// `FINGERPRINT_HIST`'s 64 buckets. `None` for anything that is not a TCP
/// SYN, or too short to hold a full TCP header: fingerprinting is a SYN
/// only technique, and forcing every other packet into some bucket would
/// mix "not applicable" with a real, if unusual, all zero fingerprint.
///
/// Matches `stage1/src/capture.rs`'s `fingerprint_bucket` exactly: 4 bits of
/// option presence (MSS, window scale, SACK permitted or SACK, timestamp;
/// NOP is padding, not counted), 2 bits of window size range.
#[inline(always)]
unsafe fn fingerprint_bucket(start: usize, end: usize, p: &Parsed) -> Option<u8> {
    if p.proto != IpProto::Tcp {
        return None;
    }
    let tcp: *const TcpHdr = ptr_at(start, end, p.l4_offset)?;
    if (*tcp).syn() == 0 {
        return None;
    }

    let opts_start = p.l4_offset + TcpHdr::LEN;
    let opts_end = p.l4_offset + (*tcp).doff() as usize * 4;

    let mut presence: u8 = 0;
    let mut pos = opts_start;
    for _ in 0..MAX_TCP_OPTION_STEPS {
        if pos >= opts_end {
            break;
        }
        let kind = match ptr_at::<u8>(start, end, pos) {
            Some(k) => *k,
            None => break,
        };
        match kind {
            TCP_OPT_EOL => break,
            TCP_OPT_NOP => pos += 1,
            TCP_OPT_MSS => {
                presence |= OPT_MSS;
                pos += 4;
            }
            TCP_OPT_WSCALE => {
                presence |= OPT_WSCALE;
                pos += 3;
            }
            TCP_OPT_SACK_PERM => {
                presence |= OPT_SACK;
                pos += 2;
            }
            TCP_OPT_TIMESTAMP => {
                presence |= OPT_TIMESTAMP;
                pos += 10;
            }
            _ => {
                // TCP_OPT_SACK or anything unrecognised: kind then a length
                // byte then data, the general TCP option shape. Reading the
                // length is what lets the walk skip it correctly rather
                // than desyncing on whatever comes after.
                let len = match ptr_at::<u8>(start, end, pos + 1) {
                    Some(l) => *l as usize,
                    None => break,
                };
                if kind == TCP_OPT_SACK {
                    presence |= OPT_SACK;
                }
                pos += len.max(2);
            }
        }
    }

    let window = u16::from_be((*tcp).window);
    let window_bucket: u8 = match window {
        0 => 0,
        1..=8192 => 1,
        8193..=32768 => 2,
        _ => 3,
    };

    Some(presence | (window_bucket << 4))
}

/// Whether this address is one of the hosts being protected.
///
/// Excluded addresses are checked here rather than left out of PROTECTED at
/// load time, because PROTECTED's subnet entry is one trie node covering the
/// whole range; there is no way to carve a single host back out of a prefix
/// match without a second, separate check.
#[inline(always)]
fn is_protected(addr: &Addr) -> bool {
    let key = aya_ebpf::maps::lpm_trie::Key::new(128, *addr);
    PROTECTED.get(&key).is_some() && EXCLUDED.get(&key).is_none()
}

#[inline(always)]
fn bump_counters(victim: &Addr, proto: IpProto, ingress_side: bool) {
    // Seed the entry on first sight. The zeroed value comes from a map the
    // kernel zero initialises, because building one on the stack compiles to
    // a memset and BPF has no implementation of it.
    if unsafe { COUNTERS.get(victim) }.is_none() {
        let Some(zero) = ZEROED.get(0) else { return };
        if COUNTERS.insert(victim, zero, 0).is_err() {
            return;
        }
    }

    // Updated through a pointer rather than read, copied, and written back.
    // Copying would put the whole struct on the stack for no benefit.
    let Some(c) = COUNTERS.get_ptr_mut(victim) else { return };
    let c = unsafe { &mut *c };

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
}

#[inline(always)]
fn bump(map: &PerCpuHashMap<SourceKey, u64>, key: &SourceKey) {
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

/// V7: same shape as `bump`/`bump_flow`, kept as three separate, fully
/// concrete functions rather than one generalised over the key type, so a
/// mistake in the new maps' wiring cannot touch the already proven ingress
/// path for `SOURCES`/`FLOWS`.
#[inline(always)]
fn bump_port(key: &PortKey) {
    let next = match unsafe { PORT_HIST.get(key) } {
        Some(n) => *n + 1,
        None => 1,
    };
    let _ = PORT_HIST.insert(key, &next, 0);
}

#[inline(always)]
fn bump_ttl(key: &TtlKey) {
    let next = match unsafe { TTL_HIST.get(key) } {
        Some(n) => *n + 1,
        None => 1,
    };
    let _ = TTL_HIST.insert(key, &next, 0);
}

#[inline(always)]
fn bump_fingerprint(key: &FingerprintKey) {
    let next = match unsafe { FINGERPRINT_HIST.get(key) } {
        Some(n) => *n + 1,
        None => 1,
    };
    let _ = FINGERPRINT_HIST.insert(key, &next, 0);
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

    // V7: port entropy and TTL variance are computed on every ingress
    // packet, matching the pcap backend, where a protocol with no port
    // reads as 0. Fingerprint diversity is SYN only.
    bump_port(&PortKey {
        victim: parsed.dest,
        port: unsafe { source_port(start, end, &parsed) },
    });
    bump_ttl(&TtlKey {
        victim: parsed.dest,
        ttl: parsed.ttl,
    });
    if let Some(bucket) = unsafe { fingerprint_bucket(start, end, &parsed) } {
        bump_fingerprint(&FingerprintKey {
            victim: parsed.dest,
            bucket,
        });
    }

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
