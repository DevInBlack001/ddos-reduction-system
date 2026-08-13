//! The user space half of the kernel capture backend.
//!
//! Loads the compiled programs, attaches them, and drains their maps once per
//! window. Nothing here decides anything: it turns map contents into the same
//! per window figures the pcap backend produces, and the detection code
//! consumes them unchanged.
//!
//! The object is loaded from disk at runtime rather than embedded, so the
//! sensor still builds on a machine with no eBPF toolchain. See
//! scripts/build-ebpf.sh.

use aya::{
    maps::{LpmTrie, MapData, PerCpuHashMap},
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpMode},
    Ebpf,
};
use ddos_stage1_common::{Addr, Counters, FlowKey, SourceKey};
use log::{info, warn};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::VictimTargets;

/// Where the object is installed by default. Overridable so a development
/// build can point at the one in the build directory.
pub const DEFAULT_OBJECT_PATH: &str = "/usr/local/lib/ddos_stage1/ddos-stage1.o";

/// One window's worth of observations for a single protected host, drained
/// from the maps.
///
/// This is deliberately the same shape the pcap backend arrives at by counting
/// packets itself, so the analysis code cannot tell which backend produced it.
#[derive(Debug, Default, Clone)]
pub struct WindowSample {
    pub ingress_packets: u64,
    pub egress_packets: u64,
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
    pub sctp: u64,
    pub gre: u64,
    pub esp: u64,
    pub other: u64,
    /// Packets per source address, which entropy is computed from.
    pub sources: HashMap<IpAddr, u64>,
    /// Packet counts per flow, for the dashboard.
    pub flows: HashMap<(IpAddr, IpAddr, u16, u8), u64>,
}

/// Owns the loaded programs and their maps for the life of the process.
///
/// Dropping this detaches everything, which is why it is held rather than
/// leaked after attaching.
pub struct KernelCapture {
    ebpf: Ebpf,
    /// Kept so the egress qdisc can be removed on the way out if this created
    /// it. Attaching TC needs a clsact qdisc present on the interface.
    egress_interface: Option<String>,
}

impl KernelCapture {
    /// Load the object, populate the protected host set, and attach both
    /// programs.
    ///
    /// `egress` is optional: without it the drop measurement is unavailable,
    /// exactly as it is on the pcap backend.
    pub fn load(
        object_path: &str,
        ingress: &str,
        egress: Option<&str>,
        targets: &VictimTargets,
    ) -> Result<Self, String> {
        let mut ebpf = Ebpf::load_file(object_path)
            .map_err(|e| format!("failed to load '{object_path}': {e}"))?;

        Self::populate_targets(&mut ebpf, targets)?;

        // XDP first. A driver without native support falls back to the generic
        // hook, which is slower but still correct, so this is worth trying
        // rather than refusing to start.
        let program: &mut Xdp = ebpf
            .program_mut("ingress")
            .ok_or("object has no 'ingress' program")?
            .try_into()
            .map_err(|e| format!("'ingress' is not an XDP program: {e}"))?;
        program
            .load()
            .map_err(|e| format!("verifier rejected 'ingress': {e}"))?;

        // Driver mode is tried explicitly rather than letting the kernel
        // choose, so the log says which one is actually in use.
        match program.attach(ingress, XdpMode::Driver) {
            Ok(_) => info!("Kernel: XDP attached to '{ingress}' in driver mode"),
            Err(_) => {
                program
                    .attach(ingress, XdpMode::Skb)
                    .map_err(|e| format!("could not attach XDP to '{ingress}': {e}"))?;
                warn!(
                    "Kernel: '{ingress}' has no native XDP support, using generic mode. \
                     This still works but costs more per packet than the driver hook."
                );
            }
        }

        let mut egress_interface = None;
        if let Some(iface) = egress {
            // TC needs a clsact qdisc. Adding one that already exists is an
            // error worth ignoring, not a failure.
            let _ = tc::qdisc_add_clsact(iface);

            let program: &mut SchedClassifier = ebpf
                .program_mut("egress")
                .ok_or("object has no 'egress' program")?
                .try_into()
                .map_err(|e| format!("'egress' is not a classifier: {e}"))?;
            program
                .load()
                .map_err(|e| format!("verifier rejected 'egress': {e}"))?;
            program
                .attach(iface, TcAttachType::Egress)
                .map_err(|e| format!("could not attach TC to '{iface}': {e}"))?;

            info!("Kernel: TC attached to '{iface}' for drop measurement");
            egress_interface = Some(iface.to_string());
        }

        Ok(Self {
            ebpf,
            egress_interface,
        })
    }

    /// Fill the prefix trie the programs consult to decide whether a packet is
    /// worth counting.
    ///
    /// An address list becomes full length prefixes, a subnet becomes one
    /// entry, so the kernel side needs no notion of which mode is in use.
    fn populate_targets(ebpf: &mut Ebpf, targets: &VictimTargets) -> Result<(), String> {
        let mut trie: LpmTrie<&mut MapData, Addr, u8> = ebpf
            .map_mut("PROTECTED")
            .ok_or("object has no 'PROTECTED' map")?
            .try_into()
            .map_err(|e| format!("'PROTECTED' is not an LPM trie: {e}"))?;

        let entries: Vec<(Addr, u32)> = match targets {
            VictimTargets::List(ips) => ips.iter().map(|ip| (to_addr(*ip), 128)).collect(),
            VictimTargets::Subnet { ip, prefix } => {
                // An IPv4 prefix shifts by 96 bits once the address is stored
                // in its mapped form.
                let bits = match ip {
                    IpAddr::V4(_) => 96 + *prefix as u32,
                    IpAddr::V6(_) => *prefix as u32,
                };
                vec![(to_addr(*ip), bits)]
            }
        };

        for (addr, prefix_len) in &entries {
            let key = aya::maps::lpm_trie::Key::new(*prefix_len, *addr);
            trie.insert(&key, 1u8, 0)
                .map_err(|e| format!("could not add a protected host: {e}"))?;
        }
        info!("Kernel: {} protected host entries loaded", entries.len());
        Ok(())
    }

    /// Read and clear every map, returning one sample per host that saw
    /// traffic.
    ///
    /// The maps are per CPU, so every read sums across CPUs. Without that a
    /// multi queue interface would report only whichever CPU happened to be
    /// read.
    ///
    /// Draining is read then delete rather than an atomic swap, so a packet
    /// arriving mid drain lands in the next window instead of this one. At
    /// window scale that is a rounding difference, and it is the same
    /// tradeoff the pcap backend already makes at its window boundary.
    pub fn drain(&mut self) -> Result<HashMap<IpAddr, WindowSample>, String> {
        let mut out: HashMap<IpAddr, WindowSample> = HashMap::new();

        self.drain_counters(&mut out)?;
        self.drain_sources(&mut out)?;
        self.drain_flows(&mut out)?;

        Ok(out)
    }

    fn drain_counters(&mut self, out: &mut HashMap<IpAddr, WindowSample>) -> Result<(), String> {
        let mut map: PerCpuHashMap<&mut MapData, Addr, Counters> = self
            .ebpf
            .map_mut("COUNTERS")
            .ok_or("object has no 'COUNTERS' map")?
            .try_into()
            .map_err(|e| format!("'COUNTERS' has an unexpected type: {e}"))?;

        let keys: Vec<Addr> = map.keys().filter_map(|k| k.ok()).collect();
        for key in keys {
            if let Ok(per_cpu) = map.get(&key, 0) {
                let entry = out.entry(from_addr(&key)).or_default();
                for c in per_cpu.iter() {
                    entry.ingress_packets += c.ingress_packets;
                    entry.egress_packets += c.egress_packets;
                    entry.tcp += c.tcp;
                    entry.udp += c.udp;
                    entry.icmp += c.icmp;
                    entry.sctp += c.sctp;
                    entry.gre += c.gre;
                    entry.esp += c.esp;
                    entry.other += c.other;
                }
            }
            let _ = map.remove(&key);
        }
        Ok(())
    }

    fn drain_sources(&mut self, out: &mut HashMap<IpAddr, WindowSample>) -> Result<(), String> {
        let mut map: PerCpuHashMap<&mut MapData, SourceKey, u64> = self
            .ebpf
            .map_mut("SOURCES")
            .ok_or("object has no 'SOURCES' map")?
            .try_into()
            .map_err(|e| format!("'SOURCES' has an unexpected type: {e}"))?;

        let keys: Vec<SourceKey> = map.keys().filter_map(|k| k.ok()).collect();
        for key in keys {
            if let Ok(per_cpu) = map.get(&key, 0) {
                let total: u64 = per_cpu.iter().sum();
                out.entry(from_addr(&key.victim))
                    .or_default()
                    .sources
                    .insert(from_addr(&key.source), total);
            }
            let _ = map.remove(&key);
        }
        Ok(())
    }

    fn drain_flows(&mut self, out: &mut HashMap<IpAddr, WindowSample>) -> Result<(), String> {
        let mut map: PerCpuHashMap<&mut MapData, FlowKey, u64> = self
            .ebpf
            .map_mut("FLOWS")
            .ok_or("object has no 'FLOWS' map")?
            .try_into()
            .map_err(|e| format!("'FLOWS' has an unexpected type: {e}"))?;

        let keys: Vec<FlowKey> = map.keys().filter_map(|k| k.ok()).collect();
        for key in keys {
            if let Ok(per_cpu) = map.get(&key, 0) {
                let victim = from_addr(&key.victim);
                out.entry(victim).or_default().flows.insert(
                    (from_addr(&key.source), victim, key.dst_port, key.proto),
                    per_cpu.iter().sum(),
                );
            }
            let _ = map.remove(&key);
        }
        Ok(())
    }
}

impl Drop for KernelCapture {
    fn drop(&mut self) {
        // The programs detach when `ebpf` drops. The qdisc does not, so a
        // restart would otherwise accumulate one per run.
        if let Some(iface) = &self.egress_interface {
            let _ = tc::qdisc_detach_program(iface, TcAttachType::Egress, "egress");
        }
    }
}

/// Convert to the 16 byte form the maps use. IPv4 is stored mapped, so one key
/// type covers both families.
fn to_addr(ip: IpAddr) -> Addr {
    match ip {
        IpAddr::V4(v4) => ddos_stage1_common::v4_mapped(v4.octets()),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Recover an address, unwrapping the mapped form back to IPv4 so logs and the
/// dashboard show what an operator configured rather than a mapped form.
fn from_addr(addr: &Addr) -> IpAddr {
    let is_v4_mapped = addr[..10].iter().all(|b| *b == 0) && addr[10] == 0xff && addr[11] == 0xff;
    if is_v4_mapped {
        IpAddr::from([addr[12], addr[13], addr[14], addr[15]])
    } else {
        IpAddr::from(*addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_survives_a_round_trip_through_the_mapped_form() {
        let ip: IpAddr = "192.0.2.3".parse().unwrap();
        assert_eq!(from_addr(&to_addr(ip)), ip);
    }

    #[test]
    fn v6_survives_a_round_trip() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(from_addr(&to_addr(ip)), ip);
    }

    #[test]
    fn a_v6_address_is_not_mistaken_for_a_mapped_v4() {
        // Only the exact mapped prefix should unwrap, so an address that
        // merely ends in the same bytes stays IPv6.
        let ip: IpAddr = "2001:db8::ffff:c000:203".parse().unwrap();
        assert!(matches!(from_addr(&to_addr(ip)), IpAddr::V6(_)));
    }

    #[test]
    fn the_v4_mapped_prefix_is_recognised() {
        let addr = ddos_stage1_common::v4_mapped([10, 0, 0, 1]);
        assert_eq!(from_addr(&addr), "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn the_unspecified_v6_address_is_not_treated_as_v4() {
        assert!(matches!(from_addr(&[0u8; 16]), IpAddr::V6(_)));
    }
}
