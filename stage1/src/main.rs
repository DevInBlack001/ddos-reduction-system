//! Entry point.
//!
//! Parses arguments, connects the capture and analysis threads with a bounded
//! channel, spawns both, and waits.
//!
//! Run `--help` for the full option list. `RUST_LOG` sets verbosity.
//!
//! Raw capture needs either root or the CAP_NET_RAW capability:
//!
//!     sudo setcap cap_net_raw+ep ./ddos_stage1

mod analysis;
mod capture;
mod entropy;
mod ewma;
mod ipc;
mod kernel;
mod persistence;
mod state;
mod welford;

use state::AnalysisConfig;
use capture::CaptureConfig;
use crossbeam_channel::bounded;
use log::info;
use std::{env, process};

// ── Simple CLI parser ─────────────────────────────────────────────────────────
// We intentionally avoid `clap` / `structopt` to keep the dependency tree lean.
// This parser handles `--flag value` style arguments only.

/// Parse CLI arguments from `std::env::args()` into a plain struct.
#[derive(Debug, Clone)]
pub enum VictimTargets {
    List(Vec<std::net::IpAddr>),
    Subnet {
        ip: std::net::IpAddr,
        prefix: u8,
    },
}

impl VictimTargets {
    pub fn contains(&self, target: &std::net::IpAddr) -> bool {
        match self {
            VictimTargets::List(list) => list.contains(target),
            VictimTargets::Subnet { ip, prefix } => {
                match (ip, target) {
                    (std::net::IpAddr::V4(net_v4), std::net::IpAddr::V4(tgt_v4)) => {
                        let net_octets = net_v4.octets();
                        let tgt_octets = tgt_v4.octets();
                        let bits = *prefix as usize;
                        if bits > 32 { return false; }
                        let bytes = bits / 8;
                        let extra_bits = bits % 8;
                        for i in 0..bytes {
                            if net_octets[i] != tgt_octets[i] {
                                return false;
                            }
                        }
                        if extra_bits > 0 {
                            let mask = 0xFF_u8 << (8 - extra_bits);
                            if (net_octets[bytes] & mask) != (tgt_octets[bytes] & mask) {
                                return false;
                            }
                        }
                        true
                    }
                    (std::net::IpAddr::V6(net_v6), std::net::IpAddr::V6(tgt_v6)) => {
                        let net_octets = net_v6.octets();
                        let tgt_octets = tgt_v6.octets();
                        let bits = *prefix as usize;
                        if bits > 128 { return false; }
                        let bytes = bits / 8;
                        let extra_bits = bits % 8;
                        for i in 0..bytes {
                            if net_octets[i] != tgt_octets[i] {
                                return false;
                            }
                        }
                        if extra_bits > 0 {
                            let mask = 0xFF_u8 << (8 - extra_bits);
                            if (net_octets[bytes] & mask) != (tgt_octets[bytes] & mask) {
                                return false;
                            }
                        }
                        true
                    }
                    _ => false,
                }
            }
        }
    }
}

/// Parse CLI arguments from `std::env::args()` into a plain struct.
struct CliArgs {
    interface:      String,
    /// V5: optional second interface, the egress side of the gateway. When
    /// set, a second capture thread measures what actually reached the
    /// victims after filtering. Absent, the sensor behaves exactly as it
    /// did before and no drop metrics are reported.
    egress_interface: Option<String>,
    victim_targets: Option<VictimTargets>,
    /// Addresses carved out of victim_targets, most often the gateway's own
    /// address when it falls inside --victim-subnet. Checked in addition to,
    /// not instead of, victim_targets: an address must match the targets and
    /// not match this list to be treated as protected.
    exclude_ips:    Vec<std::net::IpAddr>,
    k:              f64,
    alpha:          f64,
    socket:         String,
    no_filter:      bool,
    log_file:       Option<String>,
    /// If set, write every post-warmup feature vector to this CSV file.
    train_csv:      Option<String>,
    /// Integer class label written into the CSV (0=normal, 1=flash_crowd, 2=ddos).
    train_label:    u8,
    /// V4: where to persist/reload per-victim baselines across restarts.
    baseline_path:      String,
    /// V4: reject a persisted baseline older than this many seconds.
    baseline_ttl_secs:  f64,
    /// Which capture backend to use.
    capture_mode:       CaptureMode,
    /// Where the compiled eBPF object lives, for the kernel backend.
    bpf_object:         String,
    /// Detection tuning. See `AnalysisConfig` for what each one does.
    entropy_sigma_floor:   f64,
    entropy_sigma_ceiling: f64,
    rate_sigma_floor:      f64,
    distributed_dominance: f64,
    entropy_min_packets:   usize,
    emergency_volume_sigma:   f64,
    entropy_k_fallback:       f64,
    rate_sigma_ceiling_ratio: f64,
    rate_sigma_ceiling_floor: f64,
    outlier_sigma:            f64,
    rate_mean_cap:            f64,
    cooldown_windows:         u64,
    cooldown_k_factor:        f64,
    peacetime_ewma_weight:    f64,
    /// Kernel map capacities. See `kernel::MapSizes`.
    max_sources:          u32,
    max_flows:            u32,
    max_protected_hosts:  u32,
}

/// How packets are observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureMode {
    /// libpcap in user space. Works anywhere.
    Pcap,
    /// XDP and TC in the kernel. Needs driver support and the compiled object.
    Kernel,
}

impl CliArgs {
    /// Parse arguments and exit the process with a usage message on error.
    fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut interface = String::new();
        let mut egress_interface: Option<String> = None;
        let mut capture_mode = CaptureMode::Pcap;
        let mut bpf_object = crate::kernel::DEFAULT_OBJECT_PATH.to_string();
        let mut entropy_sigma_floor = state::DEFAULT_ENTROPY_SIGMA_FLOOR;
        let mut entropy_sigma_ceiling = state::DEFAULT_ENTROPY_SIGMA_CEILING;
        let mut rate_sigma_floor = state::DEFAULT_RATE_SIGMA_FLOOR;
        let mut distributed_dominance = state::DEFAULT_DISTRIBUTED_DOMINANCE;
        let mut entropy_min_packets = state::DEFAULT_ENTROPY_MIN_PACKETS;
        let mut max_sources = crate::kernel::DEFAULT_MAX_SOURCES;
        let mut max_flows = crate::kernel::DEFAULT_MAX_FLOWS;
        let mut max_protected_hosts = crate::kernel::DEFAULT_MAX_PROTECTED_HOSTS;
        let mut emergency_volume_sigma = state::DEFAULT_EMERGENCY_VOLUME_SIGMA;
        let mut entropy_k_fallback = state::DEFAULT_ENTROPY_K_FALLBACK;
        let mut rate_sigma_ceiling_ratio = state::DEFAULT_RATE_SIGMA_CEILING_RATIO;
        let mut rate_sigma_ceiling_floor = state::DEFAULT_RATE_SIGMA_CEILING_FLOOR;
        let mut outlier_sigma = state::DEFAULT_OUTLIER_SIGMA;
        let mut rate_mean_cap = state::DEFAULT_RATE_MEAN_CAP;
        let mut cooldown_windows = state::DEFAULT_COOLDOWN_WINDOWS;
        let mut cooldown_k_factor = state::DEFAULT_COOLDOWN_K_FACTOR;
        let mut peacetime_ewma_weight = state::DEFAULT_PEACETIME_EWMA_WEIGHT;
        let mut victim_ips: Option<String> = None;
        let mut victim_subnet: Option<String> = None;
        let mut exclude_ips_str: Option<String> = None;
        let mut k         = 2.0_f64;
        let mut alpha     = ewma::DEFAULT_ALPHA;
        let mut socket      = ipc::SOCKET_PATH.to_string();
        let mut no_filter   = false;
        let mut log_file:   Option<String> = None;
        let mut train_csv:  Option<String> = None;
        let mut train_label: u8 = 0;
        let mut baseline_path = persistence::DEFAULT_BASELINE_PATH.to_string();
        let mut baseline_ttl_secs = persistence::DEFAULT_TTL_SECS;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--interface" => {
                    i += 1;
                    interface = args.get(i).cloned().unwrap_or_default();
                }
                "--egress-interface" => {
                    i += 1;
                    egress_interface = args.get(i).cloned();
                }
                "--capture-mode" => {
                    i += 1;
                    match args.get(i).map(|s| s.as_str()) {
                        Some("pcap") => capture_mode = CaptureMode::Pcap,
                        Some("kernel") | Some("xdp") => capture_mode = CaptureMode::Kernel,
                        other => {
                            eprintln!("Error: --capture-mode takes 'pcap' or 'kernel', got {other:?}.");
                            process::exit(1);
                        }
                    }
                }
                "--bpf-object" => {
                    i += 1;
                    if let Some(v) = args.get(i) {
                        bpf_object = v.clone();
                    }
                }
                "--entropy-sigma-floor" => {
                    i += 1;
                    entropy_sigma_floor = parse_positive(args.get(i), "--entropy-sigma-floor");
                }
                "--entropy-sigma-ceiling" => {
                    i += 1;
                    entropy_sigma_ceiling = parse_positive(args.get(i), "--entropy-sigma-ceiling");
                }
                "--rate-sigma-floor" => {
                    i += 1;
                    rate_sigma_floor = parse_positive(args.get(i), "--rate-sigma-floor");
                }
                "--distributed-dominance" => {
                    i += 1;
                    distributed_dominance = parse_positive(args.get(i), "--distributed-dominance");
                }
                "--entropy-min-packets" => {
                    i += 1;
                    entropy_min_packets = parse_positive(args.get(i), "--entropy-min-packets") as usize;
                }
                "--max-sources" => {
                    i += 1;
                    max_sources = parse_positive_u64(args.get(i), "--max-sources") as u32;
                }
                "--max-flows" => {
                    i += 1;
                    max_flows = parse_positive_u64(args.get(i), "--max-flows") as u32;
                }
                "--max-protected-hosts" => {
                    i += 1;
                    max_protected_hosts = parse_positive_u64(args.get(i), "--max-protected-hosts") as u32;
                }
                "--emergency-volume-sigma" => {
                    i += 1;
                    emergency_volume_sigma = parse_positive(args.get(i), "--emergency-volume-sigma");
                }
                "--entropy-k-fallback" => {
                    i += 1;
                    entropy_k_fallback = parse_positive(args.get(i), "--entropy-k-fallback");
                }
                "--rate-sigma-ceiling-ratio" => {
                    i += 1;
                    rate_sigma_ceiling_ratio = parse_positive(args.get(i), "--rate-sigma-ceiling-ratio");
                }
                "--rate-sigma-ceiling-floor" => {
                    i += 1;
                    rate_sigma_ceiling_floor = parse_positive(args.get(i), "--rate-sigma-ceiling-floor");
                }
                "--outlier-sigma" => {
                    i += 1;
                    outlier_sigma = parse_positive(args.get(i), "--outlier-sigma");
                }
                "--rate-mean-cap" => {
                    i += 1;
                    rate_mean_cap = parse_positive(args.get(i), "--rate-mean-cap");
                }
                "--cooldown-windows" => {
                    i += 1;
                    cooldown_windows = parse_positive_u64(args.get(i), "--cooldown-windows");
                }
                "--cooldown-k-factor" => {
                    i += 1;
                    cooldown_k_factor = parse_positive(args.get(i), "--cooldown-k-factor");
                }
                "--peacetime-ewma-weight" => {
                    i += 1;
                    peacetime_ewma_weight = parse_positive(args.get(i), "--peacetime-ewma-weight");
                }
                "--victim-ip" | "--victim-ips" => {
                    i += 1;
                    victim_ips = args.get(i).cloned();
                }
                "--victim-subnet" => {
                    i += 1;
                    victim_subnet = args.get(i).cloned();
                }
                "--exclude-ips" | "--exclude-ip" => {
                    i += 1;
                    exclude_ips_str = args.get(i).cloned();
                }
                "--k" => {
                    i += 1;
                    k = args.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(2.0);
                }
                "--alpha" => {
                    i += 1;
                    alpha = args.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(ewma::DEFAULT_ALPHA);
                }
                "--socket" => {
                    i += 1;
                    socket = args.get(i).cloned().unwrap_or(ipc::SOCKET_PATH.to_string());
                }
                "--no-filter" => {
                    no_filter = true;
                }
                "--log-file" => {
                    i += 1;
                    log_file = args.get(i).cloned();
                }
                "--train-csv" => {
                    i += 1;
                    train_csv = args.get(i).cloned();
                }
                "--label" => {
                    i += 1;
                    train_label = args.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
                "--baseline-path" => {
                    i += 1;
                    baseline_path = args.get(i).cloned().unwrap_or(persistence::DEFAULT_BASELINE_PATH.to_string());
                }
                "--baseline-ttl-secs" => {
                    i += 1;
                    baseline_ttl_secs = args.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(persistence::DEFAULT_TTL_SECS);
                }
                "--help" | "-h" => {
                    print_usage(&args[0]);
                    process::exit(0);
                }
                "--version" | "-V" => {
                    println!("ddos_stage1 {}", env!("CARGO_PKG_VERSION"));
                    process::exit(0);
                }
                other => {
                    eprintln!("Unknown argument: {other}");
                    print_usage(&args[0]);
                    process::exit(1);
                }
            }
            i += 1;
        }

        // Validate required arguments.
        if interface.is_empty() {
            eprintln!("Error: --interface is required.");
            print_usage(&args[0]);
            process::exit(1);
        }

        // Capturing both sides on one interface would double-count every
        // packet and make the drop ratio meaningless.
        if egress_interface.as_deref() == Some(interface.as_str()) {
            eprintln!("Error: --egress-interface must differ from --interface.");
            process::exit(1);
        }

        // Build VictimTargets enum
        let victim_targets = if let Some(ref ip_str) = victim_ips {
            let mut list = Vec::new();
            for s in ip_str.split(',') {
                if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                    list.push(ip);
                } else {
                    eprintln!("Error: Invalid IP address '{s}' in victim list.");
                    process::exit(1);
                }
            }
            Some(VictimTargets::List(list))
        } else if let Some(ref subnet_str) = victim_subnet {
            let parts: Vec<&str> = subnet_str.split('/').collect();
            if parts.len() != 2 {
                eprintln!("Error: Invalid subnet format '{subnet_str}'. Must be IP/prefix (e.g. 10.0.0.0/24).");
                process::exit(1);
            }
            let ip = match parts[0].parse::<std::net::IpAddr>() {
                Ok(addr) => addr,
                Err(_) => {
                    eprintln!("Error: Invalid subnet IP address '{}'.", parts[0]);
                    process::exit(1);
                }
            };
            let prefix = match parts[1].parse::<u8>() {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("Error: Invalid subnet prefix '{}'.", parts[1]);
                    process::exit(1);
                }
            };
            Some(VictimTargets::Subnet { ip, prefix })
        } else {
            None
        };

        // Addresses excluded from an otherwise matching victim_targets, most
        // often the gateway's own address falling inside --victim-subnet.
        // Same comma-separated format as --victim-ips.
        let exclude_ips = if let Some(ref ip_str) = exclude_ips_str {
            let mut list = Vec::new();
            for s in ip_str.split(',') {
                if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                    list.push(ip);
                } else {
                    eprintln!("Error: Invalid IP address '{s}' in exclude list.");
                    process::exit(1);
                }
            }
            list
        } else {
            Vec::new()
        };

        Self { interface, egress_interface, victim_targets, exclude_ips, k, alpha, socket, no_filter, log_file, train_csv, train_label, baseline_path, baseline_ttl_secs, capture_mode, bpf_object,
               entropy_sigma_floor, entropy_sigma_ceiling, rate_sigma_floor, distributed_dominance,
               entropy_min_packets, max_sources, max_flows, max_protected_hosts,
               emergency_volume_sigma, entropy_k_fallback, rate_sigma_ceiling_ratio, rate_sigma_ceiling_floor,
               outlier_sigma, rate_mean_cap, cooldown_windows, cooldown_k_factor, peacetime_ewma_weight }
    }
}

/// Parse a tuning value, exiting with a readable message rather than silently
/// falling back to a default the operator did not ask for.
fn parse_positive(raw: Option<&String>, flag: &str) -> f64 {
    match raw.and_then(|v| v.parse::<f64>().ok()) {
        Some(v) if v > 0.0 && v.is_finite() => v,
        _ => {
            eprintln!("Error: {flag} needs a positive number, got {raw:?}.");
            process::exit(1);
        }
    }
}

/// Same as `parse_positive`, for tuning values that count whole windows.
fn parse_positive_u64(raw: Option<&String>, flag: &str) -> u64 {
    match raw.and_then(|v| v.parse::<u64>().ok()) {
        Some(v) if v > 0 => v,
        _ => {
            eprintln!("Error: {flag} needs a positive whole number, got {raw:?}.");
            process::exit(1);
        }
    }
}

fn print_usage(bin: &str) {
    eprintln!(
        "\nUsage: {bin} --interface <IFACE> [--victim-ips <IP1,IP2,...> | --victim-subnet <SUBNET>] [OPTIONS]\n"
    );
    eprintln!("Options:");
    eprintln!("  --interface  <IFACE>   Ingress interface to sniff (e.g., br0)");
    eprintln!("  --capture-mode <MODE>  pcap (default) or kernel. 'kernel' uses XDP and TC");
    eprintln!("                         instead of libpcap, and needs the compiled object");
    eprintln!("  --bpf-object <PATH>    eBPF object for the kernel backend");
    eprintln!("                         [default: {}]", crate::kernel::DEFAULT_OBJECT_PATH);
    eprintln!("  --max-sources <N>      Source addresses tracked per window, kernel backend");
    eprintln!("                         [default: {}]", crate::kernel::DEFAULT_MAX_SOURCES);
    eprintln!("  --max-flows <N>        Flows tracked per window, both backends");
    eprintln!("                         [default: {}]", crate::kernel::DEFAULT_MAX_FLOWS);
    eprintln!("  --max-protected-hosts <N>  Protected hosts, kernel backend");
    eprintln!("                         [default: {}]", crate::kernel::DEFAULT_MAX_PROTECTED_HOSTS);
    eprintln!("  --egress-interface <IFACE>  Egress interface. Enables drop-rate measurement");
    eprintln!("                              by comparing what arrived against what was forwarded");
    eprintln!("  --victim-ips <IPs>     BPF filter IP list, comma-separated (alias: --victim-ip)");
    eprintln!("  --victim-subnet <NET>  BPF filter subnet range (e.g. 10.0.0.0/24)");
    eprintln!("  --exclude-ips <IPs>    Comma-separated addresses carved out of the above, e.g. the gateway's own address");
    eprintln!("  --k          <FLOAT>   Anomaly multiplier k  [default: 2.0]");
    eprintln!("  --alpha      <FLOAT>   EWMA smoothing alpha  [default: 0.125]");
    eprintln!();
    eprintln!("Detection tuning (raise the entropy floor if normal traffic is being flagged):");
    eprintln!("  --entropy-sigma-floor <F>    Smallest entropy deviation used for the");
    eprintln!("                               boundary [default: {}]", state::DEFAULT_ENTROPY_SIGMA_FLOOR);
    eprintln!("  --entropy-sigma-ceiling <F>  Largest, so the boundary cannot drift so");
    eprintln!("                               wide nothing trips it [default: {}]", state::DEFAULT_ENTROPY_SIGMA_CEILING);
    eprintln!("  --rate-sigma-floor <F>       Same floor for the rate, in pps [default: {}]", state::DEFAULT_RATE_SIGMA_FLOOR);
    eprintln!("  --distributed-dominance <F>  Below this share from one source, traffic is");
    eprintln!("                               too spread out to be a flood [default: {}]", state::DEFAULT_DISTRIBUTED_DOMINANCE);
    eprintln!("  --entropy-min-packets <N>    Packets a window needs before its entropy may");
    eprintln!("                               raise an anomaly [default: {}]", state::DEFAULT_ENTROPY_MIN_PACKETS);
    eprintln!("  --emergency-volume-sigma <F> Rate deviation, in sigma, past which entropy");
    eprintln!("                               scaling of k is bypassed [default: {}]", state::DEFAULT_EMERGENCY_VOLUME_SIGMA);
    eprintln!("  --entropy-k-fallback <F>     Divisor for entropy-guided k scaling before a");
    eprintln!("                               baseline entropy is learned [default: {}]", state::DEFAULT_ENTROPY_K_FALLBACK);
    eprintln!("  --rate-sigma-ceiling-ratio <F>  Rate sigma ceiling as a fraction of the mean");
    eprintln!("                                  [default: {}]", state::DEFAULT_RATE_SIGMA_CEILING_RATIO);
    eprintln!("  --rate-sigma-ceiling-floor <F>  Floor under that ceiling, in pps");
    eprintln!("                                  [default: {}]", state::DEFAULT_RATE_SIGMA_CEILING_FLOOR);
    eprintln!("  --outlier-sigma <F>          Samples this many sigma from the mean are");
    eprintln!("                               rejected rather than folded into the baseline");
    eprintln!("                               [default: {}]", state::DEFAULT_OUTLIER_SIGMA);
    eprintln!("  --rate-mean-cap <F>          Hard ceiling on the learned mean rate, in pps");
    eprintln!("                               [default: {}]", state::DEFAULT_RATE_MEAN_CAP);
    eprintln!("  --cooldown-windows <N>       Windows of heightened sensitivity after a real");
    eprintln!("                               anomaly [default: {}]", state::DEFAULT_COOLDOWN_WINDOWS);
    eprintln!("  --cooldown-k-factor <F>      How much cooldown reduces k, floored at 1.0");
    eprintln!("                               [default: {}]", state::DEFAULT_COOLDOWN_K_FACTOR);
    eprintln!("  --peacetime-ewma-weight <F>  EWMA weight for the slow poisoning-detection");
    eprintln!("                               reference [default: {}]", state::DEFAULT_PEACETIME_EWMA_WEIGHT);
    eprintln!("  --socket     <PATH>    IPC socket path       [default: /run/ddos_stage1/stage1.sock]");
    eprintln!("  --no-filter            Disable BPF filter (dev/test only)");
    eprintln!("  --log-file   <PATH>    Path to write logs to in addition to terminal");
    eprintln!("  --train-csv  <PATH>    Write ALL post-warmup feature vectors to CSV (training mode)");
    eprintln!("  --label      <INT>     Class label for training CSV rows (0=normal, 1=flash_crowd, 2=ddos)");
    eprintln!("  --baseline-path <PATH> Persisted baseline file [default: /var/lib/ddos_stage1/baselines.json]");
    eprintln!("  --baseline-ttl-secs <N> Reject a persisted baseline older than N seconds [default: 3600]");
    eprintln!("  --help, -h             Show this message");
    eprintln!("  --version, -V          Print the version and exit");
    eprintln!();
    eprintln!("Environment:");
    eprintln!("  RUST_LOG=info|debug|warn   Log verbosity (default: info)");
    eprintln!();
    eprintln!("Requires root or CAP_NET_RAW capability for raw pcap capture.");
}

/// Open `iface` on the main thread and exit with a readable error if it
/// fails. A pcap failure here almost always means missing CAP_NET_RAW.
///
/// Done before spawning anything so the failure is loud and synchronous,
/// rather than the silent exit that happens when a capture thread dies and
/// drops the channel before analysis has processed a packet.
fn precheck_interface(iface: &str) {
    use pcap::Capture;
    let test_open = Capture::from_device(iface)
        .and_then(|inactive| inactive.snaplen(64).timeout(1).open());

    if let Err(e) = test_open {
        let msg = e.to_string().to_lowercase();
        if msg.contains("permission denied") || msg.contains("operation not permitted") {
            eprintln!();
            eprintln!("[ERROR] Permission denied opening '{iface}'");
            eprintln!("        pcap requires raw socket access. Fix with one of:");
            eprintln!("          1. Run as root:              sudo ./ddos_stage1 ...");
            eprintln!("          2. Grant capability (once):  sudo setcap cap_net_raw+ep ./ddos_stage1");
            eprintln!();
        } else {
            eprintln!("[ERROR] Cannot open interface '{iface}': {e}");
            eprintln!("        Check that the interface name is correct.");
            if let Ok(devices) = pcap::Device::list() {
                let names: Vec<_> = devices.iter().map(|d| d.name.as_str()).collect();
                eprintln!("        Available interfaces: {}", names.join(", "));
            }
        }
        process::exit(1);
    }
    // The test handle drops here. The real capture thread opens a fresh
    // one. Opening twice is fine; pcap handles are independent.
}

// main()
fn main() {
    // Parse CLI arguments first so we know if a log file is requested.
    let args = CliArgs::parse();

    // Setup logging target
    let log_file = if let Some(ref path) = args.log_file {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(file) => Some(file),
            Err(e) => {
                eprintln!("[ERROR] Failed to open log file '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    struct LogSplitter {
        file: Option<std::fs::File>,
    }

    impl LogSplitter {
        fn strip_ansi(buf: &[u8]) -> Vec<u8> {
            let mut clean = Vec::with_capacity(buf.len());
            let mut i = 0;
            while i < buf.len() {
                if buf[i] == 0x1b && i + 1 < buf.len() && buf[i + 1] == b'[' {
                    i += 2;
                    while i < buf.len() && (buf[i] < 0x40 || buf[i] > 0x7E) {
                        i += 1;
                    }
                    if i < buf.len() {
                        i += 1;
                    }
                    continue;
                }
                clean.push(buf[i]);
                i += 1;
            }
            clean
        }
    }

    impl std::io::Write for LogSplitter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let stderr = std::io::stderr();
            let mut handle = stderr.lock();
            let _ = handle.write_all(buf);

            if let Some(ref mut f) = self.file {
                let clean = Self::strip_ansi(buf);
                let _ = f.write_all(&clean);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            let _ = std::io::stderr().flush();
            if let Some(ref mut f) = self.file {
                let _ = f.flush();
            }
            Ok(())
        }
    }

    // Level comes from RUST_LOG.
    // Defaults to INFO if RUST_LOG is not set.
    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    );
    builder.write_style(env_logger::WriteStyle::Always);
    builder.format(|buf, record| {
        use std::io::Write;
        let level_style = buf.default_level_style(record.level());
        writeln!(
            buf,
            "[{} {level_style}{:<5}{level_style:#} {}] {}",
            buf.timestamp_millis(),
            record.level(),
            record.target(),
            record.args()
        )
    });
    builder.target(env_logger::Target::Pipe(Box::new(LogSplitter { file: log_file })));
    builder.init();

    info!(
        "FLOD System: Stage 1 sensor starting | version {}",
        env!("CARGO_PKG_VERSION")
    );

    // Build the capture and analysis configurations.

    // Capture config: BPF filter applied only when --no-filter is not set
    // and victim targets were provided.
    let cap_cfg = if !args.no_filter
        && let Some(targets) = args.victim_targets.as_ref()
    {
        info!("main: BPF filter enabled for targets: {:?}", targets);
        CaptureConfig::for_targets(&args.interface, targets, capture::Direction::Ingress)
    } else {
        log::warn!("main: BPF filter disabled, all traffic will be processed (dev mode only)");
        CaptureConfig::for_test(&args.interface)
    };

    // The egress side is optional, and uses the same filter as ingress:
    // what matters is traffic headed to a protected host on either side.
    let egress_cap_cfg = args.egress_interface.as_ref().map(|iface| {
        if !args.no_filter
            && let Some(targets) = args.victim_targets.as_ref()
        {
            CaptureConfig::for_targets(iface, targets, capture::Direction::Egress)
        } else {
            let mut c = CaptureConfig::for_test(iface);
            c.direction = capture::Direction::Egress;
            c
        }
    });

    let analysis_cfg = AnalysisConfig {
        k:              args.k,
        ewma_alpha:     args.alpha,
        socket_path:    args.socket.clone(),
        victim_targets: args.victim_targets.clone(),
        exclude_ips:    args.exclude_ips.clone(),
        train_csv:      args.train_csv.clone(),
        train_label:    args.train_label,
        baseline_path:      args.baseline_path.clone(),
        baseline_ttl_secs:  args.baseline_ttl_secs,
        egress_enabled:     args.egress_interface.is_some(),
        entropy_sigma_floor:   args.entropy_sigma_floor,
        entropy_sigma_ceiling: args.entropy_sigma_ceiling,
        rate_sigma_floor:      args.rate_sigma_floor,
        distributed_dominance: args.distributed_dominance,
        entropy_min_packets:   args.entropy_min_packets,
        // One flag sizes both backends, so the two stay comparable.
        max_tracked_flows:     args.max_flows as usize,
        emergency_volume_sigma:   args.emergency_volume_sigma,
        entropy_k_fallback:       args.entropy_k_fallback,
        rate_sigma_ceiling_ratio: args.rate_sigma_ceiling_ratio,
        rate_sigma_ceiling_floor: args.rate_sigma_ceiling_floor,
        outlier_sigma:            args.outlier_sigma,
        rate_mean_cap:            args.rate_mean_cap,
        cooldown_windows:         args.cooldown_windows,
        cooldown_k_factor:        args.cooldown_k_factor,
        peacetime_ewma_weight:    args.peacetime_ewma_weight,
    };

    // Before the interface check, so a configuration mistake is reported even
    // when the interface itself is what fails.
    analysis::log_effective_tuning(&analysis_cfg);

    // The kernel backend replaces the capture threads entirely: no pcap
    // handles, no channel, and the analysis loop drains maps on its own tick.
    if args.capture_mode == CaptureMode::Kernel {
        let targets = match args.victim_targets.as_ref() {
            Some(t) => t,
            None => {
                eprintln!("Error: the kernel backend needs --victim-ips or --victim-subnet.");
                eprintln!("It matches on protected hosts in the kernel, so there is no");
                eprintln!("equivalent of running without a filter.");
                process::exit(1);
            }
        };

        info!("main: capture backend = kernel (XDP and TC)");
        let capture = match kernel::KernelCapture::load(
            &args.bpf_object,
            &args.interface,
            args.egress_interface.as_deref(),
            targets,
            &args.exclude_ips,
            kernel::MapSizes {
                sources: args.max_sources,
                flows: args.max_flows,
                protected_hosts: args.max_protected_hosts,
            },
        ) {
            Ok(c) => c,
            Err(e) => {
                log::error!("main: could not start the kernel backend: {e}");
                log::error!("main: build the object with scripts/build-ebpf.sh, or run with");
                log::error!("main: --capture-mode pcap to use the libpcap backend instead.");
                process::exit(1);
            }
        };

        analysis::run_analysis_thread(
            analysis_cfg,
            analysis::PacketSource::Kernel(Box::new(capture)),
        );
        return;
    }

    info!("main: capture backend = pcap");

    // Privilege pre-check: attempt to open the interface NOW, on the main
    // thread, before spawning anything. If pcap fails here it almost always
    // means missing CAP_NET_RAW (not running as root).
    //
    // Doing this early gives us a loud, synchronous error message instead of
    // the silent exit that happens when the capture thread dies and drops the
    // crossbeam channel before the analysis thread ever processes a packet.
    precheck_interface(&cap_cfg.interface);
    if let Some(cfg) = egress_cap_cfg.as_ref() {
        precheck_interface(&cfg.interface);
    }

    info!(
        "main: config | interface={} | k={} | α={} | socket={}",
        cap_cfg.interface, analysis_cfg.k, analysis_cfg.ewma_alpha, analysis_cfg.socket_path
    );

    // Create the bounded crossbeam channel connecting capture → analysis.
    let (tx, rx) = bounded(capture::CHANNEL_CAPACITY);

    info!(
        "main: channel capacity = {} packets",
        capture::CHANNEL_CAPACITY
    );

    // Spawn the analysis thread first so it is ready to consume from the
    // channel before the capture thread starts flooding it.
    let analysis_handle = std::thread::Builder::new()
        .name("analysis".to_string())
        .spawn(move || {
            analysis::run_analysis_thread(analysis_cfg, analysis::PacketSource::Channel(rx));
        })
        .expect("failed to spawn analysis thread");

    // Run the capture thread on the *current* thread (main thread).
    // This blocks indefinitely.  The analysis thread runs in the background.
    //
    // Rationale: running capture on main keeps it easy to handle SIGINT/SIGTERM
    // from the OS. When the process is killed, main unblocks and the `tx`
    // Sender is dropped, which closes the channel and causes the analysis
    // thread to exit cleanly.
    // V5: the egress sensor runs on its own thread with a cloned sender,
    // feeding the same analysis loop so both sides share one window
    // boundary and one clock. Spawned before ingress takes over main.
    let egress_running = egress_cap_cfg.is_some();
    if let Some(cfg) = egress_cap_cfg {
        let egress_tx = tx.clone();
        let iface = cfg.interface.clone();
        std::thread::Builder::new()
            .name("capture-egress".to_string())
            .spawn(move || {
                capture::run_capture_thread(cfg, egress_tx);
                log::warn!("main: egress capture thread on '{iface}' exited");
            })
            .expect("failed to spawn egress capture thread");
    }

    capture::run_capture_thread(cap_cfg, tx);

    // Capture thread exited (channel closed or pcap error).
    // Wait for the analysis thread to drain and exit cleanly.
    info!("main: capture thread exited; waiting for analysis thread to finish...");

    // With an egress thread alive the channel still has a live sender, so
    // the analysis loop would never see a disconnect and the join below
    // would block forever. Normal shutdown is a signal from systemd, which
    // takes the whole process down anyway; this path only runs when ingress
    // pcap fails outright, and exiting is the honest response.
    if egress_running {
        log::warn!("main: ingress capture ended while egress is still running; exiting.");
        process::exit(1);
    }

    if let Err(e) = analysis_handle.join() {
        log::error!("main: analysis thread panicked: {e:?}");
        process::exit(1);
    }

    info!("main: clean shutdown complete.");
}
