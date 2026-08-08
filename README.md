# FLOD System

**First Line Of Defense**

An adaptive two stage Layer 4 volumetric DDoS mitigation gateway.

**Author:** Abdullah Armiyao

**Project:** Adaptive Two-Stage Framework for Near Real-Time Layer-4 Volumetric DDoS Mitigation Using Behavioral Traffic Analysis


## Authorship

This project is my own. The concept, the architecture, the two-stage design, the detection approach, the enforcement policy, the feature set, and every functional decision across all versions originated with me. I built it as a learning exercise in network security, statistical detection, and systems programming, and I directed its design and evolution throughout.

I used AI as a coding assistant during implementation — writing and refactoring code to my specifications, and acting as a sounding board while I worked through design trade-offs. The decisions about what to build, why, and how the system should behave were mine; the assistance was in translating those decisions into code faster than I would have unaided.


## What This Project Is

Most DDoS mitigation systems use **static thresholds** — hard-coded numbers like "block any IP sending more than 1000 packets/sec." The problem is that your legitimate traffic might naturally spike to 1000 pps during a registration rush, so those systems either miss real attacks or block real users.

This project solves that by building a gateway that **learns what your normal traffic looks like** and adapts its detection boundaries accordingly. It can tell the difference between a DDoS flood and a flash crowd (a legitimate traffic surge) without a human adjusting thresholds.

**Scope:** this project targets **Layer 4 volumetric floods** that are distinguishable from packet headers alone, using rate, source-IP entropy, protocol distribution, and dominant-source concentration. In practice that means floods which are both high-volume and **concentrated**: SYN, UDP, or ICMP floods arriving from a bounded set of real source addresses, including reflected and amplified traffic returning from a finite set of reflectors.

Two classes are explicitly **not** covered:

- **Randomized-source spoofing.** Forging a fresh source address per packet inverts the signature the detector looks for, raising entropy instead of lowering it. See "Shannon Source-IP Entropy" below for why, and what it would take to fix. Planned for V7.
- **Application-layer attacks.** No L7 content is parsed, so low-and-slow request floods, connection-exhaustion attacks such as Slowloris, and anything that looks ordinary at the packet level but is malicious at the request level are outside what a header-only feature set can observe.

The system is split into two stages:

- **Stage 1 (Rust):** Sits inline on the network bridge, watches every packet, runs lightweight statistics, and raises an anomaly flag when something looks wrong.
- **Stage 2 (Python):** Wakes up only when Stage 1 flags something (or on a periodic heartbeat), runs a Random Forest classifier to confirm whether it's a real attack or a flash crowd, and issues kernel-level drop rules (`ddos_blocklist` ipset) or rate limits (`ddos_ratelimit` ipset using iptables hashlimit) in real time. It also hosts a persistent FastAPI-based dashboard.


## Network Topology and Virtualization Gotchas

In virtualized hypervisor environments (like Proxmox VE), the layout of your network bridges directly controls what traffic the Sensor VM can inspect.

### The Virtual Switch Subnet Bypass Gotcha
If the **Attacker VM** and **Victim VM** are placed on the same virtual bridge (e.g., `<BRIDGE_1>`) and share the same IP subnet (e.g., `<SUBNET_A>`):
1. They communicate directly host-to-host at Layer 2. The hypervisor's virtual switch learns their MAC addresses and forwards packets directly between their virtual ports.
2. Even if the Sensor VM is configured as their default gateway, **local subnet traffic bypasses the gateway**. 
3. The Sensor VM's ingress NIC receives 0% of the unicast flood traffic. It will only capture broadcast packets (like ARP requests) or traffic sent directly to the Sensor's own IP.

---

### The Routed Subnet Setup (`<SUBNET_A>` -> `<SUBNET_B>`)

To ensure the Sensor VM can inspect and filter all traffic, the Attacker and Victim are separated into two distinct subnets connected by the Sensor VM acting as an IP Router:

```
[ Attacker / Flash Crowd ]             [ Sensor VM / Gateway ]                 [ Victim VM ]
  (Subnet: <SUBNET_A>)                 (Router/Firewall Gateway)          (Subnet: <SUBNET_B>)
  (IP: <ATTACKER_IP>)                              │                      (IP: <VICTIM_IP>)
         │                                         │                            │
    [<BRIDGE_1>] <────────────────────────────> [<INGRESS_IFACE>]              │
   (LAN Segment 1)                       (IP: <GATEWAY_IP_A>)                   │
                                                 [<EGRESS_IFACE>] <───────> [<BRIDGE_2>]
                                         (IP: <GATEWAY_IP_B>)               (LAN Segment 2)
```

*   **How it works:** The Attacker VM wants to target the Victim VM. Because they are on different subnets, the Attacker is forced to route the traffic through its default gateway — the Sensor VM's ingress interface.
*   **Where to capture:** Run `ddos_stage1` on the **ingress interface** where the flood traffic first enters the gateway.

---

## The Three-Layer Pipeline (Stage 1)

Every packet that enters the ingress interface addressed to the victim goes through this pipeline:

```
[ Packet arrives on ingress interface ]
         │
         │  BPF filter: dst host <victim_ip>  (kernel drops everything else)
         ▼
[ Stage 0: Capture Thread ]
   pcap reads raw frame → etherparse extracts src_ip + timestamp
   → sends PacketMeta over crossbeam channel →
         │
         ▼
[ LAYER 1: per-packet — Analysis Thread ]
   └── EntropyAccumulator::add(src_ip)   increments IP frequency counter
         │
         │  (window closes at >= 0.5s & 20 pkts, or 1.0s max)
         ▼
[ LAYER 2: per-window ]
   ├── h = entropy.compute_and_reset()   → diversity scalar  [0.0 .. 1.0] (Normalized)
   └── r = ewma.update(window_duration)  → rate scalar       [0.0 .. ∞ pps]
         │
         ▼
[ LAYER 3: per-window ]
   ├── welford_rate.update(r)
   ├── welford_entropy.update(h)
   ├── if r  >  μ_rate    + k·σ_rate    → FLAG_RATE_ANOMALY    (flood)
   └── if h  <  μ_entropy − k·σ_entropy → FLAG_ENTROPY_ANOMALY (concentrated source)
         │
         │  (only fires after warm-up AND at least one flag is set)
         ▼
[ IPC: FeatureVector → Unix Domain Socket → Stage 2 Python ]
```

---

## Key Building Blocks Explained

### 1. Welford's Online Variance Algorithm

**File:** `stage1/src/welford.rs`

**The problem it solves:** You need to track the running mean and standard deviation of a stream of numbers (packet rates, entropy scores) without storing every past value. The naïve approach — accumulate `sum` and `sum_of_squares`, then compute variance — causes **catastrophic cancellation**: two huge numbers almost cancel each other, leaving a near-zero or even *negative* result due to floating-point errors.

**How Welford works:**

Each time a new sample `x` arrives, run exactly these five steps:

```
n     += 1
delta  = x - mean          ← surprise vs the OLD mean
mean  += delta / n         ← shift the centre toward x
delta2 = x - mean          ← surprise vs the NEW mean
M2    += delta * delta2    ← accumulate the cross-product
```

Then: `variance = M2 / (n - 1)`

**Why two deltas?** `delta` measures how surprising `x` was *before* the mean moved. `delta2` measures how far `x` still is *after* the mean stepped toward it. Their product is the exact algebraic correction that transitions the sum-of-squares from the old mean to the new mean in one step, with no stored history and no cancellation.

**Recency cap:** After weeks of running, `n` becomes enormous and `delta/n ≈ 0`, freezing the mean. The implementation caps `n` at 500 (`MAX_N`) so the algorithm stays sensitive to recent traffic patterns — once capped, every new sample still runs the full update above, but `M2` also receives an exponential decay to stay consistent with the mean's fixed recency window. **This makes the accumulator a bounded-memory approximation of Welford's algorithm once capped, not exact running variance** — cite it as such rather than as a direct implementation of Welford (1962). The cap is paired with a *freeze-on-anomaly* rule (Stage 1 stops feeding samples into the accumulator during an active anomaly or cooldown, see "Core Safeguards" below) — the two are complementary: the cap alone would make the baseline more poisonable (shorter memory, easier for a slow-ramp attacker to shift), and the freeze is what makes that trade-off safe.

**Warm-up:** The first 200 windows are discarded from anomaly evaluation. Welford's variance is meaningless on 2–3 samples.

**Golden test:** `[4, 7, 13, 16]` → mean = 10.0, variance = 30.0 exactly.

---

### 2. Exponentially Weighted Moving Average (EWMA)

**File:** `stage1/src/ewma.rs`

**The problem it solves:** You need a *rate* (packets per second) that reacts quickly to floods but isn't thrown off by a single bursty packet interval or scheduling delays.

**How it works (Jitter-Resistant design):**
Instead of updating the EWMA rate per packet (which suffers from massive timing jitter spikes due to OS interrupt coalescing or virtualization scheduling), Stage 1 calculates the rate **once per hybrid time window** using the window's exact elapsed time:
```
window_rate = actual_packets_received / window_duration_seconds
ewma_new    = α · window_rate + (1 − α) · ewma_old
```

`α` (alpha) controls responsiveness, and is CLI-configurable (`--alpha`, see Usage below) rather than a fixed constant:
- High α → reacts fast, noisier
- Low α → smooth, slower reaction
- Default: `α = 0.125` — a conventional starting point for exponential smoothing, not a value proven optimal for this specific traffic-rate use case.

**Critical behaviour — EWMA never resets.** Unlike entropy (which is computed fresh each window), the EWMA carries memory *across* windows by design. A DDoS flood that ramps up gradually across multiple windows is still detected because the EWMA accumulates the rising rate over time.

**What it produces:** One scalar `r` per window close — the current smoothed packet rate in packets/second. This `r` feeds directly into the Welford accumulator for rate tracking.

---

### 3. Shannon Source-IP Entropy

**File:** `stage1/src/entropy.rs`

**The problem it solves:** Raw packet count can't distinguish a DDoS from a flash crowd — both produce high volume. Unique IP count misses distribution shape — ten IPs each sending five packets looks the same as one IP sending 41 packets and nine others sending one each. Shannon Entropy captures the *full probability distribution* of source IPs in a single number.

**The formula (Normalized Entropy):**

```
H_raw = −Σ p(xᵢ) · log₂(p(xᵢ))
H_norm = H_raw / log₂(N)   (where N is number of unique IPs)
```

Where `p(xᵢ)` is the fraction of packets in the current window that came from IP `xᵢ`.

**Interpretation (Independent of Traffic Volume):**

| Scenario | Normalized Entropy |
|---|---|
| All packets from one IP | **0.00** (total concentration — DDoS) |
| Packets somewhat mixed | **~0.50** |
| Packets evenly spread across all IPs | **1.00** (maximum diversity — normal/flash crowd) |

**Why entropy *drops* during a concentrated flood:** when a small number of sources produce most of the traffic, the distribution collapses and entropy falls toward zero. Layer 3 fires when entropy drops *below* `μ − k·σ` rather than above it.

**Spoofing moves entropy the other way, and that is a real gap.** A randomized-source flood, which is what most SYN and UDP floods look like in practice, forges a different source address on nearly every packet. That *raises* source-IP entropy toward 1.0 and drives `dominant_ip_ratio` toward 0, so it presents as the opposite of the signature above. Two consequences follow, and neither is hypothetical:

- The entropy alarm cannot fire, because entropy is high rather than low.
- The rate alarm is actively harder to trip. The entropy-guided scaling in `analysis.rs` widens `k` when entropy is high, so a high-entropy flood raises its own detection threshold. Only the fixed `block_sigma_multiplier` emergency bar (default 10σ) still applies.

A randomized-source flood below that emergency bar will therefore tend to be classified Flash Crowd rather than DDoS. Enforcement would not help much even if it were: blocking or rate-limiting forged addresses punishes whoever really owns them and leaves the attacker untouched, since the attacker is not at those addresses.

**What this means for scope.** Floods that are volumetric *and* concentrated (a bounded set of real sources, a reflected or amplified flood arriving from a finite set of reflectors) are handled. Randomized-source spoofing is **not currently detected**, despite being Layer 4 volumetric. Closing it needs features this pipeline does not extract, since every one of them is invariant under source-IP forgery: source-port entropy, TTL variance, and TCP option fingerprint diversity. That work is V7, not a configuration change.

**Critical behaviour — entropy resets every window.** The HashMap is cleared after each computation. Entropy measures the diversity of *this* specific window, not a historical trend. The long-run trend is tracked by the Welford accumulator.

---

### 4. The Anomaly Boundary: μ ± k·σ

**Files:** `stage1/src/welford.rs`, `stage1/src/analysis.rs`, `stage1/src/state.rs` (`AnalysisConfig.k`)

After Welford processes enough windows to establish a baseline, Layer 3 compares each new scalar against a dynamic boundary:

| Metric | Anomaly direction | Meaning |
|---|---|---|
| EWMA rate `r` | `r > μ_rate + k·σ_rate` | Rate spiked above normal → flood |
| Entropy `h` | `h < μ_entropy − k·σ_entropy` | Diversity collapsed → concentrated source |

`k = 2.0` by default (two standard deviations), configurable via `--k`. This covers ~95% of a normal distribution — values outside it are statistically unusual.

**The anomaly flags bitmask:**
- `0x01` — rate only tripped (volumetric, diverse sources → possible flash crowd)
- `0x02` — entropy only tripped (concentrated source, lower volume)
- `0x03` — **both tripped** (high volume + concentrated source → highest-confidence DDoS)

Stage 2 uses this flag plus four additional features in the Random Forest to make the final call.

---

### 5. IPC: Feature Vector Wire Format

**File:** `stage1/src/ipc.rs`

When Stage 1 flags an anomaly, it serialises a `FeatureVector` struct and sends it over a Unix Domain Socket to Stage 2 (Python).

The wire format is **exactly 184 bytes, little-endian**:

| Offset | Size | Field | Type | Description |
|---|---|---|---|---|
| 0 | 8 bytes | `entropy` | f64 | Shannon source IP entropy |
| 8 | 8 bytes | `ewma_rate` | f64 | EWMA packet rate (pps) |
| 16 | 8 bytes | `mean_h` | f64 | Running mean of entropy |
| 24 | 8 bytes | `mean_r` | f64 | Running mean of EWMA rate |
| 32 | 8 bytes | `sigma_h` | f64 | Standard deviation of entropy |
| 40 | 8 bytes | `sigma_r` | f64 | Standard deviation of EWMA rate |
| 48 | 8 bytes | `proto_ratio` | f64 | TCP packet ratio (legacy) |
| 56 | 8 bytes | `dominant_ip_ratio` | f64 | Ratio of packets from busiest IP |
| 64 | 8 bytes | `timestamp` | f64 | UNIX timestamp of window close |
| 72 | 8 bytes | `proto_tcp` | f64 | TCP packet ratio |
| 80 | 8 bytes | `proto_udp` | f64 | UDP packet ratio |
| 88 | 8 bytes | `proto_icmp` | f64 | ICMP packet ratio |
| 96 | 8 bytes | `proto_sctp` | f64 | SCTP packet ratio |
| 104 | 8 bytes | `proto_gre` | f64 | GRE packet ratio |
| 112 | 8 bytes | `proto_esp` | f64 | ESP packet ratio |
| 120 | 8 bytes | `k_multiplier` | f64 | Operative anomaly-boundary multiplier for this window (`cfg.k`, halved during cooldown recovery) |
| 128 | 8 bytes | `cooldown_counter` | f64 | Windows remaining in cooldown recovery (0–10) |
| 136 | 8 bytes | `egress_rate` | f64 | **V5:** pps measured on the egress side, i.e. what reached the victim (`-1.0` = no egress sensor) |
| 144 | 8 bytes | `drop_ratio` | f64 | **V5:** share of arriving traffic that never got through, 0.0–1.0 (`-1.0` = no egress sensor) |
| 152 | 16 bytes | `dominant_ip` | [u8; 16] | Busiest source IP (IPv6 or mapped IPv4) |
| 168 | 16 bytes | `victim_ip` | [u8; 16] | Monitored victim IP address |

Python unpacks it with: `struct.unpack('<19d16s16s', data)`

The V5 fields use `-1.0` rather than `0.0` as their "not measured" sentinel, because a genuine 0% drop ratio is a meaningful reading — it means enforcement is not removing anything — and must stay distinguishable from having no egress sensor at all. Stage 2 converts `-1.0` to `None` on receipt.

**This is a breaking wire-format change.** Both stages must be deployed together; a Stage 2 still expecting 168 bytes will misparse every window.

`k_multiplier` and `cooldown_counter` exist so Stage 2 never has to guess Stage 1's live sensitivity: earlier versions hardcoded `2.0`/`0` on the Python side for these, which silently diverged from Stage 1's real (and cooldown-adjusted) `k` the moment `--k` was set to anything non-default. Stage 2 now uses the transmitted `k_multiplier` for its own anomaly-boundary and mitigation-threshold checks instead of a fixed constant.

Fields are written manually with `byteorder` rather than transmuting the Rust struct directly. This eliminates invisible padding bugs — Rust structs can insert alignment padding that `struct.unpack` wouldn't know about.

---

### 6. The Capture Thread, BPF, and Memory Tuning

**File:** `stage1/src/capture.rs`

**Why a separate thread?** If packet capture and analysis ran in the same thread, every 50-packet window calculation (calculating floating-point entropy and writing to sockets) would stall the capture loop. Under a 100k pps flood, even microseconds of stall overflow the kernel's raw socket buffer, leading to silent drops.

**The solution:** Two threads connected by a bounded `crossbeam-channel`:
- **Capture thread** calls `pcap::next_packet()` in a tight loop, parses headers with `etherparse`, and sends `PacketMeta` into the channel. It never blocks on calculations.
- **Analysis thread** receives from the channel and executes Layers 1–3.

#### Berkeley Packet Filter (BPF) — In-Kernel Gatekeeping
Our Rust tool applies the filter `"dst host <victim_ip> or (vlan and dst host <victim_ip>)"` using the kernel's native BPF engine:
*   **The Analogy (The Mailroom Sorter):** Imagine a huge corporate building (the OS). If you don't use BPF, the mailroom clerk (the kernel) must load every junk letter onto the elevator, ride to the top floor, and dump them on the CEO's desk (user-space Rust process) to be sorted. With BPF, a fast mechanical scanner sits on the basement loading dock. It scans the envelopes and shreds non-victim letters instantly. The elevator is never clogged.
*   **The Tech:** The user-space filter compiles to BPF bytecode. The Linux kernel verifies the code for safety and uses a **Just-In-Time (JIT) compiler** to turn it into native x86 machine instructions. Packets matching the filter are cloned to our raw socket; everything else is discarded instantly in the kernel network driver.

#### High-Speed Capture Performance Tuning
To keep up under load without dropping packets, the capture module is tuned with three parameters:
1.  **Reduced Snaplen (`snaplen = 256` bytes):** Instead of copying the full frame to user-space, only the first 256 bytes are copied. That covers the Ethernet, VLAN, IPv4/IPv6, and TCP/UDP headers, which is all the analysis layer reads.
2.  **Immediate Mode (`immediate_mode = true`):** Bypasses the kernel's internal buffering window. Packets are flushed to the socket buffer instantly rather than waiting for block retirement.
3.  **Scaled Socket Buffer (`buffer_size = 128MB`):** Pins a 128MB ring buffer in kernel memory to act as a runway. At a 256-byte snaplen that holds roughly 500,000 captured headers, so a brief scheduling stall in the Rust process does not cost packets.

---

### 7. Why a Hybrid Architecture? (Rust vs. Python)

One might ask: *If the Rust pre-filter is running in user-space anyway, why not write the entire system in Python?* 

The answer lies in the **Global Interpreter Lock (GIL)** and **runtime overhead**:

*   **Python's Limitations under Flood:** Python is interpreted, garbage-collected, and bound by the GIL (only one thread can execute bytecode at a time, even on multi-core systems). Allocating an object and running a Scapy or PyShark parser for every arriving packet puts a hard ceiling on per-packet throughput, and that ceiling is reached long before a volumetric flood is exhausted.
*   **Rust's Efficiency:** Rust compiles to native code, has no garbage collector, and parses packet headers without copying them. The per-packet path has no allocation and no interpreter in it.
*   **The Division of Labor:**
    *   **Stage 1 (Rust):** Sees every packet. It condenses a window's worth of traffic into a single summary `FeatureVector`.
    *   **Stage 2 (Python):** Sees **one Feature Vector per window**, roughly one to two per second per victim. At that rate Python's per-object overhead is irrelevant, which is what makes it safe to use `scikit-learn` and `pandas` here.

No throughput figures are quoted because none have been measured on this system. The argument above is architectural: the per-packet path avoids the interpreter and the allocator entirely, and the classifier only ever sees aggregates.

---

### 8. Baseline Persistence Across Restarts (V4)

**File:** `stage1/src/persistence.rs`

**The problem it solves:** every victim's Welford/EWMA baseline lives only in memory. Any restart — a crash, a redeploy, a reboot — wipes it, forcing a fresh ~200-window warm-up. The real risk isn't just the downtime: if the restart happens *while an attack is already running*, the new warm-up period starts building "normal" directly out of attack traffic, since there's no prior peacetime reference to anchor it — poisoning the baseline from the first sample.

**Why only clean windows get persisted:** the periodic save is triggered from the exact same gate that already decides whether to feed a sample into Welford live (`anomaly_flags == 0 && cooldown_counter == 0`). That guarantees the file on disk can never be a mid-attack snapshot — worst case, a crash mid-flood just reloads whatever the last known-good baseline was *before* the flood started.

**Why it doesn't wait for a clean shutdown:** a SIGTERM-only save does nothing if power is simply lost with no warning. The real durability mechanism is a periodic snapshot (every 45s, only on clean windows) — worst case you lose the last ~45s of drift, never the whole baseline. Every write is atomic (temp file + rename, the same pattern already used for `/run/ddos_stage1/active_flows.json`), so a power loss mid-write can only ever leave the previous complete file in place, never a corrupted one. If the file is ever missing or fails to parse on load, that's treated identically to "no prior baseline" — a fresh warm-up, not a crash.

**Why a 1-hour TTL, not indefinite:** the live recency cap (`MAX_N` = 500 windows, roughly 4–8 minutes of continuous traffic) already treats anything older as not fully trustworthy. Reloading a multi-hour-old baseline would both contradict that recency philosophy and risk resurrecting a baseline from a different point in the daily traffic cycle (an overnight-quiet baseline reloaded into a busy afternoon) — a distinct failure mode from the one V4 exists to fix. The default (`--baseline-ttl-secs`, 3600) is sized for "the process just restarted," not "resume from last week."

**What's persisted, and where:** per victim — both Welford accumulators (rate + entropy: `n`, `mean`, `m2`), the EWMA smoothed rate, the cooldown counter, and both peacetime drift references. Stored as one JSON file (`--baseline-path`, default `/var/lib/ddos_stage1/baselines.json` — deliberately **not** `/tmp`, since the entire point is surviving a reboot).

---

### 9. Egress Processing and Drop Measurement (V5)

**Files:** `stage1/src/capture.rs`, `stage1/src/analysis.rs`, `stage2/static/index.html`

**The problem it solves:** before V5, "did the mitigation work?" could only be *inferred*. The gateway logged that it called `block_ip()`, and everything downstream assumed the traffic stopped. Nothing ever measured whether it actually did.

Because the sensor sits as a router between two subnets, both halves of that question are directly observable: the ingress interface carries what arrived, and the egress interface carries what was forwarded on after filtering. The difference between them is the drop rate — measured, not assumed.

```
[ Attacker ]───► <INGRESS_IFACE> ──► netfilter (FORWARD) ──► <EGRESS_IFACE> ───► [ Victim ]
                       │                      │                     │
                  ingress sensor      block / rate-limit       egress sensor
                  (what arrived)        happens here          (what got through)
```

**One process, two capture threads — not two processes.** Both sensors feed the same analysis loop through a cloned crossbeam sender, so they share one window boundary and one clock. Two separate Stage 1 processes would each keep their own 10-second window on their own timer; those windows drift apart, and subtracting egress from ingress would compare mismatched slices of time — noisiest exactly when traffic is changing fastest, which is when the number matters.

**Egress never feeds detection.** Egress packets increment a per-victim counter and nothing else. They are excluded from entropy, the source-IP histogram, the Welford baselines, the window-close decision, and `active_flows.json`. This is deliberate: egress traffic is *downstream of the gateway's own enforcement*, so letting it into the statistics would let past mitigation decisions influence future ones. Detection stays driven purely by what arrives.

For the same reason, `drop_ratio` is **not** an ML feature and `FEATURE_COLS` is unchanged. It is high precisely *because* something was already blocked; feeding it to the classifier would train the model to predict its own past decisions rather than the traffic. The existing model and training datasets remain valid.

**Enabling it:** pass `--egress-interface <IFACE>` alongside `--interface`. It is entirely optional — omit it and the sensor behaves exactly as it did in V4, with the egress fields reported as "unavailable" rather than as a 0% drop rate. The dashboard shows the ingress/egress comparison in a **Mitigation Effectiveness** panel with a show/hide toggle. That toggle controls the panel's visibility only; egress capture is a Stage 1 launch flag, and there is no control channel from the dashboard back to Stage 1.

---

### 10. NAT-Safe Enforcement (V5)

**Files:** `stage2/enforcement.py`, `stage2/api.py`, `stage2/static/firewall.html`

`ddos_blocklist` is an unconditional `DROP` matched on **source IP**. When the source is a carrier NAT, corporate egress point, or proxy, a single ipset entry therefore cuts off *every* legitimate user sharing that address.

Addresses marked as shared (Firewall → **Shared / NAT Addresses**, stored in `shared_ips.json`) are never added to `ddos_blocklist`. `block_ip()` detects the mark and delegates to `ratelimit_ip()` instead, so the source is throttled rather than dropped outright.

**What this does and does not fix.** Both enforcement sets match on source IP in the `INPUT`/`FORWARD` chains, and the `hashlimit` rule uses `--hashlimit-mode srcip` — one bucket per address. Everyone behind a shared IP therefore shares one throttle. This is **harm reduction, not a solution**: legitimate users behind that address still see degraded service, they just are not disconnected entirely.

The underlying problem is that source attribution is destroyed at the gateway and only the NAT operator can resolve it. That is what V9's federated peer signalling is for — asking the network that owns the address to identify the offending host locally. Improving the *detection* side, so a large NAT crowd stops resembling a single-source flood in the first place, needs per-flow features the pipeline does not yet extract (source-port entropy, TTL variance, TCP fingerprint diversity) and belongs with the V7 classifier work.

---

## Project File Structure

```
DDoS Reduction Project/
├── README.md                       ← this file
├── stage1/                         ← Stage 1: Rust binary
│   ├── Cargo.toml                  ← dependencies and build profile
│   └── src/
│       ├── main.rs                 ← CLI, privilege check, thread orchestrator
│       ├── capture.rs              ← Stage 0: pcap capture thread
│       ├── analysis.rs             ← Three-layer pipeline (run_analysis_thread)
│       ├── state.rs                ← AnalysisConfig + per-victim TargetState
│       ├── welford.rs              ← Welford online variance accumulator
│       ├── ewma.rs                 ← EWMA rate estimator
│       ├── entropy.rs              ← Shannon entropy calculator
│       ├── ipc.rs                  ← Binary IPC serialisation → Python
│       └── persistence.rs          ← V4: baseline persistence across restarts
├── stage2/                         ← Stage 2: Python classifier + web console
│   ├── requirements.txt            ← Python dependencies
│   ├── setup_admin.py              ← Interactive admin account provisioning
│   ├── train.py                    ← Random Forest training (LOSO evaluation)
│   ├── stage2.py                   ← Entrypoint: app assembly + main()
│   ├── storage.py                  ← Generic JSON file read/write helpers
│   ├── state.py                    ← Shared in-memory state (sessions, metrics, blocklists)
│   ├── config.py                   ← Path constants + enforcement_config.json load/save
│   ├── models.py                   ← Pydantic request payloads + IP validator
│   ├── db.py                       ← SQLite audit-log writers
│   ├── enforcement.py              ← ipset/iptables control, block/ratelimit/unblock
│   ├── auth.py                     ← Login/logout, session middleware, bcrypt, rate-limit
│   ├── ipc_receiver.py             ← Unix socket listener + classification/tier dispatch
│   ├── reports.py                  ← CSV/PDF incident report export routes
│   ├── users.py                    ← Admin account management routes
│   ├── alerts.py                   ← Discord webhook + SMTP alert dispatch
│   ├── api.py                      ← Dashboard state/history/whitelist/victim/shared-IP routes
│   └── static/                     ← Dashboard HTML/CSS/JS
└── scripts/
    ├── install.sh                  ← Linux installer (Debian/Ubuntu, RHEL, Alpine)
    ├── install.bat                 ← Windows installer (dev/test only)
    ├── update.sh                   ← Atomic update script
    ├── run.sh                      ← Unified dev runner for both stages
    └── uninstall.sh                ← Full teardown script
```

---

## Installation

### Linux (Debian/Ubuntu, RHEL/Fedora, Alpine)

```bash
# Installs interactively (prompts for interface and targets if run in a terminal):
sudo bash scripts/install.sh

# Or install non-interactively using explicit targets:
sudo bash scripts/install.sh --interface <IFACE> --victim-ips <VICTIM_IP_1>,<VICTIM_IP_2> --victim-subnet <SUBNET>
```

This will:
1. Detect your OS and install `libpcap-dev` + build tools
2. Prompt for or parse the network interface and victim IPs/subnet
3. Install Rust via `rustup` if not present
4. Compile Stage 1 in release mode
5. Install the binary to `/usr/local/bin/ddos_stage1`
6. Grant `CAP_NET_RAW` so it runs without `sudo`
7. Create the `ddos-stage1` service account and `ddos-ipc` group, and set up `/var/lib/ddos_stage1` and `/run/ddos_stage1` with the right ownership (see "Security Hardening" below — Stage 1 no longer needs to run as root)
8. Set up the Stage 2 Python virtual environment and prompt for an admin username/password (`setup_admin.py` — there is no default credential)
9. Generate a self-signed TLS certificate for the management console (`/etc/ddos_stage2/tls/`) if `openssl` is available
10. Install and configure systemd service units (`ddos-stage1` running as `ddos-stage1`, `ddos-stage2` running as `root` for `ipset`/`iptables`)

### Windows (Development / Testing Only)

```bat
install.bat
```

> **Note:** Windows does not support Linux bridges or `ipset`. The statistical engine and unit tests work, but production deployment requires Linux.

---

## Usage

### Interactive Testing (Run Both Stages Together)

For testing environments or manual execution, a unified runner script is provided in the project root. This starts the Stage 2 Python ML engine in the background, waits for its IPC socket to initialize, starts the Stage 1 Rust capture filter in the foreground, and handles graceful teardown on `Ctrl+C`:

```bash
# Start both stages with default settings (reads interface/victim IP from
# the systemd unit's configured flags, or prompts if run interactively)
sudo ./run.sh

# Start both stages with custom settings
sudo ./run.sh --interface <IFACE> --victim-ip <VICTIM_IP>
```

### Individual Components Usage

If you prefer to run the components separately:

#### 1. Stage 1 Rust Pre-Filter
```bash
# Production (on sensor VM, specifying multiple IPs or a subnet)
sudo ddos_stage1 --interface <IFACE> --victim-ips <VICTIM_IP_1>,<VICTIM_IP_2>
sudo ddos_stage1 --interface <IFACE> --victim-subnet <SUBNET>

# V5: also watch the egress side to measure how much traffic is actually dropped
sudo ddos_stage1 --interface <INGRESS_IFACE> --egress-interface <EGRESS_IFACE> \
                 --victim-ips <VICTIM_IP_1>,<VICTIM_IP_2>
```
# All options
ddos_stage1 --interface <IFACE>       # required (ingress side)
            --egress-interface <IFACE> # V5: egress side, enables drop measurement (optional)
            --victim-ips <IPs>        # BPF filter IP list (comma-separated, alias: --victim-ip)
            --victim-subnet <SUBNET>  # BPF filter subnet (e.g. <SUBNET>)
            --k <FLOAT>               # anomaly multiplier (default: 2.0)
            --alpha <FLOAT>           # EWMA smoothing (default: 0.125)
            --socket <PATH>           # IPC socket path (default: /run/ddos_stage1/stage1.sock)
            --no-filter               # disable BPF (dev only)
            --baseline-path <PATH>    # V4: persisted baseline file (default: /var/lib/ddos_stage1/baselines.json)
            --baseline-ttl-secs <N>   # V4: reject a persisted baseline older than N seconds (default: 3600)
```

### Log Levels

```bash
RUST_LOG=info   # startup, warmup progress, anomalies (default)
RUST_LOG=debug  # all of the above + every window's r and h values
RUST_LOG=warn   # anomalies and errors only
```

### Expected Output Sequence

```
# Startup
[INFO] banner
[INFO] BPF filter target victim IP = <VICTIM_IP>
[INFO] Capture: capture loop started on '<IFACE>'

# Warmup (first 200 windows)
[INFO] Analysis: warm-up window 1/200   | r=0.0 pps   | h=0.000
[INFO] Analysis: warm-up window 100/200 | r=842.3 pps  | h=0.921
[INFO] Analysis: warm-up window 200/200 | r=917.1 pps  | h=0.985

# Normal operation — silence at INFO level (no news = good news)
# With RUST_LOG=debug:
[DEBUG] Window #31: NORMAL | r=103.2 | h=0.971

# Anomaly detected
[WARN] ANOMALY window #47 | flags=0x03 | r=58291.4 (boundary=2341.1) | h=0.012 (boundary=0.650) | dom_ratio=0.980

# Clean shutdown (Ctrl+C)
[INFO] Analysis: channel closed; processed 47 windows total. Exiting.
```

### Anomaly Flag Reference

| Flag | Meaning | Likely Cause |
|---|---|---|
| `0x01` | Rate only | Volumetric flood, diverse sources — possible flash crowd |
| `0x02` | Entropy only | Concentrated source, low volume |
| `0x03` | Both | High volume + single dominant source — highest confidence DDoS |

---

## Model Training and Data Capture

To train the Random Forest model in Stage 2, you need to capture traffic using the live-label switching feature of Stage 1 to ensure a continuous, un-poisoned baseline.

### 1. Generating Training Data

Start the sensor, logging to a CSV:
```bash
sudo ddos_stage1 --label 0 --train-csv <PATH_TO_CSV>
```

Traffic generation is intentionally not prescribed here — use whatever tools you have available (load-testing tools, scripted HTTP clients, packet-crafting tools, etc.) to produce each traffic category below. What matters is the labeling procedure, not the specific tool.

**Capture Sequence (The "Clean Rule" for Labels):**
To avoid poisoning the label with transitioning traffic, always wait for traffic to hit its target rate before applying the attack label, and reset the label to `0` before turning off the attack.

1. **Phase 0 (Peacetime):** Let it run on normal traffic for ~4 minutes for Welford warm-up (wait for the `warm-up complete` log), then let it capture ~5 minutes of steady normal traffic.
2. **Phase 1 (Flash Crowd):** Start a legitimate-looking surge from many distinct source IPs (e.g. a distributed set of HTTP clients). Wait for it to hit full rate, then run `echo 1 | sudo tee /run/ddos_stage1/train_label`; capture for a few minutes; run `echo 0 | sudo tee /run/ddos_stage1/train_label`; stop the traffic and wait for it to return to baseline before continuing.
3. **Phase 2a (Single-Source DDoS):** Start a single-source flood at a rate representative of what you want to defend against. Wait for it to stabilize, then run `echo 2 | sudo tee /run/ddos_stage1/train_label`; capture for a few minutes; run `echo 0 | sudo tee /run/ddos_stage1/train_label`; stop the flood and wait for baseline to return.
4. **Phase 2b (Distributed DDoS):** Same as 2a, but from many concurrent sources instead of one — wait for it to stabilize, `echo 2 | sudo tee /run/ddos_stage1/train_label`, capture, `echo 0 | sudo tee /run/ddos_stage1/train_label`, stop.

(`/run/ddos_stage1` is root-owned, not world-writable like `/tmp` was -- this is deliberate, see the IPC/active-flows security note above, but it does mean the label switch needs `sudo`/`tee` instead of a plain shell redirect.)

**Capturing more than one session per label (required for a fair evaluation):**
A single continuous process run — even one that cycles through all four phases above via `/run/ddos_stage1/train_label` — only produces *one* Welford baseline draw per label, because the baseline lives in memory for the life of the *process*, not the life of the *label*. Evaluating generalization (see Leave-One-Session-Out below) needs at least two **independent** sessions per label: kill and restart `ddos_stage1` (fresh warm-up) before capturing a second Normal or Flash-Crowd session, rather than just flipping the label on an already-running process. `training_data.csv` is append-only (Stage 1 opens it with `OpenOptions::append(true)`), so every new session — same file, any day — is picked up automatically; `train.py`'s own session detection (a >30s timestamp gap or a label change starts a new session) sorts it out from timestamps, not from how the file was written.

One archetype worth deliberately capturing that the four phases above don't produce: a **hot-source flash crowd** — a legitimate surge where one participant (a monitoring bot, a NAT gateway, a proxy) contributes a disproportionate share of otherwise-normal traffic, so `dominant_ip_ratio` climbs on a benign sample. Keep that source's absolute rate modest (tens of pps, not hundreds+) and shrink the overall crowd size rather than raising any single source's rate aggressively — pushing a "hot source" too hard just reproduces a single-source DDoS signature with a legitimate label on it, which defeats the purpose.

### 2. Training the Model

Once you have your `training_data.csv` collected in the `stage2/` directory, run the training script:

```bash
cd stage2
python3 train.py
```

This script parses the CSV, drops NaN/inf rows, computes three derived features from the raw wire columns — `delta_rate` (`ewma_rate - mean_r`), `delta_entropy` (`entropy - mean_h`), and `dominant_rate` (`ewma_rate * dominant_ip_ratio`, the estimated pps of the single busiest source in the window) — and detects capture sessions from timestamp gaps/label changes. It prints a per-class feature-range overlap check (including `dominant_rate`) so you can see directly whether your captured classes actually overlap in rate/entropy/concentration space, rather than being trivially separable.

Evaluation and the deployed model are two separate steps:
- **Leave-One-Session-Out (LOSO) evaluation:** for every session whose label has ≥2 sessions total, that session is held out entirely, a temporary model is trained on every *other* session, and predictions on the held-out session are collected. Sessions whose label only has one session are skipped with an explicit note (holding out a class's only session would leave zero training examples of it — that's a coverage gap, not a fair test, and would just report a meaningless 0.00). Results from every fold are combined into one aggregate classification report and confusion matrix. This exists because a percentage-of-session split (or a random split) leaks: consecutive windows share EWMA/Welford state, so a model can memorize a session's fingerprint instead of learning to generalize, and will score a hollow 1.00 for it.
- **Production model:** trained separately, on *all* available sessions (balanced via upsampling), and saved as `ddos_rf_model.joblib` — this is what Stage 2 actually loads. LOSO is purely an evaluation signal for how well the approach generalizes; it never produces the shipped model itself.

Read the LOSO confusion matrix, not the headline accuracy — in particular, class-2 (DDoS) recall/precision and the true-Flash-Crowd-predicted-DDoS cell are the numbers that matter for this project's central claim (not over-blocking legitimate surges).

---

## Running Tests

```bash
cd stage1

# Requires libpcap-devel installed
cargo test

# Pure math tests only (no libpcap needed)
rustc --edition 2021 --test src/welford.rs -o /tmp/t && /tmp/t
rustc --edition 2021 --test src/ewma.rs    -o /tmp/t && /tmp/t
rustc --edition 2021 --test src/entropy.rs -o /tmp/t && /tmp/t
```

**Test coverage:** 18 tests across Welford (6), EWMA (5), Entropy (7).  
The golden vector `[4, 7, 13, 16]` → `mean=10.0, variance=30.0` is verified on every run.

---

## Update and Uninstall

```bash
# Update (rebuild Rust + update Python dependencies + restart services)
sudo bash scripts/update.sh

# Uninstall (removes binaries, venv, service units, socket file)
sudo bash scripts/uninstall.sh

# Full uninstall including build cache and Rust toolchain
sudo bash scripts/uninstall.sh --remove-build --remove-rust
```

---

## Stage 2 Integration (Python)

Stage 2 listens on the Unix domain socket `/run/ddos_stage1/stage1.sock`, unpacks the incoming 168-byte `FeatureVector` structs, and classifies traffic in real-time. It operates as a FastAPI application with a persistent SQLite storage layer and a dynamic Chart.js dashboard.


The 17 numeric fields unpacked from the Feature Vector (plus the 2 IP fields — see the wire format table above):
1. Source IP Entropy (`entropy`)
2. Packet Rate (`ewma_rate`)
3. Entropy Running Mean (`mean_h`)
4. Packet Rate Running Mean (`mean_r`)
5. Entropy Standard Deviation (`sigma_h`)
6. Packet Rate Standard Deviation (`sigma_r`)
7. Protocol Ratio (`proto_ratio` - legacy)
8. Dominant Source IP Ratio (`dominant_ip_ratio`)
9. Timestamp (`timestamp`)
10. TCP Ratio (`proto_tcp`)
11. UDP Ratio (`proto_udp`)
12. ICMP Ratio (`proto_icmp`)
13. SCTP Ratio (`proto_sctp`)
14. GRE Ratio (`proto_gre`)
15. ESP Ratio (`proto_esp`)
16. Operative Anomaly-Boundary Multiplier (`k_multiplier`) — Stage 1's live, cooldown-adjusted k, not a fixed constant.
17. Cooldown Windows Remaining (`cooldown_counter`)

Three more features are **derived in Stage 2**, not unpacked from the wire, and feed the Random Forest classifier alongside the fields above: `delta_rate` (`ewma_rate - mean_r`), `delta_entropy` (`entropy - mean_h`), and `dominant_rate` (`ewma_rate * dominant_ip_ratio` — the estimated pps of the single busiest source in the window). `dominant_rate` is also reused directly by the enforcement logic below (see "Core Safeguards"), computed once and shared rather than recomputed per use site.

### Core Safeguards and Adaptive Baselines

To ensure high-performance, robust, and poison-resistant mitigation, Stage 2 integrates the following mechanisms. All numeric values below are **defaults** — every one is operator-configurable from the Firewall tab's "Enforcement Thresholds" panel (backed by `stage2/enforcement_config.json`), not hardcoded, so a given block/rate-limit decision can always be explained by pointing at a specific, inspectable, tunable number.

1. **Adaptive Safety Overrides** (`stage2.py`'s "Adaptive Safety overrides" block):
   - Overrides the RF's raw prediction using dynamic, per-victim statistical boundaries so extreme spikes are never missed even if the classifier is unsure:
     - Volumetric suspect (re-examine the verdict at all): `ewma_rate > mean_r + k_multiplier * sigma_r` — `k_multiplier` is transmitted live from Stage 1 and reflects its own cooldown-adjusted sensitivity, not a fixed constant.
     - Extreme **single-source** rate (forces Class 2 unconditionally): `dominant_rate > max(block_rate_floor_pps, mean_r + block_sigma_multiplier * sigma_r)`, default floor 300 pps, multiplier 10σ. This checks `dominant_rate` — the busiest single source's estimated pps — **not raw aggregate `ewma_rate`.** Aggregate volume alone can't distinguish one attacker producing an extreme volume from many genuine users each producing a normal trickle (a legitimate flash crowd's aggregate rate scales with participant count exactly like an attacker's does); checking the busiest single source instead means a large but genuinely distributed crowd no longer gets force-classified as DDoS purely because enough real users showed up at once.
     - Concentrated source / entropy drop (also forces Class 2): `entropy < mean_h - k_multiplier * sigma_h` **or** `dominant_ip_ratio > dominant_ip_ratio_extreme_threshold` (default 0.75).

2. **Tiered Mitigation Strategy** — four tiers, evaluated in order, each acting on a per-source-IP rate rollup aggregated from Stage 1's active-flows telemetry (summed across every flow tuple a given source IP is using, so an attacker can't dodge the thresholds below by fragmenting its traffic across multiple destination ports):
   - **Tier 1 — Dominant-source fast path:** blocks the single busiest source outright when it's both concentrated (`dominant_ip_ratio >= dominant_ip_ratio_block_threshold`, default 0.40) and fast enough to clear the live rate boundary.
   - **Tier 2 — Independent per-source escalation:** blocks *any* individual source whose own rate clears `block_threshold` (same formula/value as the extreme-rate override above), regardless of how concentrated the *aggregate* traffic looks. This is what closes the evasion gap a purely aggregate-or-dominant-ratio gate has: spreading an attack across many sources no longer helps once every source is still individually well above human/flash-crowd rates.
   - **Tier 3 — Soft rate-limit:** any remaining source clearing the softer `ratelimit_rate_floor_pps`-derived bar (default 50 pps floor) gets rate-limited to the configured `ratelimit_hashlimit_pps` cap (default 50 pps) via `iptables hashlimit`, rather than blocked — the reversible tier for elevated-but-ambiguous sources.
   - **Tier 4 — Aggregate-cap fallback:** if a window is classified DDoS but *nothing* above matched any individual source (traffic distributed finely enough that no single source stands out even in the per-source rollup), every currently-active flow to the victim gets rate-limited rather than the system taking no action at all.
   - **Block hysteresis:** Tiers 1 and 2 (the hard-block actions) additionally require `block_hysteresis_windows` (default 2) *consecutive* Class-2 windows for that victim before firing — a single noisy window can no longer trigger an immediate block. Tiers 3/4 (rate-limiting) are intentionally immediate and ungated, since they're already the reversible tier.
   - Both `ddos_blocklist` and `ddos_ratelimit` are self-healing (configurable `block_duration_seconds` / `ratelimit_duration_seconds` ipset timeouts, default 3600s each) and are both visible on the Firewall tab and the main dashboard's stat tiles — not just the blocklist.

3. **Welford Baseline Poisoning Protection** — two complementary mechanisms on Stage 1, not one:
   - **Recency cap:** `welford.rs` caps the sample count `n` at 500 (`MAX_N`) so the running baseline can't freeze after weeks of uptime the way unbounded textbook Welford would (`delta/n → 0`). Once capped, the accumulator applies exponential decay to `M2` alongside the mean, to keep the variance estimate consistent with the same recency window — this makes it a **bounded-memory approximation of Welford's algorithm, not exact running variance**; it should be cited as such, not as a direct implementation of Welford (1962).
   - **Freeze-on-anomaly:** Stage 1 only feeds new samples into the Welford accumulator when the current window is clean (`anomaly_flags == 0`) **and** not in cooldown — during an active or recently-resolved anomaly, the baseline simply stops updating. This is what stops a slow-ramp attacker from gradually dragging the "normal" baseline up to include their own flood. The recency cap and the freeze are complementary, not redundant: the cap keeps the baseline responsive to genuine legitimate drift, which on its own would make the baseline *more* poisonable (shorter memory, easier to shift); the freeze is what makes that safe. A recency cap without the freeze would be a net negative.
   - On top of both: baseline capping (mean rate ceiling 10,000 pps), outlier rejection (>5σ deviations ignored), and peacetime-reference reversion if the Welford mean drifts more than 50% from an ultra-slow EWMA peacetime reference (α = 0.001).

4. **Kernel Resource Capacity Monitor:**
   - A background thread polls the blocklist every 30 seconds and logs a critical warning if the kernel `ipset` table exceeds 80% capacity.

---

## Security Hardening

Beyond the statistical poisoning defenses above, a security audit pass covered the parts of the system an attacker (or a misconfigured deployment) could target directly rather than through traffic patterns. Fixes span both stages:

**Transport and authentication**
- The management console serves over **HTTPS** if a certificate is present at `/etc/ddos_stage2/tls/` (`install.sh` generates a self-signed one via `openssl` if none exists), falling back to plain HTTP with an explicit startup warning otherwise — previously the login form, session cookie, and every block/unblock call travelled in cleartext, bound to `0.0.0.0:8000`.
- Passwords are hashed with **bcrypt** (`setup_admin.py`, `auth.py`), replacing a single unsalted-work-factor round of SHA-256. There is no default/fallback admin credential baked into the code — `main()` fails closed (logs a warning, no login possible) if `setup_admin.py` was never run.
- Login attempts are throttled per client IP (5 failures / 5 minutes, then a 5-minute lockout) to slow online brute-forcing of whatever hash strength is in play.

**Input validation and output encoding**
- Every IP-shaped field accepted from the dashboard (`IpPayload`, `VictimPayload`, and the raw query-param endpoints) is validated with Python's `ipaddress` module before it can reach `ipset` or get stored. Without this, a CIDR string would get silently expanded by `ipset`'s `hash:ip` sets into every host in the range instead of the single IP the operator intended.
- All dashboard pages that render server-supplied strings into `innerHTML` (whitelist/victim IPs, victim descriptions, log rows) now escape through `FlodSafe.escapeHtml()`/`jsAttr()` (`static/theme.js`) — previously these were interpolated raw, a stored-XSS path that could run arbitrary JS in an authenticated admin's session (and, since the session cookie is `httponly`, XSS was actually the *more* dangerous path in than cookie theft, not less: injected JS can call any `/api/*` endpoint same-origin regardless).
- CSV export neutralizes spreadsheet formula injection (a leading `=`, `+`, `-`, `@`, tab, or CR gets a defusing prefix) and uses proper `csv.writer` quoting instead of manual string formatting.

**Process and filesystem isolation**
- Stage 1 runs as a dedicated, unprivileged `ddos-stage1` service account with `AmbientCapabilities=CAP_NET_RAW` instead of full root — a bug anywhere in the packet-capture/analysis path no longer carries root's blast radius. Stage 2 still runs as root (needed for `ipset`/`iptables`).
- The Stage 1 ↔ Stage 2 IPC socket, the active-flows telemetry file, and the training-label switch file all live in `/run/ddos_stage1/` (root-owned, `0770` shared with a `ddos-ipc` group) instead of world-writable `/tmp`. Previously any local account could race to bind the socket path ahead of Stage 2 — e.g. during a restart window — and either receive live `FeatureVector` telemetry meant for Stage 2, or inject fabricated windows straight into the enforcement pipeline.
- `stage2.db` (holds password hashes), `whitelist.json`, `victims.json`, and `enforcement_config.json` are all `chmod 0600` — previously world-readable, letting any local account read credentials or enforcement thresholds off disk.

**Request handling**
- A 10 MB request body cap (checked via `Content-Length` before the body is read) guards every endpoint, not just the PDF export that motivated it.
- PDF export writes chart images to unique per-request temp files (`tempfile.NamedTemporaryFile`, cleaned up in a `finally` block) instead of two fixed shared filenames, which let concurrent exports clobber or mix each other's charts. The incoming base64 payload is also size-capped (8 MB) before decoding.

**Account management (`users.py`, `alerts.py`)**
- Creating an account, deleting an account, or changing a password now all require the caller to **re-enter their own current password** (`admin_password`, verified server-side via `_verify_admin_password()` against the *caller's* stored hash, not the target account's). A session cookie alone — one that leaked through a brief XSS window, or was left signed in on a shared machine — used to be enough to durably take over every admin account; now it isn't.
- Sessions are tracked as `token -> {"username", "last_active"}` instead of a bare timestamp, so a password change or account deletion can call `auth.revoke_sessions_for_user()` and immediately invalidate every other live session for that username, rather than leaving a hijacked session usable until its own idle timeout.
- The "can't delete the last admin" guard and the duplicate-username check on create are each enforced as a single atomic SQL statement (`DELETE ... WHERE username = ? AND (SELECT COUNT(*) FROM users) > 1`, and relying on the `username` `PRIMARY KEY` constraint + catching `IntegrityError`) instead of a separate check-then-act pair — closing a TOCTOU race where two concurrent requests could each pass a check before either committed (e.g. two deletes racing against a 2-admin system, both reading `count == 2` before either delete lands, leaving zero accounts behind).
- `DELETE /api/users` takes `username`/`admin_password` as a JSON request body (`DeleteUserPayload`) rather than query parameters — a query string risks landing in server access logs or browser history, which is the wrong place for a password.
- `GET /api/config/alerts` no longer echoes the Discord webhook URL back in the clear (it's a bearer credential — anyone holding it can post to the configured channel as the bot). It's redacted to a `discord_webhook_url_set` boolean, matching the existing `smtp_app_password_set` pattern; the dashboard only sends a new URL/password to the server if the operator actually typed one.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `pcap` | Raw frame ingestion from the kernel ring buffer |
| `etherparse` | Zero-copy Ethernet/IP/TCP/UDP header parsing |
| `crossbeam-channel` | Bounded MPSC channel between capture and analysis threads |
| `byteorder` | Explicit little-endian serialisation for IPC struct |
| `log` + `env_logger` | Levelled logging controlled by `RUST_LOG` |

All statistical algorithms (Welford, EWMA, Shannon Entropy) use only the Rust standard library — no external crates.

Stage 2's Python dependencies are pinned in `stage2/requirements.txt` (FastAPI, uvicorn, scikit-learn, pandas, joblib, reportlab, `python-multipart`); `bcrypt` was added for password hashing (see "Security Hardening" above) in place of the standard library's `hashlib`.

---

## Future Versions Roadmap

The planned evolutionary milestones for future gateway iterations are structured as follows:

| Version | Focus | Primary Goal | Description |
| :--- | :--- | :--- | :--- |
| **V1 (Completed)** | **Initial ML Pipeline** | Proof of concept | Basic feature extraction and initial Web UI dashboard setup. |
| **V2 (Completed)** | **Adaptive Baselines** | Dynamic defenses | Implemented entropy-guided thresholds, cluster rate-limiting, and Welford poisoning defenses. |
| **V3 (Completed)** | **Multi-Target Scaling** | Subnet-wide protection | Track and defend multiple victim IPs concurrently on a single ingress interface, keeping separate statistical baselines. |
| **V4 (Implemented)** | **Baseline Persistence** | Persistent safe boundaries | Save and load Welford baselines across reboots to prevent baseline poisoning during active attack restarts. See `stage1/src/persistence.rs`. |
| **V5 (Implemented)** | **Egress Processing** | Measure what actually gets through | Second capture thread on the egress interface. Comparing per-victim ingress vs. egress rates measures real drop effectiveness empirically, instead of inferring it from enforcement actions alone. Also covers NAT-safe enforcement: sources marked as shared/NAT egress points are rate-limited but never hard-blocked. |
| **V6** | **XDP/eBPF Acceleration** | Kernel-space filtering | Port the packet sniffer and early-drop logic to the eBPF/XDP driver path using Aya in Rust, so filtering happens before the kernel builds an `skb` for each packet. |
| **V7** | **Ensemble Intelligence** | Complex classifier models | Deploy a multi-model voting ensemble layer to resolve advanced evasion/stealth attacks while maintaining low false positives. Adds source-port entropy, TTL variance, and TCP fingerprint diversity as features, so large NAT/CGNAT crowds stop reading as single-source floods. |
| **V8** | **Automated Playbooks** | Detailed Incident Response Plan | Generate dynamic, granular incident reports and execute automated multi-stage incident response playbooks during severe breaches. |
| **V9** | **Federated Peer Signalling** | Mitigate at the source, not the symptom | Cooperating gateways exchange authenticated, **advisory** reports ("traffic from an address you own is behaving like an attacker") so the peer — the only party that can see individual hosts behind its own NAT — investigates and acts locally, instead of the receiving gateway blackholing a shared egress IP and cutting off every legitimate user behind it. Conceptually aligned with IETF DOTS (RFC 8782/8783). Requires mutual authentication and a static peer/range registry; applies only within a federation of cooperating gateways, not to arbitrary internet sources. |
| **V10** | **Multi-Interface Aggregation** | Perimeter-wide visibility | Aggregate traffic statistics across multiple parallel ingress uplinks. Deferred behind the versions above: the routed-subnet topology uses its two interfaces as the ingress and egress of a single path, not as parallel uplinks, so there is nothing to aggregate yet. |

---

## References

1. T. Bai et al., "ATS-DTA: Adaptive two-stage DDoS detection," *Cybersecurity*, vol. 9, 2026.
2. S. Abiramasundari and V. Ramaswamy, "DDoS detection using supervised ML," *Scientific Reports*, 2025.
3. E. Cohen and M. Strauss, "Maintaining time-decaying stream aggregates," *Journal of Algorithms*, 2004.
4. W. Eddy, "TCP SYN Flooding Attacks and Common Mitigations," RFC 4987, IETF, 2007.
5. NIST SP 800-61 Rev. 2, "Computer Security Incident Handling Guide," 2012.
