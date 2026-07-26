# Adaptive Two-Stage DDoS Mitigation Gateway

**Author:** Abdullah Armiyao

**Project:** Adaptive Two-Stage Framework for Near Real-Time DDoS Mitigation Using Behavioral Traffic Analysis


## What This Project Is

Most DDoS mitigation systems use **static thresholds** — hard-coded numbers like "block any IP sending more than 1000 packets/sec." The problem is that your legitimate traffic might naturally spike to 1000 pps during a registration rush, so those systems either miss real attacks or block real users.

This project solves that by building a gateway that **learns what your normal traffic looks like** and adapts its detection boundaries accordingly. It can tell the difference between a DDoS flood and a flash crowd (a legitimate traffic surge) without a human adjusting thresholds.

The system is split into two stages:

- **Stage 1 (Rust):** Sits inline on the network bridge, watches every packet, runs lightweight statistics, and raises an anomaly flag when something looks wrong.
- **Stage 2 (Python):** Wakes up only when Stage 1 flags something (or on a periodic heartbeat), runs a Random Forest classifier to confirm whether it's a real attack or a flash crowd, and issues kernel-level drop rules (`ddos_blocklist` ipset) or rate limits (`ddos_ratelimit` ipset using iptables hashlimit) in real time. It also hosts a persistent FastAPI-based dashboard.


## Network Topology and Virtualization Gotchas

In virtualized hypervisor environments (like Proxmox VE), the layout of your network bridges directly controls what traffic the Sensor VM can inspect.

### The Virtual Switch Subnet Bypass Gotcha
If the **Attacker VM** and **Victim VM** are placed on the same Proxmox bridge (e.g., `vmbr1`) and share the same IP subnet (e.g., `192.168.1.0/24`):
1. They communicate directly host-to-host at Layer 2. The Proxmox host switch learns their MAC addresses and forwards packets directly between their virtual ports.
2. Even if the Sensor VM is configured as their default gateway, **local subnet traffic bypasses the gateway**. 
3. The Sensor VM's NIC (`ens19`) receives 0% of the unicast flood traffic. It will only capture broadcast packets (like ARP requests) or traffic sent directly to the Sensor's IP.

---

### The Routed Subnet Setup (192.168.1.0/24 -> 10.0.0.0/24)

To ensure the Sensor VM can inspect and filter all traffic, the Attacker and Victim are separated into two distinct subnets connected by the Sensor VM acting as an IP Router:

```
[ Attacker / Flash Crowd ]             [ Sensor VM / Gateway ]                 [ Victim VM ]
  (Subnet: 192.168.1.0/24)             (Router/Firewall Gateway)          (Subnet: 10.0.0.0/24)
  (IP: 192.168.1.4)                                │                      (IP: 10.0.0.3)
         │                                         │                            │
     [ vmbr1 ] <───────────────────────────────> [ens19]                        │
   (LAN Segment 1)                       (IP: 192.168.1.2)                      │
                                                 [ens20] <──────────────────> [ vmbr2 ]
                                         (IP: 10.0.0.2)                     (LAN Segment 2)
```

*   **How it works:** The Attacker VM (`192.168.1.4`) wants to target the Victim VM (`10.0.0.3`). Because they are on different subnets, the Attacker is forced to route the traffic through its default gateway (`192.168.1.2` - the Sensor VM's ingress interface).
*   **Where to capture:** Run `ddos_stage1` on the **ingress interface (`ens19`)** where the flood traffic first enters the gateway.

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

**Why entropy *drops* during DDoS:** A flood from a spoofed or single source concentrates packets toward one IP, collapsing the distribution and dragging entropy toward zero. Layer 3 fires when entropy drops *below* `μ − k·σ` rather than above it.

**Critical behaviour — entropy resets every window.** The HashMap is cleared after each computation. Entropy measures the diversity of *this* specific window, not a historical trend. The long-run trend is tracked by the Welford accumulator.

---

### 4. The Anomaly Boundary: μ ± k·σ

**Files:** `stage1/src/welford.rs`, `stage1/src/analysis.rs`

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

The wire format is **exactly 168 bytes, little-endian**:

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
| 136 | 16 bytes | `dominant_ip` | [u8; 16] | Busiest source IP (IPv6 or mapped IPv4) |
| 152 | 16 bytes | `victim_ip` | [u8; 16] | Monitored victim IP address |

Python unpacks it with: `struct.unpack('<17d16s16s', data)`

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
To survive high-rate volumetric floods (1,000,000+ pps) without crashing the virtual machine, the capture module is tuned with three critical parameters:
1.  **Reduced Snaplen (`snaplen = 256` bytes):** Instead of copying the full 64KB frame buffer to user-space (which saturates the CPU cache and memory bus), we only copy the first 256 bytes. This is more than enough to capture the Ethernet, VLAN, IPv4/IPv6, and TCP/UDP headers, reducing memory transfer costs by **99.6%**.
2.  **Immediate Mode (`immediate_mode = true`):** Bypasses the kernel's internal buffering window. Packets are flushed to the socket buffer instantly rather than waiting for block retirement.
3.  **Scaled Socket Buffer (`buffer_size = 128MB`):** Pins a 128MB ring buffer in kernel memory to act as a runway. If the Rust application experiences a brief context switch stall, the kernel can buffer up to ~1.3 million packet headers (at 96 bytes each) without drops.

---

### 7. Why a Hybrid Architecture? (Rust vs. Python)

One might ask: *If the Rust pre-filter is running in user-space anyway, why not write the entire system in Python?* 

The answer lies in the **Global Interpreter Lock (GIL)** and **runtime overhead**:

*   **Python's Limitations under Flood:** Python is interpreted, garbage-collected, and bound by the GIL (only one thread can execute bytecode at a time, even on multi-core systems). Creating objects and running Scapy/PyShark parsers on every incoming packet caps Python's throughput at **~20,000 packets/second** before hitting 100% CPU.
*   **Rust's Efficiency:** Rust compiles to native code, has no garbage collector, and has zero-cost abstractions. Zero-copy parsing allows it to handle **2,000,000+ packets/second** on a single thread.
*   **The Division of Labor:**
    *   **Stage 1 (Rust):** Handles the high-speed volumetric shield (1,000,000+ pps). It condenses millions of raw packets into a single summary `FeatureVector` per window.
    *   **Stage 2 (Python):** Wakes up to process only **1 Feature Vector per window** (a tiny, low-rate stream of ~10–100 data points per second). At this volume, Python's performance overhead is negligible, allowing us to leverage Python's powerful machine learning libraries (`scikit-learn`, `pandas`) safely.

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
│       ├── analysis.rs             ← Three-layer analysis thread
│       ├── welford.rs              ← Welford online variance accumulator
│       ├── ewma.rs                 ← EWMA rate estimator
│       ├── entropy.rs              ← Shannon entropy calculator
│       └── ipc.rs                  ← Binary IPC serialisation → Python
└── scripts/
    ├── install.sh                  ← Linux installer (Debian/Ubuntu, RHEL, Alpine)
    ├── install.bat                 ← Windows installer (dev/test only)
    ├── update.sh                   ← Atomic update script
    └── uninstall.sh                ← Full teardown script
```

---

## Installation

### Linux (Debian/Ubuntu, RHEL/Fedora, Alpine)

```bash
# Installs interactively (prompts for interface and targets if run in a terminal):
sudo bash scripts/install.sh

# Or install non-interactively using explicit targets:
sudo bash scripts/install.sh --interface ens19 --victim-ips 10.0.0.3,10.0.0.4 --victim-subnet 10.0.0.0/24
```

This will:
1. Detect your OS and install `libpcap-dev` + build tools
2. Prompt for or parse the network interface and victim IPs/subnet
3. Install Rust via `rustup` if not present
4. Compile Stage 1 in release mode
5. Install the binary to `/usr/local/bin/ddos_stage1`
6. Grant `CAP_NET_RAW` so it runs without `sudo`
7. Install and configure systemd service units (`ddos-stage1` and `ddos-stage2`)

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
# Start both stages with default settings (ens19 interface, 10.0.0.3 victim IP)
sudo ./run.sh

# Start both stages with custom settings
sudo ./run.sh --interface ens19 --victim-ip 10.0.0.3
```

### Individual Components Usage

If you prefer to run the components separately:

#### 1. Stage 1 Rust Pre-Filter
```bash
# Production (on sensor VM, specifying multiple IPs or subnet)
sudo ddos_stage1 --interface ens19 --victim-ips 10.0.0.3,10.0.0.4
sudo ddos_stage1 --interface ens19 --victim-subnet 10.0.0.0/24
```
# All options
ddos_stage1 --interface <IFACE>       # required
            --victim-ips <IPs>        # BPF filter IP list (comma-separated, alias: --victim-ip)
            --victim-subnet <SUBNET>  # BPF filter subnet (e.g. 10.0.0.0/24)
            --k <FLOAT>               # anomaly multiplier (default: 2.0)
            --alpha <FLOAT>           # EWMA smoothing (default: 0.125)
            --socket <PATH>           # IPC socket path (default: /tmp/ddos_stage1.sock)
            --no-filter               # disable BPF (dev only)
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
[INFO] BPF filter target victim IP = 10.0.0.3
[INFO] Capture: capture loop started on 'br0'

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
sudo ddos_stage1 --label 0 --train-csv ../stage2/training_data.csv
```

**Capture Sequence (The "Clean Rule" for Labels):**
To avoid poisoning the label with transitioning traffic, always wait for traffic to hit its target rate before applying the attack label, and reset the label to `0` before turning off the attack.

1. **Phase 0 (Peacetime):** Let it run on normal traffic for ~4 minutes for Welford warm-up (wait for the `warm-up complete` log), then let it capture ~5 minutes of steady normal traffic.
2. **Phase 1 (Flash Crowd):**
   - Start your 100-IP `curl` flash crowd. Wait ~10 seconds for it to hit full rate.
   - Run: `echo 1 > /tmp/ddos_label`. Run for ~5 minutes.
   - Run: `echo 0 > /tmp/ddos_label`. Stop `curl`. Wait for traffic to return to baseline.
3. **Phase 2a (Single-Source DDoS):**
   - Start single-source `hping3` at ~3,000 pps. Wait ~10 seconds.
   - Run: `echo 2 > /tmp/ddos_label`. Run for ~3 minutes.
   - Run: `echo 0 > /tmp/ddos_label`. Stop `hping3`. Wait for traffic to return to baseline.
4. **Phase 2b (Distributed DDoS):**
   - Start 50-source `hping3` distributed attack loop. Wait ~10 seconds.
   - Run: `echo 2 > /tmp/ddos_label`. Run for ~3 minutes.
   - Run: `echo 0 > /tmp/ddos_label`. Stop `hping3`.

**Capturing more than one session per label (required for a fair evaluation):**
A single continuous process run — even one that cycles through all four phases above via `/tmp/ddos_label` — only produces *one* Welford baseline draw per label, because the baseline lives in memory for the life of the *process*, not the life of the *label*. Evaluating generalization (see Leave-One-Session-Out below) needs at least two **independent** sessions per label: kill and restart `ddos_stage1` (fresh warm-up) before capturing a second Normal or Flash-Crowd session, rather than just flipping the label on an already-running process. `training_data.csv` is append-only (Stage 1 opens it with `OpenOptions::append(true)`), so every new session — same file, any day — is picked up automatically; `train.py`'s own session detection (a >30s timestamp gap or a label change starts a new session) sorts it out from timestamps, not from how the file was written.

One archetype worth deliberately capturing that the four phases above don't produce: a **hot-source flash crowd** — a legitimate surge where one participant (a monitoring bot, a NAT gateway, a proxy) contributes a disproportionate share of otherwise-normal traffic, so `dominant_ip_ratio` climbs on a benign sample. Keep that source's absolute rate modest (tens of pps, not hundreds+) and shrink the overall crowd size rather than raising any single source's rate aggressively — pushing a "hot source" too hard just reproduces a single-source DDoS signature with a legitimate label on it, which defeats the purpose.

### 2. Training the Model

Once you have your `training_data.csv` collected in the `stage2/` directory, run the training script:

```bash
cd stage2
python3 train.py
```

This script parses the CSV, drops NaN/inf rows and exact-duplicate rows (a capture re-appended into the same CSV, or any other accidental double-write, otherwise doubles that session's weight in the balanced training set and in LOSO folds without raising any error), computes three derived features from the raw wire columns — `delta_rate` (`ewma_rate - mean_r`), `delta_entropy` (`entropy - mean_h`), and `dominant_rate` (`ewma_rate * dominant_ip_ratio`, the estimated pps of the single busiest source in the window) — and detects capture sessions from timestamp gaps/label changes. It prints a per-class feature-range overlap check (including `dominant_rate`) so you can see directly whether your captured classes actually overlap in rate/entropy/concentration space, rather than being trivially separable.

Evaluation and the deployed model are two separate steps:
- **Leave-One-Session-Out (LOSO) evaluation, swept across tree depths:** for every session whose label has ≥2 sessions total, that session is held out entirely, a temporary model is trained on every *other* session, and predictions on the held-out session are collected. Sessions whose label only has one session are skipped with an explicit note (holding out a class's only session would leave zero training examples of it — that's a coverage gap, not a fair test, and would just report a meaningless 0.00). This exists because a percentage-of-session split (or a random split) leaks: consecutive windows share EWMA/Welford state, so a model can memorize a session's fingerprint instead of learning to generalize, and will score a hollow 1.00 for it. The whole LOSO evaluation is repeated for `max_depth` in `[1, 2, ..., 10, None]`, and whichever depth gets the best aggregate LOSO accuracy is selected and printed — the depth is *never* hardcoded, because the right value depends entirely on how many independent sessions the current CSV has per class: with only two sessions of a class, a deep tree can carve rules that fit one session's specific fingerprint and then fail almost completely on the other (a real capture set here saw a held-out session collapse from ~1.00 to ~0.02 accuracy once depth went past 2). A different or expanded capture set will likely select a different depth; that's expected, not a bug.
- **Production model:** trained separately, on *all* available sessions (balanced via upsampling), using the depth selected by the LOSO sweep above, and saved as `ddos_rf_model.joblib` — this is what Stage 2 actually loads. LOSO is purely an evaluation signal for how well the approach (and the selected depth) generalizes; it never produces the shipped model itself.

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

Stage 2 listens on the Unix domain socket `/tmp/ddos_stage1.sock`, unpacks the incoming 168-byte `FeatureVector` structs, and classifies traffic in real-time. It operates as a FastAPI application with a persistent SQLite storage layer and a dynamic Chart.js dashboard.


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

## Dependencies

| Crate | Purpose |
|---|---|
| `pcap` | Raw frame ingestion from the kernel ring buffer |
| `etherparse` | Zero-copy Ethernet/IP/TCP/UDP header parsing |
| `crossbeam-channel` | Bounded MPSC channel between capture and analysis threads |
| `byteorder` | Explicit little-endian serialisation for IPC struct |
| `log` + `env_logger` | Levelled logging controlled by `RUST_LOG` |

All statistical algorithms (Welford, EWMA, Shannon Entropy) use only the Rust standard library — no external crates.

---

## Future Versions Roadmap

The planned evolutionary milestones for future gateway iterations are structured as follows:

| Version | Focus | Primary Goal | Description |
| :--- | :--- | :--- | :--- |
| **V1 (Completed)** | **Initial ML Pipeline** | Proof of concept | Basic feature extraction and initial Web UI dashboard setup. |
| **V2 (Completed)** | **Adaptive Baselines** | Dynamic defenses | Implemented entropy-guided thresholds, cluster rate-limiting, and Welford poisoning defenses. |
| **V3 (Completed)** | **Multi-Target Scaling** | Subnet-wide protection | Track and defend multiple victim IPs concurrently on a single ingress interface, keeping separate statistical baselines. |
| **V4** | **Baseline Persistence** | Persistent safe boundaries | Save and load Welford baselines across reboots to prevent baseline poisoning during active attack restarts. |
| **V5** | **Multi-Interface Scaling** | Perimeter-wide visibility | Aggregate traffic statistics from multiple interface ports. Spawns egress sniffers to enable ingress vs. egress rate telemetry auditing. |
| **V6** | **XDP/eBPF Acceleration** | Kernel-space filtering | Port packet sniffer and early drop logic to eBPF/XDP driver path using Aya in Rust, scaling handling capacity to 10M+ pps. |
| **V7** | **Ensemble Intelligence** | Complex classifier models | Deploy a multi-model voting ensemble layer to resolve advanced evasion/stealth attacks while maintaining low false positives. |
| **V8** | **Automated Playbooks** | Detailed Incident Response Plan | Generate dynamic, granular incident reports and execute automated multi-stage incident response playbooks during severe breaches. |

---

## References

1. T. Bai et al., "ATS-DTA: Adaptive two-stage DDoS detection," *Cybersecurity*, vol. 9, 2026.
2. S. Abiramasundari and V. Ramaswamy, "DDoS detection using supervised ML," *Scientific Reports*, 2025.
3. E. Cohen and M. Strauss, "Maintaining time-decaying stream aggregates," *Journal of Algorithms*, 2004.
4. W. Eddy, "TCP SYN Flooding Attacks and Common Mitigations," RFC 4987, IETF, 2007.
5. NIST SP 800-61 Rev. 2, "Computer Security Incident Handling Guide," 2012.
