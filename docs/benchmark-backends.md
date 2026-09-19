# Live Benchmark: Kernel and libpcap Backends

`scripts/benchmark_live.sh` runs the seven phase traffic set once per capture
backend in a single session, then `scripts/analyze_live_benchmark.py` reports
each run and compares the two. It answers a question the earlier live
benchmark left open: the kernel (XDP and TC) and libpcap backends detect the
same traffic the same way, but how do they differ in throughput, CPU, latency,
and how they behave when switched?

All runs happen in my simulated lab environment. The figures describe that
environment. Other networks, other hardware, and other traffic mixes may
produce different numbers.

Status: the first session ran on 2026-09-19 from 10:30 to 12:30 UTC in the
simulated lab environment, one run per backend (kernel, then libpcap), with
calibration on `apply`, the attack type sweep on, and Normal, Flash Crowd and
attack variants rotating. The results are at the end of this page. They come
from a single run per backend, so nothing here shows how much a figure moves
between identical runs.

## Running it

```bash
cp scripts/benchmark_live.example.env my-benchmark.env
# edit my-benchmark.env: gateway, generator hosts, SSH keys, targets,
# INGRESS_IFACE and EGRESS_IFACE
bash scripts/benchmark_live.sh my-benchmark.env
```

Stage 2 on the gateway needs this release's code, or the latency figures stay
empty (see [Stage 2 latency](#stage-2-latency)). The variables that control the
comparison:

| Variable | Default | Meaning |
|-|-|-|
| `CAPTURE_MODES` | `kernel pcap` | Backends to run, in order. Each gets the full seven phase set. |
| `RUNS_PER_MODE` | `1` | Repeats per backend. Two or more adds a run to run spread to the report. |
| `NORMAL_VARIANTS`, `FLASHCROWD_VARIANTS`, `ATTACK_VARIANTS` | empty | Named variants of each traffic class. See [Traffic variety](#traffic-variety). |
| `ATTACK_SWEEP_SECS` | `0` | Seconds each attack type runs alone, and again with Normal traffic, after the seven phases. 0 skips the sweep. |
| `ATTACK_SOURCE_FILE`, `ATTACK_SOURCES_MIN`, `ATTACK_SOURCES_MAX` | empty, `30`, `40` | The run counts the addresses in this file on the attack host and stops outside the range. |
| `CALIBRATE`, `CALIBRATE_WINDOWS`, `CALIBRATE_TIMEOUT_MINS` | `off`, `1000`, `30` | Runs `scripts/calibrate.py` during each run's warm-up stage. `off`, `measure` or `apply`. See [Calibration](#calibration-during-the-warm-up-stage). |
| `REMOTE_DIR` | `/root/.flod_benchmark` | Root only directory on the gateway for the helper scripts and their output. |
| `INGRESS_IFACE`, `EGRESS_IFACE` | empty | Interfaces whose kernel counters the sampler reads. Empty skips the interface figures. |
| `BASELINE_DIR` | `/var/lib/ddos_stage1` | Where each run's own baseline file lives. |

A run takes the warm-up (up to `WARMUP_TIMEOUT_SECS`, 900 by default), the
calibration when it is on (up to `CALIBRATE_TIMEOUT_MINS`, plus a second warm-up
if the floors are applied), 1,050 seconds of phases at the default durations,
the switch, and the attack type sweep when it is on. With five attack types at 90 seconds alone, 90 seconds
with Normal traffic and a 30 second gap each, the sweep adds another 1,050
seconds. Two backends take between one and a half and two hours.

Each session writes to `benchmark-live-results/session_<UTC time>/`, with one
directory per run (`kernel_run1`, `pcap_run1`) and a `report.txt` and
`results.json` for the session. Nothing is overwritten between sessions. A run
directory holds the sensor and Stage 2 logs, the phase boundaries, the samples,
the firewall counters, `traffic_variants.tsv` (which variant of each class ran
in each phase) and `run_info.txt` (including the source address counts).

## What happens on the gateway

For each run the script:

1. Empties `ddos_blocklist` and `ddos_ratelimit` and restarts Stage 2. A block
   lasts an hour, so without this a later run would start with the earlier
   run's sources already blocked.
2. Stops Stage 1, appends `--capture-mode <mode>` and a per run
   `--baseline-path` to `FLOD_TUNING` in `/etc/ddos_stage1/tuning.env`, and
   starts it again. The sensor takes the last value given for a flag, so the
   unit file stays untouched, and each backend learns its own baseline from
   scratch. The production baseline file is left alone.
3. Verifies the switch (unit active, the capture backend the sensor logged,
   whether an XDP program is attached, both ipsets present).
4. Starts Normal traffic and waits for warm-up. This is the warm-up stage,
   recorded as its own phase, `warmup`, so the `normal` phase that follows holds
   only steady state.
5. When calibration is on, runs `calibrate.py` under that Normal traffic
   (see below).
6. Runs the seven phases: Normal, Flash Crowd, Attacker, Normal plus Flash
   Crowd, Normal plus Attacker, Flash Crowd plus Attacker, all three.
7. When the sweep is on, runs each attack type alone and then with Normal
   traffic (see below).

After the last run it restores the original `tuning.env` byte for byte,
restarts the sensor in its original mode, and verifies that too. An exit trap
does the same if the script is interrupted, and the report labels that as an
emergency rollback.

The traffic comes from the simulated lab environment's generator machines:
Locust for Normal, a curl loop for Flash Crowd, and hping3 based scripts for
the attacks. The attacker and flash crowd machines each carry sub-interfaces
with about 100 addresses, and Locust runs 100 users.

## Calibration during the warm-up stage

The sigma floors that Stage 1 uses are a property of the network, and
`scripts/calibrate.py` measures them from the sensor's own window log under
Normal load. With `CALIBRATE` set, each run does that inside its warm-up stage,
after the sensor has warmed up and before any measured phase, so the floors in
force during the phases match the Normal traffic of that run and the result is
part of the record.

`calibrate.py` runs on the gateway with `--auto-debug` (which turns on the
per-window debug logging it reads, then turns it off again) and `--partial`
(which uses whatever it collected if the timeout arrives). The benchmark only
lets it measure. It never lets `calibrate.py --apply` write `tuning.env`,
because that replaces the whole file and would drop the capture mode and the
per run baseline path the benchmark set. Instead:

- `measure` records what calibration derived and leaves the floors already in
  force.
- `apply` also adds the derived floors to the end of the sensor's tuning line
  (the sensor takes the last value for a flag), restarts the sensor, times
  that restart, and waits for the baseline again before the phases start.
- If calibration fails or finds no usable windows, the run continues with the
  floors already in force and the report says so.

The debug logging is off again before the phases begin, so it never affects the
measured CPU or throughput. If the script is interrupted mid calibration, the
rollback removes the debug drop-in it left behind, unless that drop-in was there
before the benchmark started.

Each backend calibrates on its own. With `apply` the two backends can end up
with different floors, so their phases then run under different thresholds. The
report shows the floors side by side and says so when they differ by more than
10%. Use `measure` to keep the floors identical across backends. Each run
records `calibration.txt`, `calibration.log` (the tool's own output) and, for
`apply`, `calibration_apply.txt` (the tuning line before and after, and the
restart timing).

Calibration needs clean Normal windows on every protected host. A host that
receives no Normal traffic never reaches the requested count, and the run
continues on the partial sample.

## Traffic variety

Running one Normal pattern, one Flash Crowd pattern and one attack in every
phase and every run would only show that the model handles that traffic. Each
class can list named variants instead. In the lab configuration:

| Class | Variants |
|-|-|
| Normal | `baseline` (smooth browsing) and `bursty` (short bursts and long idle gaps) |
| Flash Crowd | `even` (every source at a similar rate) and `hot` (one source far above the rest) |
| Attack | `mixed` (distributed, SYN, UDP and ICMP in turn, jittered), `shapeb` (distributed, about 70% UDP and 30% SYN, jittered), `syn_flood` (distributed SYN, unpaced), `mp_flood` (distributed SYN, UDP and ICMP, unpaced) and `single_mp` (one source address, all protocols, jittered) |

Each time a class starts, the next variant in its list is used, offset by the
run number, so the phases differ from each other and run 2 differs from run 1.
Both backends see the same sequence for the same run number. The report shows
which variant every phase ran.

The attack type sweep covers every attack variant on every run whatever the
rotation lands on. For each type the script stops all traffic, empties both
ipsets, restarts Stage 2 and waits `TYPE_GAP_SECS`, then runs the attack alone
and then with Normal traffic added. A block lasts an hour, which is why the
reset comes first: without it, one type's blocks would shorten the next type's
time to first block.

## Source addresses and entropy

The attack's spread of source addresses decides how far its entropy sits from
Normal and Flash Crowd traffic. A distributed attack that used as many
addresses as the Normal generators would look the same on that axis. Before
anything runs, the script counts the addresses in `ATTACK_SOURCE_FILE` on the
attack host and stops if the count is outside 30 to 40 (the lab attacker
currently holds 35). The counts are recorded in each run.

For every phase the report also shows which signal flagged the anomaly windows
Stage 1 forwarded: rate only, entropy only, or both, the share that involve
entropy, the mean entropy and the mean share of the busiest source. Stage 1
forwards only flagged windows and heartbeats, so these figures describe the
flagged windows and are not a sample of all traffic.

## What is measured

| Figure | Definition and source |
|-|-|
| Throughput | Packets per second and Mbit/s at the ingress interface, from `/sys/class/net/<iface>/statistics`, the same counter for both backends. Also packets per second seen by the capture backend (`raw_captured` for libpcap, `ingress` for the kernel backend). |
| Throughput under attack | The same figures during the four attack phases, plus egress packets per second: what still leaves the gateway. |
| Packet drops | At capture (unparseable, non-IP, and truncated frames for libpcap, map drain errors for the kernel backend), at the interface (`rx_dropped`, `rx_errors`), and by the firewall (packets matched by the DROP rules on the two ddos ipsets, from `iptables` counters read at each phase boundary). |
| CPU | Per service from `/proc/<pid>/stat`, and system wide from `/proc/stat`: busy, in the kernel, and in softirq. The kernel backend counts packets in XDP under softirq, which no per process figure attributes to Stage 1, so the system wide figures carry the comparison. |
| Context switches | Voluntary and involuntary per service, summed over its threads from `/proc/<pid>/task/*/status`, and system wide from `/proc/stat`. |
| Memory | Resident set size per service. |
| Inference latency | Stage 2's own timing of building the feature frame and running the RandomForest, and the Isolation Forest where it applies, for one window. |
| Window handoff latency | From the sensor's window close timestamp to Stage 2 receiving the vector. |
| Enforcement latency | The time one block or rate limit call takes, and the time from window close to the rule being in place. |
| Attack types and variants | Every phase lists the variant of each class it ran. The attack types section compares the backends on each type alone and with Normal traffic: DDoS verdicts, time to first block, detection consistency, and the entropy figures above. |
| Attack to drop | From the start of an attack phase to the first anomaly flag, the first DDoS verdict, the first block, and the first rate limit. Only the first two attack phases start the generator from off, so only they report it. |
| Detection consistency | Each phase is split into 10 second bins. In a benign phase, the share of bins with no DDoS verdict. In an attack phase, the share of bins holding a DDoS verdict from the first detection onward. The report also lists whether the two backends agree on each phase, and with `RUNS_PER_MODE` above 1, the spread between repeated runs. |
| Calibration | For each run: the outcome, how long it took, the per target clean windows, flagged share, mean and peak rate and derived floors, the floors recommended for all targets, the tuning line before and after, the restart time to apply them, and the time until the baseline was back. The comparison shows the recommended floors and the mean rate per target for each backend. |
| Downtime | From the request to stop the sensor to capture attached (for the kernel backend, the XDP attach line) and to the first capture status line. The status line is logged every 5 seconds, so that figure is coarse. |
| Rollback time | The same two measurements after restoring the original configuration, with the outcome of the restore and of the verification checks. |

### Stage 2 latency

Stage 2 logs one summary line every 30 seconds (`LATENCY_LOG_INTERVAL_SECS`,
0 turns it off):

```
Latency: summary | interval_secs=30 | handoff_n=30 handoff_mean_ms=0.412 handoff_p95_ms=0.900 handoff_max_ms=1.300 | inference_n=30 ... | enforcement_n=0 | window_to_rule_n=0
```

The report merges the intervals inside each phase. Means are weighted by sample
count. Percentiles cannot be merged exactly, so the p95 shown is the worst
interval's p95 and the maximum is the largest seen.

## Reading the results

- Figures are per phase, averaged over runs of the same backend.
- Each backend learns its own baseline, so the phases are comparable and the
  runs stay independent, but the generators do not repeat exactly. A difference
  of a few percent between two runs of one backend is normal, which is what
  `RUNS_PER_MODE` above 1 measures.
- Attack phases after the first inherit blocks from the earlier ones within a
  run, so their time to first block reads shorter than a cold start.
- Time to first detection includes the generator's ramp up after the phase
  begins, and the same ramp applies to both backends.
- The interface counter covers all traffic on the interface, and the capture
  backend sees the filtered set, so the two throughput figures differ by design.
- Downtime measures the sensor restart. Traffic that arrives while the sensor
  is stopped goes unobserved. The full comparison of this window matters most
  for V14, where a fallback from a failed in-kernel program to the user space
  Random Forest is planned (see the [roadmap](roadmap.md)).

## Results

Read against the raw files of `session_20260919T103029Z`. The kernel run's
warm-up, calibration, `normal` and `flash_crowd` phases ran mostly without a
working path to the targets (see the egress fault under the problems below), so
the two runs are not equivalent in those phases. Figures are means
over the phases that carried traffic (the seven standard phases and the sweep
phases for the `mixed`, `shapeb` and `single_mp` attacks), with the range across
those phases beside them. The `syn_flood` phases are separate, since an unpaced
flood at 105,000 to 123,000 packets per second is a different regime, and the
`mp_flood` phases sent no traffic (see the problems below).

### Capture and resource use

| Figure | Kernel | libpcap |
|-|-|-|
| Packets captured against the interface counter | within about 5% in most phases (83% during `syn_flood`) | within about 5% in most phases (88% during `syn_flood`) |
| Packets dropped at capture, and at the interface | 0 drain errors, 0 interface drops | 0 dropped at capture, 0 interface drops |
| Stage 1 CPU | 3.2% (0.8 to 6.1) | 10.8% (2.4 to 20.4) |
| System CPU busy | 8.1% (2.1 to 15.0) | 10.8% (3.3 to 19.4) |
| Stage 1 context switches per second | 6 (4 to 7) | 4,179 (289 to 6,598) |
| System context switches per second | 727 (372 to 1,195) | 8,239 (1,057 to 12,475) |
| Stage 1 memory, average | 7.8 MB (peak 11.8 MB) | 271 MB (peak 272.8 MB) |
| Stage 2 CPU | 24.2% | 23.9% |
| Stage 2 memory, average | 250.6 MB (peak 273.2 MB) | 249.7 MB (peak 268.3 MB) |

At the flood rate the order of the CPU figures changes. During `syn_flood`
Stage 1 used 78% to 80% of a CPU in the kernel run and 54% to 55% in the
libpcap run, and system CPU was 18% to 34% and 32% to 35%. The kernel run's
Stage 1 context switches stayed at 12 to 21 per second while libpcap's reached
21,000. The kernel backend's own counters showed no drain errors at that rate.

Throughput at the interface reached 4,700 to 5,500 packets per second (2.4 to
3.0 Mbit/s) in the standard attack phases and 105,000 to 123,000 packets per
second (54 to 63 Mbit/s) during `syn_flood`. The two runs saw the same
interface rates in each phase to within a few percent.

### Latency

| Figure (mean per phase) | Kernel | libpcap |
|-|-|-|
| Handoff from the sensor to Stage 2 | 28 ms (18 to 48) | 7.6 ms (1.6 to 34) |
| Inference (frame build, Random Forest, Isolation Forest) | 26 ms (17 to 42) | 27 ms (16 to 51) |
| One enforcement call | 0.08 ms | 0.05 ms |
| Window close to rule applied | 51 ms (37 to 83) | 28 ms (19 to 40) |
| Attack start to first block | 0.5 to 1.4 s (9.5 s for `syn_flood`) | 0.6 to 0.8 s (6.4 s for `syn_flood`) |

Inference is the largest measured piece of the path in both runs and takes
about as long on either backend. The kernel run's handoff was longer in every
phase, and this run does not show why. During `syn_flood` handoff rose to 78 to
87 ms (kernel) and window close to rule applied to 116 to 122 ms.

### Switching, rollback and calibration

| Figure | Kernel | libpcap |
|-|-|-|
| Capture attached after the restart | 1.66 s | 0.11 s |
| First capture status line | 6.7 s | 16.2 s |
| Baseline back after the first warm-up | 200 s | 210 s |
| Calibration | 1,134 s, 1,001 to 1,091 clean windows per target | 1,224 s, 1,006 to 1,167 |
| Floors derived | rate 3.4, entropy 0.0936 | rate 2.5, entropy 0.1089 |
| Restart to apply the floors | 7.1 s | 5.2 s |

The rollback restored `tuning.env` byte for byte, the sensor came back in the
kernel backend with XDP attached, both ipsets were present, and all checks
passed (attach after 1.69 s, first status after 6.7 s).

The libpcap first status line is not a readiness measure. That line is logged
only when a packet arrives, and generators were stopped at the switch, so the
16.2 s is the wait for Normal traffic. Read the attach time for the restart.

The two backends calibrated to different rate floors (3.4 against 2.5, a 26%
difference), so each ran its phases under its own thresholds. Calibration also
flagged 3.5% to 10.3% of the kernel run's windows against 0% to 0.9% of the
libpcap run's, on Normal traffic of about 11 packets per second per target.

### Detection

- In the three phases without an attack, `normal` had no verdicts or actions on
  either backend, and `flash_crowd` (the even variant) had none on the kernel
  backend and 2 DDoS verdicts and 31 rate limits on libpcap. The third,
  `normal_flashcrowd`, is described next.
- The `hot` Flash Crowd variant (one source far above the rest, run with Normal
  traffic) drew DDoS verdicts on both backends: 34 (2.3% of flagged windows) on
  kernel and 15 (1.1%) on libpcap, and rate limits on 131 and 109 distinct
  addresses. This is the concentrated legitimate crowd that the training data
  lacks, and it is a false positive.
- Every attack type except `mp_flood` produced enforcement on both backends. DDoS
  verdicts stayed rare, 0% to 12% of flagged windows and mostly 2% to 5%, and the
  rate limit and block tiers did most of the mitigating. In the sweep phases that
  add Normal traffic to an attack, DDoS verdicts were 0 for every attack type on
  both backends while blocks and rate limits continued. In the standard
  `normal_attacker` phase they were 54 (kernel) and 42 (libpcap).
- `syn_flood` alone drew 0 verdicts and 280 blocks on kernel and 46 verdicts and
  314 blocks on libpcap. `single_mp` (one source) drew 8 verdicts on kernel and
  74 on libpcap.
- The backends agreed on whether a DDoS verdict was issued in 14 of 17 phases,
  and on whether enforcement acted in 16 of 17 (`flash_crowd`).
- In the standard `attacker` phase, which has no Flash Crowd traffic, both
  backends rate limited the 97 Flash Crowd source addresses from the phase before
  as well as the 35 attack sources. The attack type sweep, which empties the ipsets and restarts
  Stage 2 first, hit only the 35 attack addresses. The cause is not established.

### Entropy

The attack's 35 source addresses put its entropy well below Normal's. On flagged
windows the mean entropy was 0.80 to 0.84 for the distributed attacks alone,
0.61 to 0.71 with Normal traffic added, and 0.001 for the single source attack
alone (0.13 to 0.18 with Normal). Entropy took part in 49% to 66% of the flagged
windows when a distributed attack ran alone (rate did the rest) and in 83% to 99%
once Normal or Flash Crowd traffic was added. The unpaced `syn_flood` kept mean
entropy at 0.93 to 0.97 alone, with entropy involved in 2% to 15% of its flagged
windows, and 60% to 80% with Normal traffic added.

### Problems found in this session

- The `mp_flood` attack sent no traffic in either run. `attack_mp` on the
  attacker machine has a `#!/bin/sh` line and uses `mapfile`, which busybox `sh`
  does not have, so it exits at once. This is the same fault `high_traffic` had.
  The generator is on the lab machine and outside this repository. Its two
  phases in each run carry no data.
- The analysis mixed the two libpcap capture threads. With an egress interface the
  sensor logs status lines for both interfaces and the lines interleave, and the
  analysis read them as one series. It also credited a previous phase's traffic
  to a phase after a quiet gap, since libpcap logs its status only when packets
  arrive. Both are fixed, and the figures above use the fixed analysis.
- The gateway's egress interface goes down for minutes at a time, and that
  affected the kernel run more than the libpcap run. `ens256` belongs to a
  NetworkManager profile ("Wired connection 3") set to DHCP (`ipv4.method
  auto`) with the static address 10.0.0.254/24 added. No DHCP server answers on
  that network, so each activation fails after 45 seconds with
  `ip-config-unavailable`, NetworkManager takes the interface down and the
  address and the route to the targets go with it, and after three attempts it
  waits five minutes before trying again. While it is down the gateway cannot
  forward, so the targets receive nothing, the egress counters read zero and the
  dashboard shows all the incoming traffic as not reaching the target. Restarting
  NetworkManager re-adopts the interface (`assume`) and gives about two minutes
  of forwarding before the cycle repeats, which is why it looked as if it
  needed a restart every couple of minutes. The interface's own egress counter
  follows the cycle sample for sample: egress traffic in 35 of 35 samples during
  three activation attempts (10:33:58 to 10:36:58) and in 1 of 58 during the
  backoff that followed, with incoming traffic in all of them. It is not caused
  by the capture backend. The failure loop ran in both runs (45 failed
  activations in the kernel run's window, 66 in the libpcap run's, 32 since the
  session ended with no restarts), and the runs differ because NetworkManager
  was restarted 16 times during the kernel window, the first 30 minutes in, and
  31 times during the libpcap window, from the start. In the kernel run the
  warm-up, the calibration and the `normal` and `flash_crowd` phases therefore
  ran mostly without a working path to the targets (samples with incoming
  traffic and no egress: 59% of warm-up, 23 of 23 in `normal`, 24 of 24 in
  `flash_crowd`; none in the libpcap run). Those phases, and the floors derived
  from them, are not comparable between the runs. A change to the profile
  (`ipv4.method manual`, IPv6 off) should remove the cycle and is proposed, not
  applied. Separately, the vmxnet3 driver reinitializes `ens192` at every XDP
  attach and detach (the kernel log shows the link coming up again at each
  kernel mode start), and NetworkManager logged nothing for `ens192` at those
  moments, so this run does not show that it matters.
- Antigravity restarted NetworkManager by hand during the session (47 times).
  The script does not do this and nothing recorded it in the results. The
  restarts were a workaround for the profile fault above, and manual changes
  during a session should still not happen.
- One run per backend, so the spread between identical runs is unknown, and the
  backends ran under different floors.
