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

Status: two sessions have run on 2026-09-19 in the simulated lab environment
(10:30 to 12:30 and 14:11 to 16:14 UTC), one run per backend each. The second is
the reliable one, and the results are at the end of this page. One run per
backend means nothing here shows how much a figure moves between identical runs.

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

Two sessions have run in the simulated lab environment, each with one run per
backend (kernel, then libpcap), calibration on `apply`, the attack type sweep on,
and Normal, Flash Crowd and attack variants rotating. Both were read against the
raw files. Figures are means over the phases that carried traffic (the seven
standard phases and the sweep phases for `mixed`, `shapeb` and `single_mp`),
with the range beside them, and latency uses the median across phases because
single phases carry multi-second outliers.

The second session (`session_20260919T141144Z`, 14:11 to 16:14 UTC) is the one
to rely on. Forwarding to the targets worked throughout (no NetworkManager event
on the egress interface, and no phase with incoming traffic and no egress), the
`mp_flood` generator sent traffic, and the two backends calibrated to nearly the
same floors (rate 2.3 and 2.2, entropy 0.0780 and 0.0787). The first session
(`session_20260919T103029Z`, 10:30 to 12:30 UTC) ran its kernel half with the
egress interface down for most of the first 30 minutes, so its warm-up,
calibration, `normal` and `flash_crowd` phases are not comparable, and its
`mp_flood` phases carry no data (see the problems below).

### Capture and resource use (second session)

| Figure | Kernel | libpcap |
|-|-|-|
| Stage 1 CPU | 4.3% (1.0 to 10.4) | 12.9% (3.8 to 24.7) |
| Stage 1 context switches per second | 6.5 (4 to 12) | 3,759 (279 to 5,252) |
| Stage 1 memory, average | 8.0 MB (peak 11.8 MB) | 271 MB |
| System CPU busy | 12.2% (3.3 to 25.3) | 13.6% (6.1 to 24.6) |
| Stage 2 CPU | 31.7% (13 to 53) | 31.9% (21 to 72) |
| Packets dropped at the interface | 0 | 0 |
| Stage 1 CPU at the four unpaced flood phases (82,000 to 108,000 packets per second) | 75% to 82% | 48% to 53% |
| Packets the backend counted, as a share of the interface counter, at those floods | 79% to 89% | 89% to 100% |

The first session gave the same picture: Stage 1 at 3.2% against 10.8% CPU, 6
against 4,179 context switches a second, and 7.8 MB against 271 MB, with the CPU
order also reversed at the SYN flood (78% to 80% against 54% to 55%). So these
figures replicated. Interface throughput in the standard attack phases was 4,600
to 5,400 packets per second (about 2.4 to 3 Mbit/s) and the two runs saw the same
rate in each phase to within a few percent.

### Latency

| Median across phases (ms) | Kernel | libpcap |
|-|-|-|
| Handoff from the sensor to Stage 2 | 43 (first session 30) | 12 (first session 5) |
| Inference (frame build, Random Forest, Isolation Forest) | 32 (28) | 30 (28) |
| Window close to rule applied | 72 (45) | 45 (30) |
| One enforcement call | 0.05 to 0.10 | 0.04 to 0.09 |

The kernel backend's handoff was longer than libpcap's in both sessions, and in
most attack phases by 1.5 to 12 times (in the Normal and Flash Crowd phases the
two were close or libpcap was longer). This run does not show why. Inference took
about the same on both. The libpcap run had rare, large stalls that a mean
hides: in the second session one phase (`normal_flashcrowd`) had a mean handoff
of 2.8 s and a 25 second maximum, and Stage 1 logged three IPC writes to Stage 2
failing with "Resource temporarily unavailable" (the socket to Stage 2 was full,
so Stage 2 was behind). The first session had one such stall per run around
Stage 2 restarts. With inference at 30 ms a window and six targets, Stage 2
handles windows one after another, and the run shows what happens when it falls
behind. Attack start to first block was 0.4 to 1.3 s for the jittered attacks
(libpcap never blocked `single_mp`, it rate limited it) and 5.7 to 9.1 s for the
unpaced floods, apart from `mp_flood` on libpcap, where the first block came 90 s in.

### Switching, rollback and calibration

| Figure (second session) | Kernel | libpcap |
|-|-|-|
| Capture attached after the restart | 1.60 s | 0.13 s |
| First capture status line | 6.6 s | not seen within 60 s |
| Calibration | 1,209 s | 1,163 s |
| Floors derived | rate 2.3, entropy 0.0780 | rate 2.2, entropy 0.0787 |
| Restart to apply the floors | 7.0 s | 5.3 s |

The rollback restored `tuning.env` byte for byte, the sensor came back in the
kernel backend with XDP attached, and all six checks passed (attach after 1.72 s,
first status after 6.76 s). The first session's figures were the same to within
0.1 s.

The libpcap first status line is not a readiness measure. That line is logged
only when a packet arrives, and generators are stopped at the switch, so it
waited for Normal traffic (16.2 s in the first session and past the 60 s limit in
the second). Read the attach time for the restart.

### Detection (second session)

- The backends agreed on whether a DDoS verdict was issued in 14 of 17 phases and
  on whether enforcement acted in 17 of 17. Enforcement matched the expected
  outcome in 15 phases on each backend, and the two misses are the Flash Crowd
  phases, where both backends acted.
- DDoS verdicts stayed rare, and the rate limit and block tiers did most of the
  mitigating. In the sweep phases that add Normal traffic to an attack, DDoS
  verdicts were 0 for every attack type on both backends while blocks and rate
  limits continued.
- Flash Crowd is where the system errs. The `hot` variant (one source far above
  the rest, with Normal traffic) drew 26 DDoS verdicts on kernel and 65 on
  libpcap, and rate limits of 725 and 620. The even variant drew 2 verdicts and
  14 rate limits on kernel and 24 verdicts and 522 rate limits on libpcap. In the
  first session the `hot` variant drew 34 and 15 verdicts. The training data has
  no concentrated legitimate crowd, and the even variant's libpcap result
  suggests that even it can be misread at these rates. The interface rate of the
  even variant differed between the runs (about 1,000 against 600 packets per
  second), so the two are not identical loads.
- Every attack type was mitigated on both backends, including `mp_flood`, which
  now sent about 100,000 packets per second. Verdict counts differ by type and
  backend: `mixed` 53 and 53, `shapeb` 23 and 22, `syn_flood` 58 and 0,
  `mp_flood` 0 and 89, `single_mp` 57 and 93 (kernel and libpcap). The unpaced
  floods produced verdicts on one backend and none on the other, which shows how
  much the verdict count depends on timing at those rates.
- In an attack-only phase of the first session both backends rate limited the 97
  Flash Crowd addresses from the phase before. The cause was found afterwards:
  see "Flow snapshot" below.

### Entropy (second session)

The attack's 35 source addresses put its entropy well below Normal's. On flagged
windows the mean entropy was 0.81 to 0.85 for the jittered distributed attacks
alone, 0.61 to 0.72 with Normal traffic added, and 0.000 for the single source
attack alone (0.13 to 0.14 with Normal). Entropy took part in 57% to 63% of the
flagged windows when a jittered distributed attack ran alone and in 87% to 95%
once Normal traffic was added; the same shift showed in the first session (49% to
66%, then 83% to 99%). The unpaced floods kept mean entropy at 0.90 to 0.97
alone, with entropy involved in 4% to 37% of flagged windows, and 73% to 97% with
Normal traffic added.

### Problems found

- **The egress interface fault (first session).** `ens256` belonged to a
  NetworkManager profile set to DHCP with a static address added, and no DHCP
  server answers on that network. Each activation failed after 45 seconds, the
  interface lost its address and the route to the targets, and after three
  attempts NetworkManager waited five minutes. While it was down the gateway
  could not forward, so the targets received nothing, the egress counters read
  zero and the dashboard showed all incoming traffic as not reaching the target.
  A NetworkManager restart gave about two minutes of forwarding. The interface's
  own counter followed the cycle sample for sample (egress traffic in 35 of 35
  samples during three activation attempts and 1 of 58 during the backoff). It
  affected both backends (45 failed activations in the kernel run's window, 66 in
  libpcap's, 32 after the session with no restarts) and the runs differed because
  NetworkManager was restarted 16 times in the kernel window and 31 times in the
  libpcap window. The profile was changed to `ipv4.method manual` with IPv6 off
  on 2026-09-19 at 13:52 UTC, and the second session had no NetworkManager event
  for the whole run. The benchmark now refuses to start when the egress interface
  has no address, and the report warns about a phase with legitimate traffic where
  more than 20% of the sample intervals had incoming traffic and no egress.
  Separately, the vmxnet3 driver reinitializes `ens192` at every XDP attach and
  detach, and NetworkManager logged nothing for `ens192` at those moments, so
  this run does not show that it matters.
- **`mp_flood` sent nothing in the first session.** `attack_mp` had a `#!/bin/sh`
  line and uses `mapfile`, which busybox `sh` does not have. The shebang is bash
  now and the second session shows the attack running.
- **The analysis mixed the two libpcap capture threads.** With an egress
  interface the sensor logs status lines for both interfaces and the lines
  interleave, and the analysis read them as one series. It also credited a
  previous phase's traffic to a phase after a quiet gap. Both are fixed. The
  egress stall warning applies only to phases with Normal or Flash Crowd traffic,
  because the firewall drops an attack-only phase's traffic by design.
- **Manual changes during a session.** In the first session NetworkManager was
  restarted by hand 47 times as a workaround for the egress fault. The second
  session had none.
- **One run per backend.** The spread between identical runs is still unknown,
  and the latency stalls above show that some figures move a lot from run to run.

### Follow-up on the open findings (2026-09-19)

These come from the two sessions above, the gateway's capture files and models,
and a replay of the captured windows. Nothing here needed a new run.

- **Stage 2 falling behind.** One cause is confirmed. `auto_label.py` held the
  capture file lock for a whole read, score and rewrite pass and scored one row at
  a time. `ipc_receiver.py` waited on that lock inside its receive loop, so the
  IPC socket filled and window handoff jumped from milliseconds to tens of
  seconds. In the second session the only auto-label run (15:27:07 to 15:30:50,
  3 min 42 s of CPU) matches the stalls logged at 15:28:26, 15:29:44 and 15:30:49.
  A run on the gateway at 16:43 to 17:01 took about 18 minutes for a
  50,000 row queue. Scoring the same 50,000 rows in one batch per model takes 2.0
  seconds on the workstation and stages the same 21,867 rows as the gateway run.
  The job now takes the lock only to read the file and to swap in the result with
  any rows appended meanwhile, and the receive loop tries the lock without waiting
  and queues rows in a bounded buffer.
- **A stall with no auto-label run.** The libpcap run stalled from about 15:45:40
  to 15:46:08 (handoff maximum 24.7 s). Stage 2 used about 7 CPU ticks per 5
  seconds in that stretch against about 200 around it, so it was waiting and not
  computing, and its log has nothing between 15:45:40 and 15:46:07. It then used
  about a full core to catch up. The burst of 97 rate limits at 15:46:09 ran at
  about 2 ms each after the stall ended, so that is a consequence. What Stage 2
  waited on is not identified. Stage 2 now records the time it spends handling
  each window (`busy` in the latency summary) and logs any window that takes a
  second or more, which separates a stall inside Stage 2 from windows arriving
  late.
- **Flow snapshot.** Stage 1 writes every flow to every protected host into one
  file about every 10 seconds, and Stage 2 read all of it on each DDoS window,
  whatever host a flow targeted and however old the snapshot was. The aggregate
  cap fallback therefore rate limited flows to other hosts and flows from the
  phase before, which explains the 97 Flash Crowd addresses limited in an
  attack-only phase. Enforcement now keeps only flows to the window's victim and
  ignores a snapshot older than 30 seconds.
- **Concentrated Flash Crowd.** The captured hot variant windows were replayed
  through the deployed RandomForest and the safety overrides. The RandomForest
  called them DDoS. The overrides changed no verdict. The hot windows have a
  dominant source share of 0.2 to 0.3 (median 0.21 to 0.32 per run) where the Flash
  Crowd corpus has 0.03 to 0.09, so a shallow forest reads them as concentrated.
  `scripts/label_from_benchmark.py` labels captured windows from the traffic the
  benchmark recorded for each phase. Adding one session's labeled rows (Normal, Flash
  Crowd and DDoS windows, repeated 5 times) to the corpus and testing on the other
  session, hot and even Flash Crowd windows called DDoS fell from 39 of 45 to 3 of 45
  and from 20 of 27 to 0 of 27 (depth 5). DDoS windows in the attack phases were
  still called DDoS (20,099 of 20,099, and 5,906 against 5,982 of 6,217).
  These are small, biased sets, since the capture files hold only windows the
  models called DDoS or doubted, so the figures show the direction and need the
  final run to confirm them.
- **Depth and the confidence gate.** The depth rule picked depth 3 because depths
  3 to 5 tie at 0.997 accuracy. At depth 3, 75% of correctly classified held-out
  rows reach 0.90 confidence, and 64% of the correctly called live DDoS windows do.
  Depth 6 gives 88% and 96%. The rule now prefers the depth that clears the gate
  more often among depths that tie on accuracy, and picks depth 6 on the current
  corpus with 0.995 accuracy.
- **Isolation Forest flag rate.** Under the deployed tuning the Isolation Forest
  flagged 0.3% to 1.2% of Normal windows and 0.0% to 1.7% of Flash Crowd windows in
  the four runs (1 to 3 of 257 to 300 windows in Normal, 15 of 876 at most in Flash
  Crowd). The 100% and 27% figures came from the corpus and the deployed sigma floors
  disagreeing. The model retrained on 2026-09-19 at 16:43 has not been measured live.
- **Egress against ingress.** In the second session legitimate phases had egress
  packets at 94% to 100% of ingress on both backends. The 2.4 times gap recorded
  in August does not appear. The attack phases show 7% to 11%, which is the
  firewall dropping the attack.
- **Entropy variance.** `sigma_h` takes 20 distinct values in the 50,000 captured
  DDoS windows, and six of them cover 93%. They are the entropy floors and ceilings
  that different calibrations set (0.078 and 0.0787 are floors and cover 56% of the
  windows, 0.2263 to 0.2369 are ceilings). The floor comes from the spread measured
  across 33 clean windows per host during calibration, so a window sitting on it is
  at the measured baseline spread. Its weight in the RandomForest is 0.15%.
- **A torn row.** The gateway's `anomalous_capture.csv` holds one row of 18 fields,
  two rows interleaved, written on 2026-09-18 at 13:47. It made every auto-label run
  log a warning. Rows with the wrong column count are now dropped, and rows with a
  non-finite value stay out of the models.
- **Auto-labeled rows and the gate.** The 21,867 rows staged on the gateway are all
  labeled DDoS. 7,567 fall in attack-only phases, 14,297 in phases that mix attack
  with other traffic, and 3 in Flash Crowd phases. Of the at least 108 Flash Crowd
  window verdicts captured as DDoS, 3 passed the agreement and confidence gate.
- **Why every staged row is DDoS.** The two capture files that hold scorable rows
  are `ddos_capture.csv`, which only ever receives windows the RandomForest called
  DDoS, and `anomalous_capture.csv`, which receives windows the Isolation Forest
  flagged. Routine Normal and Flash Crowd windows enter neither, so the labeling
  pass has no path to a Normal or Flash Crowd row from ordinary traffic. On the
  gateway's 2026-09-19 files the DDoS capture yielded all 21,867 staged rows and the
  anomalous capture yielded none: 35,996 of its 49,999 rows are zero-traffic windows
  (all six traffic fields exactly 0.0), which are never labeled, and none of the
  other 14,003 reach 0.90 confidence in the RandomForest. Zero-traffic windows are no
  longer written to the anomalous capture. Rows labeled from benchmark phases fill the
  gap (`scripts/label_from_benchmark.py`).

