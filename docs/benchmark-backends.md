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

Status: the scripts are built and tested against synthetic logs. The first
comparison run in the simulated lab environment is pending, so this page has
no results yet.

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
| `INGRESS_IFACE`, `EGRESS_IFACE` | empty | Interfaces whose kernel counters the sampler reads. Empty skips the interface figures. |
| `BASELINE_DIR` | `/var/lib/ddos_stage1` | Where each run's own baseline file lives. |

A run takes the warm-up (up to `WARMUP_TIMEOUT_SECS`, 900 by default) plus
1,050 seconds of phases at the default durations, plus the switch. Two
backends take roughly one hour.

Each session writes to `benchmark-live-results/session_<UTC time>/`, with one
directory per run (`kernel_run1`, `pcap_run1`) and a `report.txt` and
`results.json` for the session. Nothing is overwritten between sessions.

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
4. Waits for warm-up, then runs the seven phases: Normal, Flash Crowd,
   Attacker, Normal plus Flash Crowd, Normal plus Attacker, Flash Crowd plus
   Attacker, all three.

After the last run it restores the original `tuning.env` byte for byte,
restarts the sensor in its original mode, and verifies that too. An exit trap
does the same if the script is interrupted, and the report labels that as an
emergency rollback.

The traffic comes from the simulated lab environment's generator machines:
Locust for Normal and Flash Crowd, and the attack generator for the Attacker.
The attacker and flash crowd machines each carry sub-interfaces with about 100
addresses, attacks use 30 to 60 of the attacker's addresses, and Locust runs
100 users on each generator machine.

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
| Attack to drop | From the start of an attack phase to the first anomaly flag, the first DDoS verdict, the first block, and the first rate limit. Only the first two attack phases start the generator from off, so only they report it. |
| Detection consistency | Each phase is split into 10 second bins. In a benign phase, the share of bins with no DDoS verdict. In an attack phase, the share of bins holding a DDoS verdict from the first detection onward. The report also lists whether the two backends agree on each phase, and with `RUNS_PER_MODE` above 1, the spread between repeated runs. |
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

Not run yet.
