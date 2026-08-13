# FLOD System

**First Line Of Defense**

An adaptive two stage Layer 4 volumetric DDoS mitigation gateway.

**Author:** Abdullah Armiyao

**Project:** Adaptive Two Stage Framework for Near Real Time Layer 4 Volumetric
DDoS Mitigation Using Behavioral Traffic Analysis


## What It Does

Most DDoS mitigation uses fixed thresholds: block anything sending more than
some hard coded number of packets per second. That fails in both directions.
Legitimate traffic spikes during a busy period and real users get blocked, or
an attacker stays just under the line and gets through.

FLOD learns what your normal traffic looks like and moves its own detection
boundaries to match. It distinguishes a DDoS flood from a flash crowd, a
legitimate surge, without anyone adjusting a threshold by hand.

It sits inline on a gateway between the traffic source and the hosts being
protected, and drops or throttles offending sources in the kernel.


## How It Is Built

**Stage 1** is a Rust sensor on the packet path. It captures every packet
headed for a protected host, computes rate and source diversity over short
windows, and compares them against a baseline it maintains itself. It does only
arithmetic, so it stays out of the way of traffic.

**Stage 2** is a Python service. It receives a summary from Stage 1 once per
window, classifies it with a Random Forest, and issues kernel level enforcement
through ipset and iptables. It also serves the web dashboard.

The two are connected by a Unix domain socket.


## Scope

FLOD works on Layer 4 volumetric floods visible from packet headers alone:
rate, source IP entropy, protocol mix, and how concentrated traffic is on its
busiest source. In practice that means floods which are both high volume and
concentrated, arriving from a bounded set of real addresses.

Two things are explicitly out of scope:

**Randomized source spoofing.** Forging a new source address per packet raises
entropy instead of lowering it, inverting the signal the detector looks for.

**Application layer attacks.** No request content is parsed, so low and slow
request floods and connection exhaustion are outside what a header only feature
set can observe.


## Quick Start

```bash
git clone https://github.com/DevInBlack001/ddos-reduction-system.git
cd ddos-reduction-system
sudo bash scripts/install.sh --interface <IFACE> --victim-ips <IP1>,<IP2>

cd stage2 && sudo venv/bin/python3 setup_admin.py

sudo systemctl enable --now ddos-stage2
sudo systemctl enable --now ddos-stage1
```

The dashboard is on port 8000. Full instructions, including the network layout
this depends on, are in the wiki.

The installer also sets up the eBPF build toolchain when it can, matching
whatever LLVM your distribution ships. That part is optional: without it the
sensor still builds and runs on libpcap.

The sensor has two capture backends. libpcap is the default and works
anywhere. With the toolchain in place, `--capture-mode kernel` counts packets
in the driver path via XDP and TC instead, waking user space once per window
rather than once per packet. Detection is identical either way.

To run the test suites:

```bash
scripts/test.sh
```


## Documentation

**Wiki**, for running the system:

| Page | Covers |
|-|-|
| Installation | Requirements, network placement, first login |
| Configuration | Sensor flags, enforcement tuning, alerts |
| Dashboard Guide | Every page in the console |
| Troubleshooting | When something is not working |

**docs/**, for understanding or changing it:

| Document | Covers |
|-|-|
| [Architecture](docs/architecture.md) | The pipeline, threading, capture tuning, egress measurement |
| [Detection](docs/detection.md) | Welford, EWMA, entropy, anomaly boundaries, baseline persistence |
| [IPC](docs/ipc.md) | The feature vector wire format |
| [Enforcement](docs/enforcement.md) | Classification, the four mitigation tiers, NAT handling |
| [Training](docs/training.md) | Capturing labelled data and training the model |
| [Testing](docs/testing.md) | Running both test suites |
| [Security](docs/security.md) | The hardening pass and the threat model |
| [Roadmap](docs/roadmap.md) | Completed and planned versions |

[CONTRIBUTING.md](CONTRIBUTING.md) covers development setup and conventions.
[SECURITY.md](SECURITY.md) covers reporting vulnerabilities.


## Authorship

This project is my own. The concept, the architecture, the two stage design,
the detection approach, the enforcement policy, the feature set, and every
functional decision across all versions originated with me. I built it as a
learning exercise in network security, statistical detection, and systems
programming, and I directed its design and evolution throughout.

I used AI as a coding assistant during implementation, writing and refactoring
code to my specifications and acting as a sounding board while I worked through
design trade offs. The decisions about what to build, why, and how the system
should behave were mine.


## Status

A capstone project, and a working system, but not one that has been through the
adversarial testing a production security product needs. Deploy it on a lab
network or somewhere you can afford to have it be wrong.


## Licence

See [LICENSE](LICENSE).
