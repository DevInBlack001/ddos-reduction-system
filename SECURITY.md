# Security Policy

FLOD System is a solo research/personal project. There's no dedicated security
team and no SLA, but reports are taken seriously and triaged as quickly as
possible.

## Supported Versions

Only the most recent tagged release is supported with fixes. Older tags exist
for historical reference only.

| Version | Supported          |
|-|-|
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

The `v1` through `v5` branches are frozen mirrors of tags `0.1` through `0.5`,
kept so each version stays browsable. They are **not** maintained lines and
receive no fixes. Treat the tags as authoritative.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through any public channel.**
That includes GitHub Issues, Discussions, and the Wiki.

Use GitHub's private vulnerability reporting instead:

1. Go to the [Security tab](../../security) of this repository.
2. Click **"Report a vulnerability"**.
3. Include what you'd normally include in a report: affected component
   (Stage 1 sniffer/enforcement, Stage 2 API/dashboard, IPC layer), steps to
   reproduce, impact, and any PoC.

You should get an initial response within a few days. If the issue is
confirmed, a fix will be prioritized and credit given in the release notes
unless you'd prefer otherwise.

## Scope

In scope:
- Stage 1 (Rust): packet capture, feature extraction, IPC to Stage 2.
- Stage 2 (Python): FastAPI dashboard, auth, enforcement logic (`ipset`/`iptables`
  rule generation), report generation.
- The IPC channel between the two stages.

Out of scope:
- Vulnerabilities in third-party dependencies with no exploitable path through
  this project's usage of them (report those upstream instead).
- Issues that require pre-existing **root** on the sensor host. If an attacker
  already has root there, they control the enforcement layer outright.

Explicitly **in** scope, despite the above: anything reachable by an
*unprivileged local account* on the sensor host. Privilege boundaries on that
host are part of the threat model, not outside it. Stage 1 runs as a dedicated
service account holding only `CAP_NET_RAW`, the IPC socket and runtime files
live in a root-owned directory rather than a world-writable one, and the
credential store is mode 0600. Anything that defeats one of those separations
is a valid report.

## Security Considerations for Deployment

This system is designed to run inline on a network gateway with elevated
privileges (raw packet capture, `ipset`/`iptables` rule injection). A few
things to keep in mind if you deploy it:

- The Stage 2 dashboard performs authentication and session handling; it is
  not intended to be exposed directly to the public internet. Put it behind
  a VPN, reverse proxy with additional access controls, or restrict it to a
  management network.
- The enforcement process needs the capability to modify firewall rules.
  Treat its credentials and the host it runs on with the same care as any
  other privileged network infrastructure.
- The IPC socket between Stage 1 and Stage 2 is local-only by design; don't
  expose it over the network without adding authentication.
