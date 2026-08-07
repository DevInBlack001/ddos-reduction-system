# Security Policy

FLOD System is a solo research/personal project. There's no dedicated security
team and no SLA, but reports are taken seriously and triaged as quickly as
possible.

## Supported Versions

Only the most recent tagged release is supported with fixes. Older tags exist
for historical reference only.

| Version | Supported          |
| ------- | ------------------- |
| 0.5.x   | :white_check_mark:  |
| < 0.5   | :x:                  |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

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
- Issues that require root/local access to the host the sensor already runs
  on with elevated privileges.

## Security Considerations for Deployment

This system is designed to run inline on a network gateway with elevated
privileges (raw packet capture, `ipset`/`iptables` rule injection). A few
things to keep in mind if you deploy it:

- The Stage 2 dashboard performs authentication and session handling; it is
  not intended to be exposed directly to the public internet. Put it behind
  a VPN, reverse proxy with additional access controls, or restrict it to a
  management network.
- The enforcement process needs the capability to modify firewall rules —
  treat its credentials and the host it runs on with the same care as any
  other privileged network infrastructure.
- The IPC socket between Stage 1 and Stage 2 is local-only by design; don't
  expose it over the network without adding authentication.
