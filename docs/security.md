# Security

Beyond the statistical poisoning defences in [detection.md](detection.md), this
covers what an attacker or a misconfigured deployment could target directly.

To report a vulnerability, see [SECURITY.md](../SECURITY.md). Not the issue
tracker.

## Threat Model

Stage 1 runs as a dedicated unprivileged account with only the capability
needed for raw capture. Stage 2 runs as root because it drives ipset and
iptables.

Files holding credentials or secrets are owner only. That protects against
other local accounts, not against root. Since Stage 2 already runs as root,
pre existing root on the sensor host is outside the model; unprivileged local
access is inside it.

## Transport and Authentication

The console serves over HTTPS when a certificate is present, and the installer
generates a self signed one. Without a certificate it falls back to plain HTTP
with an explicit startup warning. Previously the login form, the session
cookie, and every enforcement call travelled in cleartext.

The session cookie is marked secure only when TLS is actually configured. A
secure cookie is never sent over plain HTTP, so setting it unconditionally
would lock out every deployment without a certificate.

Passwords are hashed with bcrypt, replacing a single unsalted round of SHA-256.
There is no default credential anywhere in the code. If the setup script was
never run, startup logs a warning and no login is possible.

Login attempts are throttled per client address, five failures in five minutes
followed by a lockout, to slow online brute forcing.

Sessions expire after ten minutes of inactivity.

## Input Validation and Output Encoding

Every address shaped field accepted from the dashboard is validated with
Python's `ipaddress` module before it can reach ipset or be stored. Without
this a CIDR string would be silently expanded by ipset into every host in the
range rather than the single address intended.

Dashboard pages that render server supplied strings escape them through shared
helpers. These were previously interpolated raw, a stored scripting path that
could run arbitrary code in an authenticated session. Since the session cookie
is HTTP only, script injection was the more dangerous path in, not the less:
injected code can call any endpoint same origin regardless of whether it can
read the cookie.

CSV export neutralises spreadsheet formula injection and uses proper quoting
rather than manual string formatting.

## Process and Filesystem Isolation

The IPC socket, the active flows telemetry, and the training label switch all
live in a root owned directory shared through a dedicated group, rather than a
world writable temporary directory.

Previously any local account could race to bind the socket path ahead of Stage
2, for instance during a restart, and either receive live telemetry or inject
fabricated windows straight into the enforcement pipeline.

The database, the whitelist, the target list, and the saved configuration are
all owner only. They were previously world readable, letting any local account
read credentials or enforcement thresholds off disk.

The database permission is set before write ahead logging is enabled. SQLite
gives the sidecar files the mode the database has when it creates them, and
those files hold recently written pages including user rows.

## Request Handling

A request body cap is checked from the declared length before the body is read,
and applies to every endpoint rather than only the export that motivated it.

PDF export writes chart images to unique per request temporary files, cleaned
up in a `finally` block, instead of fixed shared filenames that let concurrent
exports mix each other's charts. The incoming payload is size capped before
decoding.

Report diagrams are drawn server side as vector graphics rather than accepted
as uploaded images, so the server never renders content it was handed.

## Account Management

Creating an account, deleting one, or changing a password all require the
caller to re enter their own current password, verified against the caller's
stored hash rather than the target account's.

A session cookie alone, one that leaked through a brief scripting window or was
left signed in on a shared machine, used to be enough to durably take over
every admin account.

Sessions record their username, so a password change or account deletion
immediately invalidates every other live session for that user rather than
leaving a hijacked session usable until its own timeout.

The "cannot delete the last account" guard and the duplicate username check are
each enforced as a single atomic statement rather than a check followed by an
act. The separate pair left a race where two concurrent deletes could both pass
the check before either committed, leaving zero accounts.

Account deletion takes its parameters as a request body rather than query
parameters. A query string can land in access logs and browser history, which
is the wrong place for a password.

The alerts endpoint does not echo the configured webhook URL back in the clear.
It is a bearer credential: anyone holding it can post to that channel. It is
reduced to a boolean, matching how the stored mail password is handled, and the
dashboard only sends a new value when the operator types one.

## Resource Bounds

Anything keyed by attacker controlled data needs an explicit bound.

The flow map is capped, since its key comes from packet headers and a
randomized source flood would otherwise allocate an entry per packet.

The channel between capture and analysis is bounded, so a slow consumer blocks
the producer rather than growing memory without limit.
