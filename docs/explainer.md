# Explainer

The rest of `docs/` is written for someone who is going to read or change the
code. This page is not. It explains what the system is actually doing, in
plain language, and then walks through every single number and field the
sensor measures, in the same order the code uses them, so a reader who is not
a programmer can look at any value in a log line, a report, or the wire
format and know what it means and why it is there.

No code appears below. Where a technical document is the authoritative source
for a detail, it is linked, but nothing here requires opening it.

## The Idea in One Paragraph

FLOD sits between the internet and the servers it protects. It watches
traffic going in one direction and learns what "normal" looks like for each
server it protects: how many packets per second usually arrive, how many
different senders usually contribute, what mix of protocols usually shows up.
Once it has learned that, it compares every few seconds of new traffic
against what it learned, and if something is far enough outside the normal
range, it flags it. A second program looks at the flag along with everything
else measured that period and decides whether to do nothing, block the
worst offender, or slow everyone talking to that server down for a while.

The two central ideas that make this possible, instead of just picking a
fixed number and blocking anything over it, are covered next.

## Why Not Just Pick a Number

A fixed threshold, "block anything over 1000 packets per second," fails in
both directions. A small server's normal traffic might be 50 packets per
second, so 1000 never trips even during a real flood. A busy server's normal
traffic might be 5000 packets per second on an ordinary Tuesday, so the fixed
number blocks real visitors constantly.

FLOD instead learns a baseline for each server it protects, separately, and
measures against that server's own normal rather than one number shared by
every server.

## Windows

Instead of reacting to every single packet, the sensor groups a few seconds
of traffic together, does its measuring once per group, and then starts a
fresh group. Each group is called a window. All the numbers below except the
ones explicitly marked as running totals describe one window: what happened
in that few seconds, not the whole history of the connection.

## The Baseline: Mean and How Much It Normally Wobbles

For a quantity like the packet rate, the system keeps two running numbers as
it watches ordinary traffic over time: the average value (the mean), and how
much that value typically wobbles from window to window around the average
(the standard deviation). A server whose rate is almost always close to its
average has a small wobble. A server whose rate genuinely varies a lot,
busier at some times of day than others, has a larger one.

Both numbers only update while a window looks ordinary. If a window looks
like an attack, it is excluded, so an attack never gets to redefine what
"normal" means partway through. This is covered in full in
[Detection](detection.md#baseline-poisoning-defences); the short version is
that an attacker slowly ramping traffic up cannot drag the baseline up along
with them, because a ramping window is exactly the kind that stops updating
the baseline.

## The Boundary: How Far From Normal Counts as Suspicious

Once the system knows a server's average and its normal wobble, it draws a
line: average, plus some number of wobbles. That number is called `k`, and it
defaults to 2. Two wobbles above average covers roughly 95 percent of
ordinary variation for a bell curve shaped quantity, so something past that
line is unusual enough to be worth a second look, without being so tight that
ordinary busy moments constantly trip it.

The same idea works in reverse for a measurement where an attack means the
number goes *down* rather than up, covered next.

## Diversity of Senders, and Why It Matters More Than Volume

A high packet count alone cannot tell a flood from a legitimate rush of
visitors, both are simply a lot of traffic. What tells them apart is how many
different senders that traffic is coming from, and how evenly it is spread
across them.

Picture ten different visitors sending five packets each, versus one visitor
sending forty one packets and nine visitors sending one packet each. Both
add up to the same fifty packets. The first is spread evenly. The second is
almost entirely one sender. A real flood usually looks like the second
shape, concentrated on very few senders, or even one, while a real rush of
genuine visitors usually looks like the first, spread across many.

The system boils this shape down to a single number between 0 and 1, called
entropy. Zero means every packet came from one sender. One means it was
spread as evenly as possible across everyone who sent anything. A concentrated
flood pulls this number down, so unlike the rate boundary above, the alarm
for entropy fires when the number drops too low, not when it climbs too
high.

### Where This Breaks: Forged Senders

The above assumes an attacker's traffic is easy to tell apart from real
traffic by who it is coming from. An attacker who fakes a different, made up
sender address on every single packet defeats that assumption directly: to
the entropy measurement, ten thousand fake addresses each sending one packet
looks exactly like ten thousand real visitors each sending one packet. Not
only does the flood escape the low entropy alarm, entropy reads *unusually
high*, the opposite of what a flood normally looks like, and the volume
alarm's own sensitivity is tied to entropy, so a high reading makes the
system slower to react on rate too.

This is a real limitation, not a rare edge case, and it is why three further
measurements exist that do not depend on who a packet claims to be from at
all. They are explained in [Measurements That Do Not Depend On The Sender's
Claimed Address](#measurements-that-do-not-depend-on-the-senders-claimed-address)
below.

## Warm Up

A brand new baseline built from a handful of windows is not trustworthy yet,
the same way judging whether today's traffic is unusual after watching for
ten seconds would be unreliable. The sensor collects 200 windows worth of
ordinary looking traffic per server before it will use that server's
baseline to flag anything. Those 200 windows still get reported so a
dashboard has something to show immediately, but they are explicitly marked
as warm up data, and nothing downstream is allowed to treat them as a
verdict. See [is_warmup](#is_warmup) below for what that marker looks like
on the wire, and why it had to be added.

## Cooldown

After a real attack is confirmed and then stops, the system does not
immediately relax back to its normal sensitivity. For a configurable number
of windows afterward, it stays easier to trip again, on the reasoning that
an attacker who backs off and restarts shortly after is common enough to
plan for. This period is called cooldown, and it counts down window by
window until it reaches zero.

## Measurements That Do Not Depend On The Sender's Claimed Address

Three further numbers exist specifically to survive the forged sender
problem described above. Each is built from a per window tally keyed by the
*value itself* (which port number, which TTL, which fingerprint) rather than
by who sent it, so faking a different sender address on every packet cannot
inflate or hide from any of them the way it can with the entropy measurement
above.

**Source port entropy.** Every packet leaving a computer is tagged with a
port number on the sending side, the source port, chosen more or less
arbitrarily by the sending computer's networking software. This measurement
applies the exact same diversity idea as sender entropy above, but counts
which source ports showed up instead of which sender addresses did. It
behaves like a second, independent read on the same underlying question,
"how varied is this traffic," from an angle a forged sender address does not
touch.

**TTL variance.** Every packet carries a small number called Time To Live
(TTL for IPv4, "hop limit" for its newer IPv6 counterpart), which starts at a
value the sending computer's operating system picks and counts down by one
at every router the packet passes through on its way here. Different
operating systems start at different values, and different real world paths
cross different numbers of routers, so traffic from a genuinely varied set of
real machines and network paths tends to arrive with a mix of TTL values, not
one identical number every time. This measurement is how much that value
varies within a window. A machine faking thousands of different sender
addresses is still, physically, one machine sending packets down one network
path, so it produces one TTL value over and over regardless of which
address it claims, which lower variance can expose even when the address
itself gives nothing away.

**TCP SYN fingerprint diversity.** Explained in full in the next section,
because it needs some background first.

### TCP, SYN Packets, and Fingerprinting

Two computers wanting to talk over TCP, the protocol behind most web
traffic, first perform a short handshake to open the connection. The very
first packet of that handshake is called a SYN packet, and it is where a
sending computer's operating system announces a small set of optional
settings it would like to use for the conversation: mainly, the maximum
message size it wants to receive, whether it can trim mismatched clock
timestamps for smoother timing, and how large a batch of data it can accept
before requiring an acknowledgment. Which of these options a given SYN packet
includes, and in what order, is not random. It is decided by the sending
computer's TCP software, which means it differs somewhat predictably between
operating systems, and between purpose built traffic generating tools and
ordinary consumer devices. Reading these signals off a SYN packet to guess
roughly what kind of software sent it, without looking at any of the actual
message content, is a long standing, well known technique, often called p0f
style fingerprinting after an early tool that did it.

FLOD reduces this signal to a small number, a fingerprint bucket: which of a
handful of common options were present, combined with a rough range for the
requested batch size. There is a small fixed table of these buckets, not a
free form value, because the point is to group similar looking SYN packets
together, not to identify an exact device.

**TCP SYN fingerprint diversity** is then the same entropy idea one more
time, applied to which fingerprint bucket showed up how often within a
window. A single tool blasting identical, scripted SYN packets at high
volume tends to produce one repeated fingerprint. A window with a genuinely
varied set of real client software behind it tends to produce a mix.

This measurement only has anything to say about TCP traffic that includes a
SYN packet in the window, since that packet is the only place these options
appear. A window with no such packet in it reads 0.0 for this value, the
same way sender entropy reads 0.0 for an empty window: not itself
suspicious, just "nothing to measure here."

## Protocols

Every packet is carried by one underlying network protocol. TCP is what most
web browsing, file transfer, and app traffic uses. UDP is common for video
calls, games, and DNS lookups, anything that would rather drop a little data
than wait for a retransmission. ICMP is diagnostic traffic, most familiarly
what a "ping" uses. SCTP, GRE, and ESP are less common: SCTP shows up in some
telecom and signalling systems, GRE and ESP are both used to carry traffic
inside tunnels between networks, ESP specifically as part of an encrypted
VPN tunnel. The system tracks what fraction of a window's traffic was each
one, since a flood is often unusually concentrated on a single protocol in a
way ordinary mixed traffic is not.

## Blocking, Throttling, and Confirming It Worked

When the system decides a sender is the source of an attack, it can drop
every packet from that sender outright (a block), or cap how fast it is
allowed to send without cutting it off entirely (a throttle, used when the
evidence is real but less certain, or when many senders are involved and
singling one out is not possible). Both wear off automatically after a set
period, so a wrong call heals itself rather than lasting forever.

Because the sensor watches both sides, what came in and what actually made
it through to the server, it can also measure whether a block or throttle
worked, rather than assuming it did because the order was given. What
fraction of a window's traffic never made it through is a direct measurement
of that.

## The Two Verdicts: What Kind of Traffic Is This, and Have We Seen Anything Like It Before

Once a window's measurements are gathered, two independent programs each
give an opinion on it, asking two different questions.

The first, a Random Forest, was shown thousands of examples of traffic
already labelled ordinary, a legitimate rush of visitors, or an attack, and
learned to recognise the shape of each. Given a new window, it answers "which
of the shapes I was taught does this most resemble."

The second, an Isolation Forest, was never told which examples were which
kind. It only learned the general shape of everything it was shown, of every
kind combined, and it answers a completely different question: "does this
look like *anything* I was shown, or is it strange enough to stand apart from
the whole training set." This exists because a supervised program like the
first one can only ever recognise the kinds of traffic it was actually
taught. An attack shaped differently from every example it saw has no
guaranteed reason to be recognised, no matter how good the training was. The
second program's job is specifically to catch that case: not "which known
category is this," but "is this unlike anything at all."

When the first program says a window looks ordinary or like a legitimate
rush of visitors, and the second says the same window looks unlike anything
in its training data, the window is labelled `Anomalous` and surfaced to
whoever is watching the dashboard, without automatically blocking or
throttling anyone. It is a flag for a person to look at, the same way a
legitimate rush of visitors is surfaced rather than acted on by itself. See
[Enforcement](enforcement.md#classification) for exactly how the two
opinions combine and what does and does not follow from each one.

## Why An Anomalous Flag Does Not Retrain Anything By Itself

Being told a window is unfamiliar is not the same as being told what it
is. It could be a genuinely new attack. It could just as easily be a
legitimate pattern nobody happened to capture while teaching the system
what "normal" looks like. Automatically feeding flagged windows back into
the program that learns from labelled examples would mean training it on a
guess nobody actually verified, and it opens a door: someone who notices
that sending traffic shaped a certain way keeps getting flagged could use
that to gradually influence what the system decides is acceptable, entirely
without ever being right about what their traffic actually was.

So instead, every window the Isolation Forest flags is written to a
separate file, `anomalous_capture.csv`, with everything a person would need
to go look into it, which server it concerned, the Isolation Forest's own
score, what the RandomForest had called it, and every one of the
measurements explained above. What it does not carry is a label, because
nothing at that point actually knows what the traffic was. Filling that in
is deliberately left to a person who can go check. Once someone has, that
row can be folded into the next round of training data the same way any
other labelled traffic can. See
[Training](training.md#reviewing-anomalous-traffic) for the full process.

## Every Field, In Order

Everything above is what the numbers *mean*. This section is what they are
*called*, in the exact order the sensor sends them, so a raw log line, a CSV
row, or the wire format documented in full in [IPC](ipc.md) can be read
field by field against the explanations above.

| Field | What it is | Explained above |
|-|-|-|
| `entropy` | This window's sender diversity, 0.0 to 1.0 | [Diversity of Senders](#diversity-of-senders-and-why-it-matters-more-than-volume) |
| `ewma_rate` | The smoothed packets per second reading, carried forward across windows rather than reset each time | [Windows](#windows) |
| `mean_h` | The learned average entropy for this server | [The Baseline](#the-baseline-mean-and-how-much-it-normally-wobbles) |
| `mean_r` | The learned average rate for this server | [The Baseline](#the-baseline-mean-and-how-much-it-normally-wobbles) |
| `sigma_h` | How much entropy normally wobbles for this server | [The Baseline](#the-baseline-mean-and-how-much-it-normally-wobbles) |
| `sigma_r` | How much the rate normally wobbles for this server | [The Baseline](#the-baseline-mean-and-how-much-it-normally-wobbles) |
| `proto_ratio` | An older measurement of TCP's share of traffic, kept for compatibility; `proto_tcp` below is the current equivalent | [Protocols](#protocols) |
| `dominant_ip_ratio` | What fraction of this window came from its single busiest sender | [Diversity of Senders](#diversity-of-senders-and-why-it-matters-more-than-volume) |
| `timestamp` | The moment this window closed | [Windows](#windows) |
| `proto_tcp` | TCP's share of this window's traffic | [Protocols](#protocols) |
| `proto_udp` | UDP's share | [Protocols](#protocols) |
| `proto_icmp` | ICMP's share | [Protocols](#protocols) |
| `proto_sctp` | SCTP's share | [Protocols](#protocols) |
| `proto_gre` | GRE's share | [Protocols](#protocols) |
| `proto_esp` | ESP's share | [Protocols](#protocols) |
| `k_multiplier` | How many "wobbles" past average currently counts as suspicious for this server, right now, including any cooldown adjustment | [The Boundary](#the-boundary-how-far-from-normal-counts-as-suspicious), [Cooldown](#cooldown) |
| `cooldown_counter` | How many windows are left in cooldown for this server | [Cooldown](#cooldown) |
| `egress_rate` | How many packets per second actually reached the server, after any blocking or throttling | [Blocking, Throttling, and Confirming It Worked](#blocking-throttling-and-confirming-it-worked) |
| `drop_ratio` | What fraction of this window's traffic never made it through | [Blocking, Throttling, and Confirming It Worked](#blocking-throttling-and-confirming-it-worked) |
| `source_port_entropy` | Diversity of sending ports this window, unaffected by a forged sender address | [Measurements That Do Not Depend On The Sender's Claimed Address](#measurements-that-do-not-depend-on-the-senders-claimed-address) |
| `ttl_variance` | How much the TTL / hop count varied this window | [Measurements That Do Not Depend On The Sender's Claimed Address](#measurements-that-do-not-depend-on-the-senders-claimed-address) |
| `fingerprint_diversity` | Diversity of TCP SYN fingerprints this window | [TCP, SYN Packets, and Fingerprinting](#tcp-syn-packets-and-fingerprinting) |
| `is_warmup` | Whether this window's baseline is still warm up data, not yet trustworthy | [Warm Up](#warm-up), [`is_warmup`](#is_warmup) |
| `dominant_ip` | The address of this window's busiest sender | [Diversity of Senders](#diversity-of-senders-and-why-it-matters-more-than-volume) |
| `victim_ip` | Which protected server this window describes | [The Idea in One Paragraph](#the-idea-in-one-paragraph) |

Three further numbers are not sent over the wire at all, because they are
simple arithmetic on fields already listed, and are computed only once they
reach the second program:

| Field | What it is | Formula |
|-|-|-|
| `delta_rate` | How far above or below this server's average rate this window's rate is | `ewma_rate - mean_r` |
| `delta_entropy` | How far above or below this server's average entropy this window's entropy is | `entropy - mean_h` |
| `dominant_rate` | Roughly how many packets per second the single busiest sender contributed | `ewma_rate * dominant_ip_ratio` |

### `is_warmup`

Worth its own note, because it fixed a real, observed mistake. The first 200
windows for a server, described in [Warm Up](#warm-up) above, do get sent
across so a dashboard has something to display immediately, but their
`mean_h`, `mean_r`, `sigma_h`, and `sigma_r` are built from only a handful of
samples and are not trustworthy yet. The program judging each window used to
have no way to tell a warm up window apart from a fully learned one, and
judged both the same way. Watched live: five servers restarted at once read
as `Anomalous` on nearly every single window during their warm up period,
purely because a program trained on fully warmed up traffic had never seen
numbers that raw and unsettled before, and mistook "unfamiliar" for
"suspicious." `is_warmup` is the fix: a plain marker carried alongside every
other measurement, `1.0` during those first 200 windows and `0.0` afterward,
and the deciding programs are told to skip judgment entirely while it reads
`1.0`, the same way a warm up window already skipped judgment on the sensor
side.
