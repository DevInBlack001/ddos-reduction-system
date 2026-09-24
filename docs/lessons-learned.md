# Lessons Learned

A record of real bugs found during development, kept because most of them
generalize past this specific project. Grouped by shape, not by date. Every
entry here ends in a fix or a rule adopted afterward. What is still open is
in [Known Gaps](known-gaps.md).

## A fix that compiled, passed its own tests, and did nothing

Sustained legitimate traffic growth could freeze a target's rate baseline
permanently: once the rate climbed past a boundary learned from an earlier,
lower-rate baseline, every subsequent window flagged too, which kept
cooldown re-armed, which kept the baseline from ever updating to catch up.
The fix added a cap, `--max-baseline-freeze-windows`: past that many
consecutive frozen windows, the current traffic is accepted as the new
baseline regardless.

It compiled, passed 74 tests, and changed nothing in practice. The escape's
own log line fired exactly as designed, but a separate, pre-existing
outlier check independently gated the same update and rejected the sample
the escape had just forced through, because a sample that spent hundreds of
windows building pressure against a frozen boundary necessarily deviates
from that boundary's stale mean and standard deviation by a wide margin,
which is precisely what an outlier check is built to catch. The escape and
the outlier check were both individually correct and mutually canceling.
Fixed by having a window that is clean specifically because it escaped a
freeze also bypass the outlier check for that one window, since the whole
point of forcing the escape is to trust the sample.

The lesson isn't "test more." Both pieces had tests, and both passed. It's
that two correct, independently-reasoned safety mechanisms can defeat each
other silently, and the only way to catch that is watching the actual
number the fix is supposed to move, not just the log line announcing that
it tried to.

## Data that looked fine at the row-count level and wasn't

**A curl-loop traffic generator that never sent a single request.** Deployed
with a `#!/bin/sh` shebang but written in bash (array syntax, `mapfile`,
`[[`). On a host where `/bin/sh` is a symlink to busybox rather than bash,
that shebang runs the script under an interpreter that doesn't implement
`mapfile`, which fails on the very first line that needs it. Under `set -e`,
that's the whole script: it exits before starting a single worker, silently,
for the entire configured duration. A full capture campaign completed
cleanly, three cycles, thousands of rows, no errors anywhere in the
orchestration log, and every row from that traffic class was a literal
zero-traffic window: rate, entropy, and every derived feature read exactly
zero. The row count and the cycle-completion log were both telling the
truth and both irrelevant; the bug was invisible at that level and only
showed up when the feature distributions themselves were checked before
trusting the data.

**A classifier trained on a stale tuning constant.** A rate floor was
recalibrated on the deployed sensor from its code default to a measured
value roughly seven times smaller. The training data backing the production
model predated that recalibration, so its own version of that feature was
pinned at the old, much larger floor for nearly every row, `max(raw,
old_floor)` swallowing whatever the real value would have been. Once the
sensor was recalibrated, live traffic's version of that same feature landed
in a range the model had never seen a single training example of, and the
model read the mismatch as "unlike anything in training," which is not the
same thing as "anomalous," on traffic that was otherwise unremarkable. The
model wasn't wrong about what it had learned; what it had learned no longer
matched what it was being asked to judge.

**Short sessions mislabeled by an automated capture script's own timing.**
An orchestration script starts an attack generator, sleeps through a ramp
period so the traffic has time to reach a representative rate, and only
then writes the new label. During that sleep, attack traffic is
already flowing into a window still stamped with the previous phase's
label. Six such sessions turned up in one capture: short, an elevated rate
that didn't match the label on them, sitting exactly at a phase boundary.
An early read using entropy alone flagged them as ambiguous, since some
looked lower-entropy (a concentrated flood's own well-known signature) and
some looked higher-entropy (closer to a legitimate crowd's signature, or so
it seemed). Checked against the real, correctly-labelled session
immediately adjacent to each one in the same capture run rather than
against entropy in isolation, all six matched their neighbor's real
signature, including the higher-entropy ones, because a distributed flood
legitimately reads high entropy too. The project's own detection design
already documents that as the reason randomized source spoofing evades an
entropy-only signal; the same fact almost caused a training row to be
mislabeled by the same mistaken assumption a defender could make. The
fix was the project's own already-documented rule for exactly this
situation, applied retroactively: relabel each contaminated session to
match what its own traffic actually measured, verified session by session
against a real neighbor, not discarded and not guessed at from one feature
in isolation.

## The same mistake, three times

A constant that's wrong for one deployment can only be fixed by
recompiling. This project hit that exact shape of bug three separate
times, on three unrelated pieces of tuning: an entropy floor sized from a
narrow sample of traffic, a set of baseline-drift and cooldown constants
added together in one pass, and BPF map capacities that were compiled in
rather than set by user space at load time. Each time, the fix was the
same: move the value onto a configuration struct with a command-line flag
and a documented default, explicitly described as a starting point rather
than a value proven optimal. None of the three fixes changed default
behavior; all three changed what an operator could do when the default
turned out to be wrong for their traffic, without needing a rebuild.

Three occurrences of the identical mistake is a pattern worth naming on its
own: "should this be configurable" is a question worth asking by default
for any threshold, not just once it's caused a visible problem.

## Trusting a metric without checking what it measures

An offline benchmark reconstructed one system's decision as `rate > mean +
k * standard_deviations`, using only the columns a training CSV already
carried, to compare against a fixed threshold. Run against the captured data, it
rated the adaptive system worse than the fixed threshold at correctly
leaving a legitimate traffic surge alone, backwards from the system's
actual deployed behavior. The reconstruction wasn't wrong about what it
computed; it modeled only the first stage's raw per-window rate gate, which
is *supposed* to fire on a legitimate surge, since that genuinely is an
unusual rate. It wasn't modeling the second stage, the trained classifier
that actually distinguishes a surge from an attack using entropy,
dominance, and protocol mix alongside rate, which is the part the real
system leans on for exactly the distinction the benchmark existed to test.
The proxy was internally consistent and still measured the wrong thing.

Re-run using the real, trained classifier under genuine held-out
evaluation instead of a hand-derived stand-in, the same comparison flipped
entirely: 100% precision, 0% false-positive rate, and every real instance
of the legitimate surge correctly left alone, against the fixed threshold
flagging all of it. A benchmark script that runs cleanly and returns a
number is not the same claim as a benchmark that measures the thing it's
named after.

## Placeholder values that looked like real ones

Two separate sentinels, in two separate parts of the codebase, ended up
indistinguishable from genuine data once they left the code that produced
them. A fallback address used when nothing else could be resolved was a
real, in-range private IP, which could collide with an actual host on an
operator's network; a "no dominant source" placeholder for an empty
measurement window was `0.0.0.0`, syntactically a valid address, which
in one exported log turned out to be the single most common "source" in
the file, ahead of every genuine one, at nearly a fifth of all records.
Both were fixed the same way: the sentinel that reaches a human or a log
is now a value that cannot be confused with a real one, `"Unknown"`, not
an address indistinguishable from ordinary data until someone reads the
export closely enough to notice a suspicious concentration.

## Deployment convenience becoming a privilege boundary

Running the classification and enforcement service directly out of the
checked-out working copy, as root, is the shortest path from clone to
running system, and it was also a real privilege problem: the account
that ran `git clone` could still write to the code, the configuration, the
trained models, and the database that root then executed and trusted, all
in the same writable directory. The fix moved everything mutable, code,
virtual environment, models, configuration, and state, into two separate
root-owned locations outside the checkout, with the checkout's own
convenience commands (a plain development run, not the production install)
deliberately left untouched, since a developer running their own code
under their own account crosses no privilege boundary the deployed service
does.

A related regression came from a genuinely well-intentioned fix elsewhere:
a change meant to stop the classifier from treating a sensor's warm-up
telemetry as steady-state traffic accidentally gated a set of
deterministic, always-on safety enforcement rules on that same warm-up
check, leaving a freshly restarted or newly added target completely
unenforced, no blocking, no rate-limiting, no alerting, for its first
couple hundred windows. Caught by a structured security review before it
shipped. The fix extracted the safety logic into its own
function that takes no warm-up parameter at all, specifically so a future
change to warm-up handling has no path back into gating enforcement by
accident the way one `if` wrapping too much code did the first time.

## A test that covered one input format

The live benchmark's analysis read the two capture backends' periodic status
lines the same way. One backend logs running totals and the other resets its
counters after every line, so each line is that interval's own count. The
test built lines in one format only. The first run on the other backend
printed negative packet counts, which cannot happen and should have been
read as a sign the parsing was wrong. The fix sums the
per-interval samples and differences the cumulative ones, and it was checked
against an independent sum of the raw log. The rule: build test input for
every format a parser accepts, and treat an impossible value as a bug in the
reader until shown otherwise.

## Comparing runs after changing the instrument

Three benchmark reruns in one day each recalibrated the sensor's sigma floors
during their own first phase, restarted the sensor several times, and had the
network manager restarted on the gateway every two minutes. The escalation
figures moved from about 2% to about 36 to 73%, and the changes to the
instrument were enough to produce that on their own. The runs also wrote to
one results directory, so each overwrote the last one's phase markers before
they could be checked. The rules: fix the instrument before a session and
leave it alone until it ends, write each run to its own directory, and check
every reported figure against the raw files before it goes into a document.
Two figures in one hand-off report were wrong (a CPU maximum and a row count
that included the header) and were caught only by doing that.

## Data captured under a different configuration than the one deployed

A training set captured under one set of sigma floors was used to train an
Isolation Forest that then ran on a sensor with other floors. Two of its
inputs, the learned standard deviations, sat in a range it had never seen,
and it flagged every live window as an outlier. A benchmark write-up first
explained that as the lab's traffic differing from a captured session, which
was plausible and untested. Swapping just those two columns into the training set's
range changed the flag rate from 100% to 27% and 0%, which was the test that
should have come first. The rule: when a model misbehaves on live data, change
one input at a time before writing an explanation, and capture training data
under the tuning that will be deployed.

## A count written from arithmetic

A release note gave the Python test count as 312, worked out by adding the
tests written that day to the total the run had already reported. The run
had counted them already: the suite went from 303 to 308. The release notes
and two artifacts were corrected afterward, and the commit message that
carried the wrong number stayed, because rewriting pushed history costs more
than the error does. The rule: quote a test count from the run's own output,
and quote it after the last change to the tests.

## Two capture threads wrote one status line format

The live benchmark's analysis read the libpcap backend's `Capture: status` lines
as one running total. With an egress interface configured the sensor runs a
capture thread per interface, each logging its own cumulative counters under
the same message, so the lines interleave and the "total" jumped between two
unrelated series. The per phase packet counts looked plausible in the phases
with steady traffic and were wrong in the others. It surfaced in the first
backend comparison, where libpcap appeared to capture 14% of the interface's
traffic in the first phases and 100% later. Checking the raw log showed the
interface name in every line and the phases lining up with the wrong series.
A second trap sat next to it: libpcap logs the status only when a packet
arrives, so a quiet phase leaves a hole, and a total taken across the hole
credited the previous phase's traffic to the next one. Read every field a log
line carries before treating its lines as one series, and treat a boundary
sample that is much older than the log's normal cadence as missing.

## A silent generator that looked like a result

The `mp_flood` attack in the same session sent no traffic in either backend, and
the report still listed it with verdict counts of zero. The lab script has a
`#!/bin/sh` line and uses `mapfile`, which the machine's busybox shell lacks, so
it exits at once. This is the same fault the Flash Crowd generator had weeks
earlier. A phase whose interface counter reads near zero is a generator that did
not run, and reads differently from an attack the system failed to detect.

## A restart that fixes it is a symptom

For several sessions the gateway needed NetworkManager restarted every couple of
minutes before the dashboard showed traffic reaching the targets, and the working
theory was that the kernel backend's capture stalled. The interface counters told
a different story. The egress interface's own transmit counter was zero for
whole phases while incoming traffic never stopped, then jumped to normal during
NetworkManager's three 45 second activation attempts and fell to zero again
during the five minute backoff that followed. A profile set to DHCP on a
network with no DHCP server was failing every activation and taking the
interface's address and route down with it, and a restart only reset the retry
cycle. The capture backend was innocent, and the two runs differed only in when
someone restarted NetworkManager. A fix that has to be repeated is a symptom, so
find what the restart resets, and read the raw counters on both sides of the
component under suspicion before blaming it. Fixed by changing the profile to
`ipv4.method manual` with IPv6 off, which removed the retry cycle entirely: the
next session had no NetworkManager event on that interface.

## A pass that did not check its own inputs

Two benchmark sessions in a row reported a pass and were unusable. In the first,
a generator left running by an interrupted attempt sent 4,600 to 6,800 packets a
second through warm-up and calibration, so the sensor learned it as Normal and set a
rate floor of 209.3 against 2.5 for the same traffic on the other backend. The report
had warned that every target's sample was not peacetime traffic, and the summary said
pass. In the second, two copies of the script ran at once against one gateway and
fed traffic into each other's phases. Each failure showed in the raw interface
counters, and neither showed in the detection figures, which looked like a system
misbehaving. A run should prove its own preconditions (an idle interface, one driver,
a baseline learned from scratch) before it measures, and whoever reads the result
should read the calibration section first.

## The answer was where rows enter the queue

The auto-label job staged 21,867 rows and every one was DDoS, after runs that
included Normal and Flash Crowd phases. The two capture files that feed it only
receive windows the Random Forest called DDoS or the Isolation Forest flagged, so
ordinary traffic never reaches it in bulk, and 36,000 of the anomalous file's 50,000
rows were zero-traffic windows the job never labels. Reading where rows enter a
pipeline explained the result faster than reading the models. The Flash Crowd the
models misread had the same shape: a class that only shows up when it is
misclassified cannot be learned from the captures of the model that misclassifies it,
so its labels had to come from what the benchmark was sending.

## Waiting on a lock in the loop that must not wait

Stage 2 fell behind by tens of seconds while a background job scored a capture
file. The job held the file's lock through a whole read, score and rewrite pass,
one row at a time, and the receive loop blocked on that lock. The fix has two
halves: the job locks only to read and to swap in the result, and scores in one batch
per model (2 seconds against about 18 minutes), and the loop tries the lock without
waiting and queues rows in a bounded buffer. A loop that serves a live stream should
never block on something a slower job can hold.

## A log field stamped from the wrong window

`log_incident` read the most recent window across all protected hosts rather
than the one for the host actually being logged, so an action taken against
one host could be stamped with a different host's entropy measurement, and a
window with no measurement recorded as zero rather than null, indistinguishable
from a real zero reading. Fixed to record the value for the host itself, and
null when there isn't one. Existing rows were not rewritten, since the correct
value for them isn't recoverable: zero entropy on a row from before this fix
means unknown.

## A model that had never seen a legitimate crowd

Normal traffic shaped as one source far above the rest (a `hot` distribution)
drew DDoS verdicts on both capture backends and rate limits on more than 100
legitimate addresses. The RandomForest made the call correctly by its own
training: nothing in the training data was a concentrated but legitimate
crowd, so the shape read as an attack because none of its examples said
otherwise. `scripts/label_from_benchmark.py` labels captured windows straight
from the benchmark's own phase ground truth rather than a human guess, and
adding 176 such rows cut the `hot` variant from 65 verdicts and 620 rate
limits to 2 and 29 in the next clean run, confirmed again on a second
backend.

## Enforcement acted on a stale flow snapshot

During an attack-only phase, both capture backends rate limited the previous
phase's Flash Crowd sources along with that phase's own attack sources.
Enforcement read every flow in the sensor's 10 second snapshot, whatever host
it targeted and however old it was. It now keeps only flows to the window's
own host and ignores a snapshot older than 30 seconds.

## A generator paced too evenly to teach anything

`sigma_r`, the standard deviation Stage 1 learns for a target's rate, comes
from window to window variation in a smoothed rate. A load generator that
paces every request or packet on a fixed interval, rather than the
independent, uncoordinated timing real clients or a real botnet have,
produces almost no such variation, so `sigma_r` sat at its configured floor
for an entire capture no matter how much traffic was flowing, teaching a
model "this traffic is mechanically regular" instead of the class it was
meant to represent. Fixed on the generator side: randomised inter-request
wait time, an active source count that varies across a session, and short
randomised bursts in place of one continuous flood. Confirmed on a real
recapture: `sigma_r` varied across every label.

## A capture path that only fed two of three classes

`ipc_receiver.py` only ever consulted the Isolation Forest, and therefore
only ever wrote to the review queue, when the RandomForest had already
called a window Normal or Flash Crowd; a window it called DDoS never reached
that check, so DDoS could never grow through automatic labeling. It
compounded at training time too: `balance_classes()` upsamples every class
to match whichever is currently largest, so as Normal and Flash Crowd kept
growing from real auto-labeling runs, DDoS's fixed pool would have been
duplicated further each retrain just to keep pace, balanced in row count,
increasingly stale in diversity. Fixed with a third capture path,
`ddos_capture.csv`, that writes a window whenever the RandomForest
confidently calls it DDoS, re-scored by the same dual-model agreement,
confidence threshold, and freshness check as the other two, so DDoS gets the
same automated, gated path into training the other two classes already had.

## Comparing runs that weren't running the same thing

Three benchmark reruns recalibrated the sensor's floors during their own
first phase, restarted the sensor several times, and had NetworkManager
restarted every two minutes on the gateway underneath them. Escalation moved
from 0% to 2% to 36 to 73% across the reruns, and those changes to the thing
being measured are enough to explain all of it on their own, without needing
to doubt the detection logic itself. A benchmark run has to hold the sensor
still: set the floors, restart once, warm up, then run, and don't touch it
again until the run ends.
