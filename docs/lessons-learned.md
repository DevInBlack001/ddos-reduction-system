# Lessons Learned

A record of real bugs found during development, kept because most of them
generalize past this specific project. Grouped by shape, not by date. Every
entry here shipped a fix; nothing below is still open (see
[Roadmap](roadmap.md#known-gaps) for what still is).

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
then writes the new label. During that sleep, real attack traffic is
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
carried, to compare against a fixed threshold. Run against real data, it
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
shipped, not after. The fix extracted the safety logic into its own
function that takes no warm-up parameter at all, specifically so a future
change to warm-up handling has no path back into gating enforcement by
accident the way one `if` wrapping too much code did the first time.
