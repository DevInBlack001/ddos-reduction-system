# Training the Classifier

## Capturing Data

Start the sensor writing every post warm up window to a CSV:

```bash
sudo ddos_stage1 --interface <IFACE> --victim-ips <IP> --label 0 --train-csv <PATH>
```

In this mode every window is written, not only the flagged ones.

Traffic generation is deliberately not prescribed. Use whatever load testing
tools, scripted clients, or packet crafting tools you have. What matters is the
labelling procedure, not the tool.

### The Clean Rule

Never let transitioning traffic carry a label. Wait for traffic to reach its
target rate before applying the label, and set the label back to 0 before
stopping the traffic.

The label is switched at runtime by writing to the label file:

```bash
echo 1 | sudo tee /run/ddos_stage1/train_label
```

That directory is root owned rather than world writable, which is why the
switch needs `tee` instead of a plain shell redirect.

This rule is easy to violate in an automated capture script without
noticing, not just a manual one. A script that starts an attack
generator, sleeps through a ramp period, and only then sets the label
has real, already-flowing traffic landing in the CSV for that whole
sleep, still stamped with the previous phase's label. Six sessions in
one V7 capture were caught this way: short (a few hundred rows against
a real session's thousands), an elevated rate that did not match their
label, sitting exactly at a phase boundary. Confirmed by comparing each
one against the real, correctly-labelled session immediately next to it
in the same capture, not from rate or entropy thresholds alone, since a
distributed flood's entropy can look as high as a legitimate crowd's.
Relabelled to match what the traffic actually was rather than discarded.

### Capture Sequence

**Phase 0, peacetime.** Run normal traffic for about four minutes so warm up
completes, then capture about five minutes of steady normal traffic.

**Phase 1, flash crowd.** Start a legitimate surge from many distinct sources.
Wait for full rate, set the label to 1, capture for a few minutes, set it back
to 0, then stop the traffic and wait for the baseline to settle.

**Phase 2a, single source attack.** Start a single source flood at a rate
representative of what you want to defend against. Wait for it to stabilise,
set the label to 2, capture, set it back to 0, stop, wait.

**Phase 2b, distributed attack.** The same as 2a but from many concurrent
sources.

### More Than One Session Per Label

This part is easy to get wrong and it invalidates the evaluation.

A single process run, even one cycling through all four phases, produces only
**one** baseline draw per label, because the baseline lives in memory for the
life of the process rather than the life of the label.

Evaluating generalisation needs at least two independent sessions per label.
Kill and restart the sensor, so it warms up fresh, before capturing a second
normal or flash crowd session. Flipping the label on an already running process
is not a second session.

The CSV is opened in append mode, so every new session lands in the same file
and is picked up automatically. The training script detects session boundaries
from the data itself, using a timestamp gap or a label change, not from how the
file was written.

### An Archetype Worth Capturing

The four phases above do not produce a **hot source flash crowd**: a legitimate
surge where one participant, a monitoring bot or a NAT gateway or a proxy,
contributes a disproportionate share of otherwise normal traffic. That drives
the dominant source ratio up on a benign sample, which is exactly the confusion
the system needs to learn to resolve.

Keep that source's absolute rate modest, tens of packets per second rather than
hundreds, and shrink the overall crowd instead of pushing one source harder.
Pushing it too hard just reproduces a single source attack signature with a
legitimate label on it, which teaches the model the opposite of what you want.

### Generator Timing Regularity

A scripted load or flood tool paces requests far more evenly than real
clients or a real botnet do. `sigma_r`, the rate's standard deviation, is
computed from window to window variation in the smoothed rate; if every
source sends on a fixed schedule, or a flood tool runs unpaced (`hping3
--flood`, which sends as fast as the machine can rather than on any
schedule at all), that variation collapses to almost nothing and `sigma_r`
sits at its configured floor for the entire session no matter how much
traffic is flowing. Every row then carries the same value for a feature the
classifier expects to vary, which teaches "this traffic is mechanically
regular" instead of the class signature you actually want captured.

Before capturing Flash Crowd or DDoS sessions, check that whatever is
generating the traffic:

- Paces requests with a randomised wait time or interval, not a fixed one.
- Varies the active source or user count over the session rather than
  holding it flat for the whole capture.
- Runs a flood tool in short, randomised bursts rather than one continuous
  unpaced flood, so the aggregate rate has real amplitude across windows.

A quick way to check before committing a whole session: after a short test
capture, group the CSV by label and look at `sigma_r`'s spread. If it is a
single repeated value for a label, the generator is too regular and the
session is not worth keeping as is.

Confirmed fixed on a real recapture: jittered burst timing (randomised
gaps and packet counts, no unpaced flood mode, no full-silence stretch)
produced real `sigma_r` variation across every label rather than a value
pinned at the configured floor.

## Training

```bash
scripts/train.sh
```

Prompts for the training CSV and which model, or models, to train, then
dispatches to `train.py` for the RandomForest, `train_isolation_forest.py`
for the Isolation Forest, or both. Both models are always trained on the
same cleaned CSV, so they see the same shape of data. Either script can
still be run directly, `cd stage2 && python3 train.py`, when only one model
needs retraining.

**Where the trained model actually lands depends on what it finds.** A
production install (`scripts/install.sh`) runs Stage 2 from a root owned
`/opt/flod/stage2`, loading its models from `/var/lib/flod`, not the
checkout; see [Security](security.md). `scripts/train.sh` detects that
install and writes there instead, which needs `sudo` since that directory
is root only, exactly like updating what a root process will load
should. Run it plainly, without a detected production install, and it
trains into the checkout as before, no `sudo` needed, matching a
development setup. Running `train.py`/`train_isolation_forest.py`
directly follows the same rule: both honour `MODEL_PATH`/`IF_MODEL_PATH`
environment variables, which `scripts/train.sh` sets when it detects a
production install.

The RandomForest script drops rows containing NaN or infinity, computes the
three derived features, and detects capture sessions.

It prints a per class feature range overlap check so you can see whether your
captured classes genuinely overlap in rate, entropy, and concentration space.
Classes that do not overlap are trivially separable, and a model trained on
them will score well while learning nothing useful.

### Two Separate Outputs

**Leave one session out evaluation.** For every session whose label has at
least two sessions, that session is held out entirely, a temporary model is
trained on all the others, and predictions on the held out session are
collected. Results from every fold combine into one report and confusion
matrix.

Sessions whose label has only one session are skipped with a note. Holding out
a class's only session leaves zero training examples of it, which is a coverage
gap rather than a fair test.

This exists because a random or percentage split leaks. Consecutive windows
share baseline state, so a model can memorise a session's fingerprint instead
of generalising, and will report a hollow perfect score.

**The production model.** Trained separately on all available sessions,
balanced by upsampling, and saved as the file Stage 2 loads. The evaluation
above never produces the shipped model.

### Reading the Result

Read the confusion matrix, not the headline accuracy. The numbers that matter
for this project's central claim are attack recall and precision, and the cell
counting true flash crowds predicted as attacks. That cell is the one that
represents blocking real users.

## The Isolation Forest

**File:** `stage2/train_isolation_forest.py`

A second, independent model, trained on the same cleaned CSV `train.py`
uses. Unlike the RandomForest, it is unsupervised: it fits on the full
pooled dataset, all three labels together, and never reads the label
column. The question it answers is not what class a window looks like, but
whether it looks like anything in the training set at all, which is what
lets it flag an attack shaped differently from anything captured, one the
RandomForest has no guaranteed reason to recognise regardless of what
features it is given. Trained on the full dataset rather than only the
`Normal` rows, on purpose: a model fit only on normal traffic would answer
"is this normal looking," a narrower question than "is this like anything
either model has learned."

**No manual `contamination` value.** `IsolationForest`'s `contamination`
parameter sets what fraction of the training set it treats as outliers,
and it is swept automatically the same way `train.py` sweeps `max_depth`:
across a fixed candidate list, refitting for each one and keeping whichever
value scores best. It does not have a genuine peak the way `max_depth`'s
LOSO accuracy does, though. The raw score, the DDoS outlier rate minus the
benign outlier rate, climbs the entire way through the candidate range
instead of turning over inside it, because a larger `contamination` simply
flags more of everything and DDoS rows carry a heavier tailed anomaly score
than benign ones. Picking the candidate with the largest raw score would
always land on the edge of whatever range is given, `contamination=0.25` on
a real 34,727 row capture, which flags 6.3% of ordinary traffic, roughly one
window in sixteen, as `Anomalous`. That defeats the point of a state meant
to be a rare signal, and it is the same failure shape this project already
fixed once for the entropy floor: a criterion that looks like an optimum
but is really just the boundary of the search range.

The fix caps the benign outlier rate (`BENIGN_OUTLIER_RATE_CAP`, default
0.05, a starting point rather than a proven value, the same convention as
every other tuning default in this project) and selects the
highest-separating candidate that stays under it, falling back to the
least noisy candidate if every one exceeds the cap. On the same 34,727 row
capture this selects `contamination=0.1`: a 28.8% DDoS outlier rate against
a 4.7% benign one.

### Reading the Result

The script prints an outlier rate by label after fitting, explicitly marked
as a sanity check rather than a validation metric: there is no held out
set and no ground truth for "was this an evasive attack," since the label
column was never used for fitting. A DDoS outlier rate meaningfully above
the benign rate is the useful signal; both near zero means `contamination`
is too small to be useful, and both near 100% means it is too large to be
selective. A DDoS outlier rate near 100% on its own is not the goal either:
that would mean the Isolation Forest has re-derived the RandomForest's job
on training data it already saw, not that it will catch an attack shaped
differently from anything in this capture, which is the only case Part B
exists for and the one this in-sample check cannot exercise.

## Both Models in Production

Both `.joblib` files load at startup and run every window, independently,
not in sequence or as a fallback chain. See
[enforcement.md](enforcement.md#classification) for how the two verdicts
combine into the `Anomalous` state.

## Reviewing Anomalous Traffic

**File:** `stage2/config.py`, `stage2/ipc_receiver.py`

An `Anomalous` verdict is not itself a label. It means the Isolation Forest
found a window unlike anything in the training set, not what the window
actually is: a new attack shape, a legitimate pattern the Normal or Flash
Crowd sessions never captured, or something else entirely. Deciding which
of those it was needs a person to look at it, the same way any other
labelling decision in this document does. Feeding a flagged window straight
back into `train.py` without that step would train the RandomForest on an
unverified guess, and worse, gives anyone who can shape traffic that gets
flagged a way to influence what the model later learns is acceptable.

Every window the Isolation Forest flags is appended to
`stage2/anomalous_capture.csv`, created on the first flagged window. Its
first thirteen columns are in the exact order `training.csv` uses:

```
entropy,ewma_rate,mean_h,mean_r,sigma_h,sigma_r,proto_ratio,dominant_ip_ratio,
source_port_entropy,ttl_variance,fingerprint_diversity,timestamp,label
```

`label` is always written blank. Nothing fills it in automatically. Three
further columns carry context for the review itself, not for training:
`victim_ip`, the protected host; `if_score`, the Isolation Forest's own
anomaly score for that window, more negative is more unlike training; and
`rf_verdict`, what the RandomForest called it before the Isolation Forest
overrode the display label.

To use it: look at what each flagged window actually was, whatever logs,
traffic captures, or dashboard history are available for that time and
victim. Fill in `0`, `1`, or `2` for any row whose real class you can
determine. Drop `victim_ip`, `if_score`, and `rf_verdict`, and the row is
now a normal training row, appendable to `training.csv` the same way a new
capture session is, following [More Than One Session Per
Label](#more-than-one-session-per-label) above: a handful of individually
reviewed rows is not a session, and does not substitute for one, but it is
real ground truth about a gap the current training data has, which is
exactly what should shape what to capture on purpose next.
