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

## Training

```bash
cd stage2
python3 train.py
```

The script drops rows containing NaN or infinity, computes the three derived
features, and detects capture sessions.

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
