# V8: Confidence Gated Automatic Labeling

Design spec. Corresponds to the V8 roadmap entry in `docs/roadmap.md`.

## Goal

Two kinds of window today have no path to labeled training data without an
operator manually running `--train-csv` or hand-labeling a review queue:
windows the Isolation Forest flags `Anomalous` (already captured to
`anomalous_capture.csv`, but only a human fills in `label`), and windows
from before any RandomForest model has been trained on a deployment at all
(no capture path in production exists for these today). This milestone
automates labeling for the confidently-classifiable subset of both,
leaving anything ambiguous in the existing human-reviewed flow rather than
lowering the bar for what counts as labeled data.

Scope is deliberately limited to these two cases, not every window. A
window the RF already classifies confidently in real time mostly confirms
what the RF already believes; it does not teach it anything new. These two
cases are the ones with no other route to labeled data today.

## The Core Safeguard: an Independent Second Opinion

Re-running the *same* RF against a stored row and trusting a confident
answer is unsafe on its own: if the row is one the RF already has a blind
spot for, re-scoring it just reproduces that blind spot with new-found
confidence. This matters most for IF-flagged rows, since IF flagged one
specifically because it looked unlike anything in the RF's training data.
Auto-labeling the RF's self-confirmed opinion and folding it into training
would teach the RF to be more confident about missing that same shape of
attack, the opposite of this feature's purpose.

The fix is a second, independently trained classifier from a different
algorithm family, built alongside the RF and IF rather than derived from
either: a gradient boosted tree ensemble (`sklearn.ensemble.
HistGradientBoostingClassifier`, already in scikit-learn, no new
dependency), trained on the same `training_data.csv`. Boosting builds its
trees sequentially, correcting the previous round's errors, a structurally
different process from the RF's bagged, independently-grown trees, giving
a genuine second opinion rather than a rerun of the first. This mirrors
why IF is a second, different model alongside the RF, applied here to the
labeling decision instead of to live enforcement. Whether gradient
boosting is actually the best-suited second family for this feature set,
versus e.g. logistic regression, is an
empirical question, validated by the same LOSO methodology `train.py`
already uses for the RF, not assumed.

**A row is only eligible for automatic labeling when both models agree on
the class and both clear the confidence threshold independently.**
Two differently-built models making the same mistake on a genuinely novel
row is far less likely than one model rehashing its own opinion, which is
what makes agreement a real signal rather than a rubber stamp.

**Plus the freshness rule**: a row is only eligible if *each* model
scoring it was trained after the row was captured, checked as
`model_file_mtime > row_timestamp` for both. For a cold-start row this is
automatic, no models existed at capture time, so whichever exist now were
necessarily trained after. For an IF-flagged row, it means a stale,
unretrained model can never auto-label its own blind spot, even with a
second opinion agreeing, only models that have genuinely learned something
new since get to weigh in. One rule, applied to both models, covers both
capture sources without separate logic per source.

## Building the Second Model

Trained by extending `scripts/train.sh`'s existing interactive selector
(today: RF, IF, or both) with a third option, rather than adding a new,
separate training path. Reuses everything that script already got right
the first time: the absolute-path fix for a CSV entered relative to the
caller's shell, and requiring `sudo` to write into `/var/lib/flod` on a
production install rather than silently training into the checkout while
the running root service keeps loading something else. Deliberately not
trained automatically during `install.sh`: nothing else in this project
auto-trains a model against whatever `training_data.csv` happens to be
sitting in the checkout at install time, and starting now would be a
surprising, silent way to end up with a production model an operator never
chose to build. `train_second_model.py` (new file) mirrors
`train_isolation_forest.py`'s existing shape: same CSV loader, same
`FEATURE_COLS`, LOSO-swept hyperparameters the same way `train.py` sweeps
`max_depth`, saved to `config.SECOND_MODEL_PATH`.

## Capture

**Cold-start rows** (new): in `ipc_receiver.py`, when `clf is None`
(no RandomForest model deployed yet, the actual "before the first model is
trained" condition; the Isolation Forest is a secondary, optional model
and its absence alone does not mean this), write the window's 13 base
columns, `entropy, ewma_rate, mean_h, mean_r, sigma_h, sigma_r,
proto_ratio, dominant_ip_ratio, source_port_entropy, ttl_variance,
fingerprint_diversity, timestamp, label`, matching `training_data.csv`'s
own column order exactly, `label` blank, to a new
`config.PRETRAINING_CSV_PATH` (`pretraining_capture.csv`). Reuses the
existing `_write_anomalous_row`-style atomic append, factored into a
shared helper both capture points call rather than duplicated.

**IF-flagged rows** (existing): `anomalous_capture.csv` already captures
this, unchanged.

**Bound on both files**: an operator-configurable row cap
(`AUTO_LABEL_MAX_QUEUE_ROWS`, a starting-point default, not a proven
value, per this project's own tuning convention), oldest rows dropped once
exceeded, logged when it happens. Without a cap, a fresh deployment left
running with `clf is None` for a long stretch, or a long configured delay
under heavy traffic, grows an unbounded file, the same class of exposure
this project's own security checklist already asks every persistent
collection point to guard against.

## The Labeling Job

A standalone script, `scripts/auto_label.py`, run periodically via a
systemd timer, not a background thread inside the long-running `stage2.py`
service. This matches `scripts/calibrate.py`'s existing shape (something
that runs occasionally against accumulated state, not on every window) and
avoids adding another concurrent writer against the patterns that already
burned this project once (the retention-purge lock contention documented
elsewhere in this project's notes).

Each run:

1. Load the RF model (`config.MODEL_PATH`) and the second-opinion model
   (`config.SECOND_MODEL_PATH`), and both files' mtimes. If either is
   missing, exit; agreement cannot be checked with only one model.
2. For each row in `pretraining_capture.csv` and `anomalous_capture.csv`
   older than the configured delay (`AUTO_LABEL_DELAY_HOURS`, a single
   global value for this milestone, not per label class, the roadmap's
   open question on that resolved toward the simpler option until real
   evidence says otherwise) and with both models' mtimes newer than
   `row_timestamp`: recompute the three derived features
   (`delta_rate = ewma_rate - mean_r`, `delta_entropy = entropy - mean_h`,
   `dominant_rate = ewma_rate * dominant_ip_ratio`) from the stored base
   columns, then call `predict_proba()` on both models.
3. If both models' top class agrees and both top-class probabilities
   clear `AUTO_LABEL_CONFIDENCE_THRESHOLD` (a starting-point default, not
   a proven value), write the row, labeled with the agreed class, to a new
   staging file, `auto_labeled_capture.csv`, in `training_data.csv`'s own
   13-column order, and remove it from the source file.
4. Anything not eligible (too young, a missing model, disagreement, or
   either model below the confidence threshold) stays in its source file
   for the next run, or for a human, exactly as it does today.

`auto_labeled_capture.csv` is a staging file, not a write path into
`training_data.csv` itself. This preserves this project's existing
discipline that nothing enters the authoritative training set without a
deliberate, recorded merge (every past merge in this project's history is
individually documented, session by session), the automation removes the
per-row manual labeling effort, not the human review step before a merge
actually happens. An operator still looks at a batch of pre-labeled rows
and merges deliberately, the same motion as reviewing
`anomalous_capture.csv` today, just against far fewer, already-labeled
rows instead of every row needing a label assigned from scratch.

## Configuration

All new settings follow this project's existing convention, `AnalysisConfig`-style
where applicable, an environment-driven default in `config.py` otherwise,
documented as a starting point rather than a proven value:

| Setting | Default | Meaning |
|-|-|-|
| `AUTO_LABEL_DELAY_HOURS` | 24 | Minimum row age before it is eligible for auto-labeling |
| `AUTO_LABEL_CONFIDENCE_THRESHOLD` | 0.90 | Minimum top-class `predict_proba` to auto-label rather than leave for review |
| `AUTO_LABEL_MAX_QUEUE_ROWS` | 50000 | Cap per capture file before oldest rows are dropped |
| `SECOND_MODEL_PATH` | `<state dir>/ddos_gb_model.joblib` | The second-opinion model's location, alongside `MODEL_PATH` and `IF_MODEL_PATH` |

## Testing Plan

New `stage2/tests/test_auto_label.py`:

- The freshness safeguard: a row is never auto-labeled if either model's
  mtime is not newer than `row_timestamp`, regardless of confidence or
  agreement; it is labeled when both models are fresh, agree, and are
  confident.
- Agreement: models predicting different classes never auto-label the
  row, even if both individually clear the confidence threshold.
- The confidence threshold: agreement with one model below threshold
  never auto-labels; agreement with both above threshold does.
- Missing model: either model absent means nothing is eligible that run.
- The delay: a row younger than `AUTO_LABEL_DELAY_HOURS` is never
  eligible.
- The queue cap: oldest rows are dropped once a capture file exceeds
  `AUTO_LABEL_MAX_QUEUE_ROWS`.
- Cold-start capture: `_write_anomalous_row`'s shared helper writes to
  `pretraining_capture.csv` with the correct 13-column header when `clf is
  None`, and does not write when a model is present.

No Rust changes. Entirely Stage 2 and a new standalone script, consistent
with the roadmap's reasoning for ranking this the easiest of the five
milestones in the V8 to V12 restructure.

## Open Questions

- Whether `AUTO_LABEL_CONFIDENCE_THRESHOLD` should differ per class (a
  confident DDoS call may warrant a lower bar than a confident Normal
  call, given the asymmetric cost of each kind of mistake), left as one
  global value for this milestone pending real data on whether that
  asymmetry is large enough to matter.
- Whether `auto_labeled_capture.csv` needs its own retention cap the way
  the two source files do, or whether an operator merging it periodically
  keeps it naturally bounded in practice.
