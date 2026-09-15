# V8 Confidence Gated Automatic Labeling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automate labeling for the two kinds of captured window that have no path to labeled training data today (Isolation-Forest-flagged windows and windows from before any RandomForest model exists), gated by agreement between two independently trained models plus a freshness check, so nothing feeds training data on a model's own unverified opinion of itself.

**Architecture:** A new capture point in `ipc_receiver.py` writes cold-start windows to a new CSV, mirroring the existing `anomalous_capture.csv` capture. A new standalone script, `stage2/auto_label.py`, run periodically by a systemd timer, re-scores rows in both capture files against the RandomForest and a newly introduced second model (a `HistGradientBoostingClassifier`, trained via an extended `scripts/train.sh`), auto-labeling into a staging CSV only when both models agree, are both confident, and were both trained after the row was captured.

**Tech Stack:** Python 3, scikit-learn (`HistGradientBoostingClassifier`, already a dependency via `sklearn.ensemble`), pandas, joblib, `unittest` (this project's existing test style), bash (systemd unit generation in `install.sh`/`update.sh`).

**Spec:** `docs/specs/2026-09-13-confidence-gated-labeling-design.md`

## Global Constraints

- No em dash, double hyphen, or triple hyphen anywhere: code, comments, commit messages. Use a comma, period, or parentheses instead.
- Comments are short and factual; explain why only when the why is not obvious.
- Test names are sentences describing behaviour, matching every existing file in `stage2/tests/`.
- Test addresses, when any are needed, come from `192.0.2.x` (protected hosts), `198.51.100.x` (traffic sources), `203.0.113.x` (dashboard clients), `2001:db8::/32` (IPv6). None needed in this plan's tests, no test here touches an IP address.
- Tuning values are configurable (env-var-driven constants in `config.py` or module-level constants mirroring `train_isolation_forest.py`'s own pattern), never hardcoded, documented as starting points, not proven values.
- Every commit message ends without a trailer of any kind (no `Co-Authored-By`, no `Claude-Session`), per this project's standing preference.
- Run `cd stage2 && python3 -m pytest tests/ -x -q` (from a venv with the project's dependencies, see `stage2/requirements.txt`) after each Python test-bearing task. If pytest is unavailable in this environment, note that explicitly rather than claiming a run that did not happen.

---

## Task 1: Config constants for the new capture files and the second model

**Files:**
- Modify: `stage2/config.py:85` (right after the existing `ANOMALOUS_CSV_PATH` line)
- Test: `stage2/tests/test_config.py`

**Interfaces:**
- Produces: `config.PRETRAINING_CSV_PATH`, `config.AUTO_LABELED_CSV_PATH`, `config.SECOND_MODEL_PATH`, `config.AUTO_LABEL_DELAY_HOURS` (float), `config.AUTO_LABEL_CONFIDENCE_THRESHOLD` (float), `config.AUTO_LABEL_MAX_QUEUE_ROWS` (int). All read from environment variables of the same name, with the defaults given below, exactly like the existing `ANOMALOUS_CSV_PATH`/`MODEL_PATH` lines immediately above them.

- [ ] **Step 1: Write the failing test**

Add to `stage2/tests/test_config.py` (new test class at the end of the file):

```python
class NewCaptureAndSecondModelPathTests(unittest.TestCase):
    def test_pretraining_csv_path_defaults_beside_the_anomalous_capture_file(self):
        self.assertEqual(
            os.path.dirname(config.PRETRAINING_CSV_PATH),
            os.path.dirname(config.ANOMALOUS_CSV_PATH),
        )
        self.assertEqual(os.path.basename(config.PRETRAINING_CSV_PATH), "pretraining_capture.csv")

    def test_auto_labeled_csv_path_defaults_beside_the_anomalous_capture_file(self):
        self.assertEqual(
            os.path.dirname(config.AUTO_LABELED_CSV_PATH),
            os.path.dirname(config.ANOMALOUS_CSV_PATH),
        )
        self.assertEqual(os.path.basename(config.AUTO_LABELED_CSV_PATH), "auto_labeled_capture.csv")

    def test_second_model_path_defaults_beside_the_random_forest_model(self):
        self.assertEqual(os.path.dirname(config.SECOND_MODEL_PATH), os.path.dirname(config.MODEL_PATH))
        self.assertEqual(os.path.basename(config.SECOND_MODEL_PATH), "ddos_gb_model.joblib")

    def test_auto_label_tuning_defaults(self):
        self.assertEqual(config.AUTO_LABEL_DELAY_HOURS, 24.0)
        self.assertEqual(config.AUTO_LABEL_CONFIDENCE_THRESHOLD, 0.90)
        self.assertEqual(config.AUTO_LABEL_MAX_QUEUE_ROWS, 50000)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd stage2 && python3 -m pytest tests/test_config.py -k NewCaptureAndSecondModelPathTests -v`
Expected: FAIL with `AttributeError: module 'config' has no attribute 'PRETRAINING_CSV_PATH'` (or similar, for whichever attribute pytest reaches first).

- [ ] **Step 3: Add the constants**

In `stage2/config.py`, right after the existing `ANOMALOUS_CSV_PATH` line (`stage2/config.py:85`), add:

```python
# V8: windows captured before any RandomForest model exists, no capture
# path in production has ever existed for these before. label is blank
# the same way anomalous_capture.csv's is, filled in by auto_label.py
# once a model exists to score it. See docs/specs/2026-09-13-confidence-
# gated-labeling-design.md.
PRETRAINING_CSV_PATH = os.environ.get("PRETRAINING_CSV_PATH", os.path.join(_STATE_DIR, "pretraining_capture.csv"))
# Rows auto_label.py has confidently labeled, staged here rather than
# written into training_data.csv directly: nothing enters the
# authoritative training set without a deliberate, recorded merge, the
# same discipline every past merge in this project's history already
# follows, this only removes the per-row manual labeling effort.
AUTO_LABELED_CSV_PATH = os.environ.get("AUTO_LABELED_CSV_PATH", os.path.join(_STATE_DIR, "auto_labeled_capture.csv"))
# V8: a second, independently trained classifier auto_label.py checks
# agreement against before trusting a label. Never loaded by
# ipc_receiver.py; only auto_label.py and train_second_model.py touch it.
SECOND_MODEL_PATH = os.environ.get("SECOND_MODEL_PATH", os.path.join(_STATE_DIR, "ddos_gb_model.joblib"))
# Starting points, not proven values, same convention as every other
# tuning default in this project.
AUTO_LABEL_DELAY_HOURS = float(os.environ.get("AUTO_LABEL_DELAY_HOURS", "24"))
AUTO_LABEL_CONFIDENCE_THRESHOLD = float(os.environ.get("AUTO_LABEL_CONFIDENCE_THRESHOLD", "0.90"))
AUTO_LABEL_MAX_QUEUE_ROWS = int(os.environ.get("AUTO_LABEL_MAX_QUEUE_ROWS", "50000"))
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd stage2 && python3 -m pytest tests/test_config.py -k NewCaptureAndSecondModelPathTests -v`
Expected: PASS, 4 passed.

- [ ] **Step 5: Run the full config test file to check for regressions**

Run: `cd stage2 && python3 -m pytest tests/test_config.py -v`
Expected: PASS, every prior test still passing.

- [ ] **Step 6: Commit**

```bash
git add stage2/config.py stage2/tests/test_config.py
git commit -m "feat: add config paths for V8's cold-start capture, staging, and second model"
```

---

## Task 2: Share the CSV-append helper and add the cold-start row writer

**Files:**
- Modify: `stage2/ipc_receiver.py:78-108` (the `ANOMALOUS_CSV_HEADER` constant and `_write_anomalous_row`)
- Test: `stage2/tests/test_ipc_receiver.py`

**Interfaces:**
- Consumes: `config.PRETRAINING_CSV_PATH` (Task 1).
- Produces: `ipc_receiver.PRETRAINING_CSV_HEADER` (list of 13 column names), `ipc_receiver._write_pretraining_row(**feature_values)` (same keyword shape as the existing `_write_anomalous_row`, minus `victim_ip`/`if_score`/`rf_verdict`). `_write_anomalous_row`'s existing signature and behaviour are unchanged; only its internals are refactored to share `_append_csv_row`/`_base_feature_row`.

- [ ] **Step 1: Write the failing test**

Add to `stage2/tests/test_ipc_receiver.py`, a new test class after `WriteAnomalousRowTests`:

```python
class WritePretrainingRowTests(unittest.TestCase):
    def setUp(self):
        self.path = temp_path(".csv")
        os.unlink(self.path)  # start from "file does not exist"
        self.original_path = config.PRETRAINING_CSV_PATH
        config.PRETRAINING_CSV_PATH = self.path

    def tearDown(self):
        config.PRETRAINING_CSV_PATH = self.original_path
        unlink(self.path)

    def _rows(self):
        with open(self.path) as handle:
            return list(csv.reader(handle))

    def test_creates_the_file_on_the_first_cold_start_window(self):
        ipc_receiver._write_pretraining_row(**FEATURES)
        self.assertTrue(os.path.exists(self.path))

    def test_the_thirteen_columns_match_trainingcsvs_own_order(self):
        ipc_receiver._write_pretraining_row(**FEATURES)
        header = self._rows()[0]
        self.assertEqual(header, [
            "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
            "proto_ratio", "dominant_ip_ratio", "source_port_entropy",
            "ttl_variance", "fingerprint_diversity", "timestamp", "label",
        ])

    def test_the_label_column_is_left_blank(self):
        ipc_receiver._write_pretraining_row(**FEATURES)
        row = self._rows()[1]
        self.assertEqual(row[12], "")

    def test_a_second_cold_start_window_appends_rather_than_overwriting(self):
        ipc_receiver._write_pretraining_row(**FEATURES)
        ipc_receiver._write_pretraining_row(**FEATURES)
        rows = self._rows()
        self.assertEqual(len(rows), 3)  # header + two data rows


class SharedCsvAppendHelperTests(unittest.TestCase):
    """The refactor must not change _write_anomalous_row's own behaviour;
    WriteAnomalousRowTests above already pins its output format, this
    class only pins that the two writers now share one low-level append
    so a future third capture point does not need a third copy of it."""

    def test_write_anomalous_row_and_write_pretraining_row_share_the_append_helper(self):
        self.assertIs(ipc_receiver._write_anomalous_row.__globals__["_append_csv_row"],
                       ipc_receiver._write_pretraining_row.__globals__["_append_csv_row"])
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd stage2 && python3 -m pytest tests/test_ipc_receiver.py -k "WritePretrainingRowTests or SharedCsvAppendHelperTests" -v`
Expected: FAIL, `AttributeError: module 'ipc_receiver' has no attribute '_write_pretraining_row'`.

- [ ] **Step 3: Refactor `_write_anomalous_row` and add `_write_pretraining_row`**

Replace `stage2/ipc_receiver.py:78-108` (from `ANOMALOUS_CSV_HEADER = [` through the end of `_write_anomalous_row`) with:

```python
ANOMALOUS_CSV_HEADER = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "source_port_entropy", "ttl_variance",
    "fingerprint_diversity", "timestamp", "label", "victim_ip", "if_score", "rf_verdict",
]

# V8: windows captured before any RandomForest model exists. Same 13 base
# columns as ANOMALOUS_CSV_HEADER, no context columns, since no model ran
# at capture time to produce a score or a verdict. See docs/specs/2026-09-
# 13-confidence-gated-labeling-design.md.
PRETRAINING_CSV_HEADER = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "source_port_entropy", "ttl_variance",
    "fingerprint_diversity", "timestamp", "label",
]


def _append_csv_row(path, header, row):
    """Append one row to a capture CSV, writing the header first if the
    file does not exist yet. Shared by every capture point in this module
    so the append-and-header behaviour lives in one place."""
    write_header = not os.path.exists(path)
    try:
        with open(path, "a", newline="") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(header)
            w.writerow(row)
    except OSError as e:
        logging.error(f"[-] Failed to write {path}: {e}")


def _base_feature_row(feature_values):
    """The 13 base columns shared by every capture format, training_data.csv's
    own column order. label is always blank: nothing at capture time
    knows what this traffic actually is."""
    return [
        f"{feature_values['entropy']:.6f}", f"{feature_values['ewma_rate']:.6f}",
        f"{feature_values['mean_h']:.6f}", f"{feature_values['mean_r']:.6f}",
        f"{feature_values['sigma_h']:.6f}", f"{feature_values['sigma_r']:.6f}",
        f"{feature_values['proto_ratio']:.6f}", f"{feature_values['dominant_ip_ratio']:.6f}",
        f"{feature_values['source_port_entropy']:.6f}", f"{feature_values['ttl_variance']:.6f}",
        f"{feature_values['fingerprint_diversity']:.6f}", f"{feature_values['timestamp']:.3f}",
        "",
    ]


def _write_anomalous_row(victim_ip, if_score, rf_verdict, **feature_values):
    """Append one Anomalous window to config.ANOMALOUS_CSV_PATH for later
    review. label is left blank: nothing here knows what this traffic
    actually is, only that it looked unlike anything in training. The
    first 13 columns match training.csv's own order exactly, so a row
    can be copied straight across once a human fills in the label and
    drops the victim_ip/if_score/rf_verdict columns on the end."""
    row = _base_feature_row(feature_values) + [victim_ip, f"{if_score:+.4f}", rf_verdict]
    _append_csv_row(config.ANOMALOUS_CSV_PATH, ANOMALOUS_CSV_HEADER, row)


def _write_pretraining_row(**feature_values):
    """Append one cold-start window (no RandomForest model deployed yet)
    to config.PRETRAINING_CSV_PATH for auto_label.py to score once a model
    exists. label is left blank, same reasoning as _write_anomalous_row."""
    _append_csv_row(config.PRETRAINING_CSV_PATH, PRETRAINING_CSV_HEADER, _base_feature_row(feature_values))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd stage2 && python3 -m pytest tests/test_ipc_receiver.py -v`
Expected: PASS, every test in the file, including the pre-existing `WriteAnomalousRowTests` (confirms the refactor did not change its behaviour) and the two new classes.

- [ ] **Step 5: Commit**

```bash
git add stage2/ipc_receiver.py stage2/tests/test_ipc_receiver.py
git commit -m "refactor: share the capture CSV append helper, add the cold-start row writer"
```

---

## Task 3: Capture cold-start windows in the receive loop

**Files:**
- Modify: `stage2/ipc_receiver.py:341-347` (right after the existing RandomForest prediction block)
- Test: `stage2/tests/test_ipc_receiver.py`

**Interfaces:**
- Consumes: `ipc_receiver._write_pretraining_row` (Task 2).
- Produces: nothing new consumed by a later task; this is the last piece that wires capture into the live path.

This task adds the call inside the per-window loop, which is not independently unit-testable as a whole (it is inline code inside `run_ipc_receiver`, a long-running socket loop). Per this project's existing pattern (`ApplySafetyOverridesTests` tests the pure function that inline code calls, not the loop itself), the test here pins the one new piece of decision logic being added: that this call only fires when `clf is None` and the window is not a warm-up window. Since that condition is a plain boolean expression inline in the loop rather than its own function, this task extracts it into a small named function first, so it has something to test without needing a real socket.

- [ ] **Step 1: Write the failing test**

Add to `stage2/tests/test_ipc_receiver.py`:

```python
class ShouldCapturePretrainingRowTests(unittest.TestCase):
    def test_true_when_no_random_forest_model_is_loaded_and_not_warming_up(self):
        self.assertTrue(ipc_receiver._should_capture_pretraining_row(clf=None, is_warmup=False))

    def test_false_during_warmup_even_with_no_model(self):
        self.assertFalse(ipc_receiver._should_capture_pretraining_row(clf=None, is_warmup=True))

    def test_false_once_a_random_forest_model_is_loaded(self):
        self.assertFalse(ipc_receiver._should_capture_pretraining_row(clf=object(), is_warmup=False))
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd stage2 && python3 -m pytest tests/test_ipc_receiver.py -k ShouldCapturePretrainingRowTests -v`
Expected: FAIL, `AttributeError: module 'ipc_receiver' has no attribute '_should_capture_pretraining_row'`.

- [ ] **Step 3: Add the predicate and wire the capture call**

In `stage2/ipc_receiver.py`, add this function right after `_write_pretraining_row` (from Task 2):

```python
def _should_capture_pretraining_row(clf, is_warmup):
    """Cold-start capture fires only before any RandomForest model exists
    (the actual "before the first model is trained" case) and never during
    warm-up, since a warm-up window's mean/sigma-derived features are not
    meaningful even to a model trained later. The Isolation Forest is a
    secondary, optional model; its absence alone does not mean this."""
    return clf is None and not is_warmup
```

Then, in the main receive loop at `stage2/ipc_receiver.py:341-347`, immediately after the existing block:

```python
                if not is_warmup and clf:
                    pred_class = int(clf.predict(features_df)[0])
```

add:

```python
                if _should_capture_pretraining_row(clf, is_warmup):
                    _write_pretraining_row(
                        entropy=entropy, ewma_rate=ewma_rate, mean_h=mean_h, mean_r=mean_r,
                        sigma_h=sigma_h, sigma_r=sigma_r, proto_ratio=proto_ratio,
                        dominant_ip_ratio=dominant_ip_ratio, source_port_entropy=source_port_entropy,
                        ttl_variance=ttl_variance, fingerprint_diversity=fingerprint_diversity,
                        timestamp=timestamp,
                    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd stage2 && python3 -m pytest tests/test_ipc_receiver.py -v`
Expected: PASS, every test in the file.

- [ ] **Step 5: Commit**

```bash
git add stage2/ipc_receiver.py stage2/tests/test_ipc_receiver.py
git commit -m "feat: capture cold-start windows for later confidence-gated labeling"
```

---

## Task 4: The second model's training script

**Files:**
- Create: `stage2/train_second_model.py`

**Interfaces:**
- Produces: a `.joblib` file at `config.SECOND_MODEL_PATH`'s default location (or an explicit path given as the second CLI argument), loadable by `joblib.load()` and exposing `.predict_proba()`. Consumed by Task 6 (`auto_label.py`) and by an operator via `scripts/train.sh` (Task 5).

No unit test file: this project's own convention leaves `train.py` and `train_isolation_forest.py` without `pytest` coverage, verified instead by a real run against data, which this task's Step 2 does with a small synthetic CSV.

- [ ] **Step 1: Write the script**

Create `stage2/train_second_model.py`:

```python
#!/usr/bin/env python3
"""
train_second_model.py: Stage 2, V8's independent second opinion.

Separate from train.py and train_isolation_forest.py on purpose, same
reasoning as train_isolation_forest.py's own docstring: each training
script stays a self-contained thing an operator runs, not a module meant
to be imported. This one fits a HistGradientBoostingClassifier on the
same cleaned feature set train.py uses, all three labels, supervised,
the same as the RandomForest.

Why a second model at all: auto_label.py (see docs/specs/2026-09-13-
confidence-gated-labeling-design.md) only auto-labels a captured row when
this model and the RandomForest agree. Re-scoring a row with the same RF
that already has a blind spot for it just reproduces that blind spot with
new-found confidence; a second, differently built model (boosting builds
its trees sequentially correcting errors, a structurally different
process from the RF's bagged, independently grown trees) gives a genuine
second opinion instead.
"""

import os
import sys
import warnings
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils import resample

# See train.py's matching comment: cosmetic sklearn/joblib warning about
# config propagation that does not apply here.
warnings.filterwarnings(
    "ignore",
    message=r".*should be used with `sklearn\.utils\.parallel\.Parallel`.*",
    category=UserWarning,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "stage1", "training_data.csv")
# Same SECOND_MODEL_PATH environment variable config.py honours, so
# training against a production install can target the root-owned model
# directory Stage 2's auto_label.py actually reads from.
SECOND_MODEL_PATH = os.environ.get("SECOND_MODEL_PATH", os.path.join(SCRIPT_DIR, "ddos_gb_model.joblib"))

FEATURE_COLS = [
    "entropy",
    "ewma_rate",
    "mean_h",
    "mean_r",
    "sigma_h",
    "sigma_r",
    "proto_ratio",
    "dominant_ip_ratio",
    "delta_rate",
    "delta_entropy",
    "dominant_rate",
    "source_port_entropy",
    "ttl_variance",
    "fingerprint_diversity"
]
LABEL_COL = "label"


def balance_classes(X, y):
    """Upsample every class to the size of the largest class. Training-split
    only, never call this on evaluation data. Duplicated from train.py
    rather than imported, same reasoning as train_isolation_forest.py's
    own FEATURE_COLS duplication: these are independently run scripts, not
    modules meant to import each other."""
    train_df = X.copy()
    train_df[LABEL_COL] = y.values
    per_class = [train_df[train_df[LABEL_COL] == lbl] for lbl in (0, 1, 2)]
    per_class = [d for d in per_class if len(d) > 0]
    if len(per_class) < 2:
        return X, y
    max_size = max(len(d) for d in per_class)
    upsampled = [resample(d, replace=True, n_samples=max_size, random_state=42) for d in per_class]
    balanced = pd.concat(upsampled, ignore_index=True)
    return balanced[FEATURE_COLS], balanced[LABEL_COL]


# max_leaf_nodes is HistGradientBoostingClassifier's rough equivalent of
# max_depth: it bounds how much a single tree in the ensemble can carve up
# the training set. Swept the same way train.py sweeps max_depth, for the
# same reason: the right value depends on how many independent sessions
# THIS dataset has per class, not a value tuned once on a different
# capture set. sklearn's own default is 31.
CANDIDATE_MAX_LEAF_NODES = [3, 7, 15, 31, 63, 127, None]


def main():
    print("=== FLOD System: Stage 2 Second Model Training (V8) ===")

    if len(sys.argv) > 1:
        csv_file = sys.argv[1]
        if not os.path.exists(csv_file):
            print(f"[-] Error: '{csv_file}' not found.")
            sys.exit(1)
    else:
        csv_file = CSV_PATH
        if not os.path.exists(csv_file):
            csv_file = "training_data.csv"
            if not os.path.exists(csv_file):
                print(f"[-] Error: Training data not found at '{CSV_PATH}' or './training_data.csv'")
                print("    Please copy the collected CSV file to this directory and run again.")
                sys.exit(1)
    model_out = sys.argv[2] if len(sys.argv) > 2 else SECOND_MODEL_PATH

    print(f"[+] Loading dataset from: {csv_file}")
    df = pd.read_csv(csv_file)
    print(f"[+] Loaded {len(df)} raw rows.")

    derived_cols = {"delta_rate", "delta_entropy", "dominant_rate"}
    required_raw_cols = [c for c in FEATURE_COLS if c not in derived_cols] + [LABEL_COL, "timestamp"]
    missing_cols = [c for c in required_raw_cols if c not in df.columns]
    if missing_cols:
        print(f"[-] Error: '{csv_file}' is missing column(s): {', '.join(missing_cols)}")
        print("    This looks like a pre-V7 capture. Recapture with the current sensor")
        print("    before training, or point this script at a CSV that already has them.")
        sys.exit(1)

    df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)

    dup_count = df.duplicated().sum()
    if dup_count > 0:
        print(f"[!] Dropping {dup_count} exact-duplicate rows found in the dataset.")
        df = df.drop_duplicates().reset_index(drop=True)

    df = df.sort_values(by="timestamp").reset_index(drop=True)
    df["time_diff"] = df["timestamp"].diff()
    df["label_changed"] = df[LABEL_COL] != df[LABEL_COL].shift()
    df["new_session"] = (df["time_diff"] > 30.0) | (df["time_diff"].isna()) | df["label_changed"]
    df["session_id"] = df["new_session"].cumsum()

    df = df[~((df[LABEL_COL] == 1) & (df["ewma_rate"] < 100))].reset_index(drop=True)

    dropped_idle_ddos = ((df[LABEL_COL] == 2) & (df["ewma_rate"] < 1.0)).sum()
    if dropped_idle_ddos > 0:
        print(f"[!] Dropping {dropped_idle_ddos} idle rows mislabeled as DDoS (rate < 1 pps).")
    df = df[~((df[LABEL_COL] == 2) & (df["ewma_rate"] < 1.0))].reset_index(drop=True)

    df["delta_rate"] = df["ewma_rate"] - df["mean_r"]
    df["delta_entropy"] = df["entropy"] - df["mean_h"]
    df["dominant_rate"] = df["ewma_rate"] * df["dominant_ip_ratio"]

    print("\n== Raw Class Distribution ==")
    print(df[LABEL_COL].value_counts().to_string())

    print("\n[+] Running Leave-One-Session-Out (LOSO) evaluation across candidate max_leaf_nodes...")
    sessions_per_label = df.groupby(LABEL_COL)["session_id"].nunique()
    all_sessions = sorted(df["session_id"].unique())

    eligible_sessions = []
    for sess_id in all_sessions:
        label = df[df["session_id"] == sess_id][LABEL_COL].iloc[0]
        if sessions_per_label.get(label, 0) < 2:
            print(f"[!] Session {sess_id} (label {label}): SKIPPED, only session for this "
                  f"label, holding it out would leave zero training examples of it.")
        else:
            eligible_sessions.append(sess_id)

    best_max_leaf_nodes = 31  # undocumented-data fallback if LOSO can't run at all below
    best_acc = -1.0
    best_fold_true, best_fold_pred = [], []

    if not eligible_sessions:
        print("[-] No label currently has >=2 sessions, LOSO cannot run yet. "
              f"Falling back to an UNVALIDATED default max_leaf_nodes={best_max_leaf_nodes}.")
    else:
        for max_leaf_nodes in CANDIDATE_MAX_LEAF_NODES:
            fold_true, fold_pred = [], []
            for sess_id in eligible_sessions:
                test_df = df[df["session_id"] == sess_id]
                train_df = df[df["session_id"] != sess_id]

                X_fold_train, y_fold_train = balance_classes(train_df[FEATURE_COLS], train_df[LABEL_COL])
                X_fold_test, y_fold_test = test_df[FEATURE_COLS], test_df[LABEL_COL]

                fold_clf = HistGradientBoostingClassifier(max_leaf_nodes=max_leaf_nodes, random_state=42)
                fold_clf.fit(X_fold_train, y_fold_train)
                y_fold_pred = fold_clf.predict(X_fold_test)

                fold_true.extend(y_fold_test.values)
                fold_pred.extend(y_fold_pred)

            overall_acc = float(np.mean(np.array(fold_true) == np.array(fold_pred)))
            print(f"[+] max_leaf_nodes={max_leaf_nodes}: LOSO accuracy={overall_acc:.3f}")
            if overall_acc > best_acc:
                best_acc, best_max_leaf_nodes = overall_acc, max_leaf_nodes
                best_fold_true, best_fold_pred = fold_true, fold_pred

        print(f"\n[+] Selected max_leaf_nodes={best_max_leaf_nodes} (LOSO accuracy={best_acc:.3f}) "
              "for the production model below.")
        print("\n== LOSO Aggregate Classification Report (selected max_leaf_nodes, all held-out folds combined) ==")
        print(classification_report(best_fold_true, best_fold_pred, target_names=["Normal (0)", "Flash Crowd (1)", "DDoS (2)"], zero_division=0))
        print("\n== LOSO Aggregate Confusion Matrix (selected max_leaf_nodes) ==")
        print(confusion_matrix(best_fold_true, best_fold_pred))

    print("\n[+] Training final production model on all available data...")
    X_all, y_all = balance_classes(df[FEATURE_COLS], df[LABEL_COL])
    print(f"[+] Balanced production training set size: {len(X_all)} rows.")

    if len(X_all) < 100:
        print("[-] Warning: Dataset is very small. Classification results may be unreliable.")

    clf = HistGradientBoostingClassifier(max_leaf_nodes=best_max_leaf_nodes, random_state=42)
    clf.fit(X_all, y_all)
    print("[+] Model training complete.")

    # HistGradientBoostingClassifier has no .feature_importances_ (unlike
    # RandomForestClassifier), so this script has no equivalent section to
    # train.py's Feature Importances print, not an oversight.

    print(f"\n[+] Saving trained model to: {model_out}")
    joblib.dump(clf, model_out)
    print("[+] Done!")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify it runs against a synthetic CSV**

Create a throwaway synthetic dataset and run the script against it, matching the real `train_isolation_forest.py`'s own verification precedent (a small synthetic capture, not a fabricated pass/fail claim):

```bash
cd stage2
python3 -c "
import pandas as pd
import numpy as np
rows = []
t = 1700000000.0
for session, label, n in [(0, 0, 40), (1, 0, 40), (2, 1, 40), (3, 1, 40), (4, 2, 40), (5, 2, 40)]:
    for i in range(n):
        rows.append(dict(
            entropy=0.9 if label != 2 else 0.3, ewma_rate=20.0 if label == 0 else (500.0 if label == 1 else 5000.0),
            mean_h=0.9, mean_r=20.0, sigma_h=0.1, sigma_r=7.1, proto_ratio=1.0,
            dominant_ip_ratio=0.1 if label != 2 else 0.8, source_port_entropy=0.9, ttl_variance=0.1,
            fingerprint_diversity=0.1, timestamp=t, label=label,
        ))
        t += 2.0
    t += 60.0
pd.DataFrame(rows).to_csv('/tmp/synthetic_v8_training.csv', index=False)
"
python3 train_second_model.py /tmp/synthetic_v8_training.csv /tmp/synthetic_v8_gb_model.joblib
```

Expected: the script runs to completion, prints a LOSO accuracy for each candidate `max_leaf_nodes`, and ends with `[+] Done!` having written `/tmp/synthetic_v8_gb_model.joblib`. Confirm the file loads and predicts:

```bash
python3 -c "
import joblib
clf = joblib.load('/tmp/synthetic_v8_gb_model.joblib')
print(clf.predict_proba([[0.9, 20.0, 0.9, 20.0, 0.1, 7.1, 1.0, 0.1, 0.0, 0.0, 2.0, 0.9, 0.1, 0.1]]))
"
```

Expected: a 1x3 array of probabilities summing to 1.0, no exception.

- [ ] **Step 3: Commit**

```bash
git add stage2/train_second_model.py
git commit -m "feat: add train_second_model.py, V8's independent second opinion"
```

---

## Task 5: Extend `scripts/train.sh` to train the second model

**Files:**
- Modify: `scripts/train.sh`

**Interfaces:**
- Consumes: `stage2/train_second_model.py` (Task 4).

No unit test: this is a bash script with no existing test harness in this project (`scripts/test.sh` does not test `scripts/*.sh` files, only `stage1`, `stage2`'s pytest suite, and the eBPF build). Verified by a syntax check and a dry run.

- [ ] **Step 1: Extend the option validation, help text, and dispatch**

In `scripts/train.sh`, change the `-w|--which` help line and default handling to accept `sm` (second model) alongside `rf`/`if`/`both`, and add `all` as a convenience for all three. Apply these edits:

Change:
```bash
  -w, --which <rf|if|both>  Which model(s) to train       [default: $WHICH]
```
to:
```bash
  -w, --which <rf|if|sm|both|all>  Which model(s) to train [default: $WHICH]
```

Change:
```bash
while true; do
    WHICH=$(ask "Train which model(s)? (rf, if, or both)" "$WHICH")
    case "${WHICH,,}" in
        rf|if|both) WHICH="${WHICH,,}"; break ;;
        *) echo "    Answer rf, if, or both." >&2 ;;
    esac
done
```
to:
```bash
while true; do
    WHICH=$(ask "Train which model(s)? (rf, if, sm, both, or all)" "$WHICH")
    case "${WHICH,,}" in
        rf|if|sm|both|all) WHICH="${WHICH,,}"; break ;;
        *) echo "    Answer rf, if, sm, both, or all." >&2 ;;
    esac
done
```

Change:
```bash
    export MODEL_PATH="$STAGE2_STATE_DIR/ddos_rf_model.joblib"
    export IF_MODEL_PATH="$STAGE2_STATE_DIR/ddos_if_model.joblib"
```
to:
```bash
    export MODEL_PATH="$STAGE2_STATE_DIR/ddos_rf_model.joblib"
    export IF_MODEL_PATH="$STAGE2_STATE_DIR/ddos_if_model.joblib"
    export SECOND_MODEL_PATH="$STAGE2_STATE_DIR/ddos_gb_model.joblib"
```

Change:
```bash
if [[ "$WHICH" == "rf" || "$WHICH" == "both" ]]; then
    info "Training the RandomForest (train.py)..."
    "$VENV_PYTHON" train.py "$CSV_PATH"
    success "RandomForest trained."
    echo ""
fi

if [[ "$WHICH" == "if" || "$WHICH" == "both" ]]; then
    info "Training the Isolation Forest (train_isolation_forest.py)..."
    "$VENV_PYTHON" train_isolation_forest.py "$CSV_PATH"
    success "Isolation Forest trained."
    echo ""
fi
```
to:
```bash
if [[ "$WHICH" == "rf" || "$WHICH" == "both" || "$WHICH" == "all" ]]; then
    info "Training the RandomForest (train.py)..."
    "$VENV_PYTHON" train.py "$CSV_PATH"
    success "RandomForest trained."
    echo ""
fi

if [[ "$WHICH" == "if" || "$WHICH" == "both" || "$WHICH" == "all" ]]; then
    info "Training the Isolation Forest (train_isolation_forest.py)..."
    "$VENV_PYTHON" train_isolation_forest.py "$CSV_PATH"
    success "Isolation Forest trained."
    echo ""
fi

if [[ "$WHICH" == "sm" || "$WHICH" == "all" ]]; then
    info "Training the second model (train_second_model.py)..."
    "$VENV_PYTHON" train_second_model.py "$CSV_PATH"
    success "Second model trained."
    echo ""
fi
```

- [ ] **Step 2: Syntax check**

Run: `bash -n scripts/train.sh`
Expected: no output, exit code 0.

- [ ] **Step 3: Dry run against the synthetic CSV from Task 4**

Run: `bash scripts/train.sh --defaults -c /tmp/synthetic_v8_training.csv -w sm`
Expected: runs `train_second_model.py` against the synthetic CSV (from a checkout with no production install, this trains into `stage2/ddos_gb_model.joblib`), prints `Second model trained.`, exits 0. Clean up afterward: `rm -f stage2/ddos_gb_model.joblib`.

- [ ] **Step 4: Commit**

```bash
git add scripts/train.sh
git commit -m "feat: teach scripts/train.sh to train the second model"
```

---

## Task 6: The labeling job's decision logic

**Files:**
- Create: `stage2/auto_label.py`
- Test: `stage2/tests/test_auto_label.py`

**Interfaces:**
- Consumes: `config.PRETRAINING_CSV_PATH`, `config.ANOMALOUS_CSV_PATH`, `config.AUTO_LABELED_CSV_PATH`, `config.SECOND_MODEL_PATH`, `config.AUTO_LABEL_DELAY_HOURS`, `config.AUTO_LABEL_CONFIDENCE_THRESHOLD`, `config.AUTO_LABEL_MAX_QUEUE_ROWS` (Task 1); `stage2/train_second_model.py`'s output shape (Task 4, a joblib model with `.predict_proba()`).
- Produces: `auto_label.is_row_eligible(row_timestamp, model_mtimes, delay_hours, now=None)`, `auto_label.decide_label(rf_proba, second_proba, confidence_threshold)`, `auto_label.trim_csv_rows(rows, max_rows)`. These three pure functions are this task's focus; the file's `main()` orchestration (reading the two capture files, loading both models, calling these three functions, and rewriting the CSVs) is written in this task alongside them but is not independently unit tested, matching this project's own convention that I/O orchestration in a training-adjacent script is verified by a real run, not mocked out in `pytest`.

- [ ] **Step 1: Write the failing tests for the three pure functions**

Create `stage2/tests/test_auto_label.py`:

```python
"""Tests for auto_label.py's labeling decision logic: the freshness
safeguard, model agreement, and the capture-file row cap. See
docs/specs/2026-09-13-confidence-gated-labeling-design.md."""

import csv
import os
import unittest

import _support
from _support import temp_path, unlink

import config
import auto_label


class IsRowEligibleTests(unittest.TestCase):
    """A row is eligible only once it clears the configured delay AND every
    model scoring it was trained after the row was captured. The freshness
    half exists so a stale, unretrained model can never auto-label its own
    blind spot, even with a second opinion agreeing."""

    def test_ineligible_when_younger_than_the_delay(self):
        now = 1_000_000.0
        row_timestamp = now - 3600.0  # one hour old
        self.assertFalse(auto_label.is_row_eligible(
            row_timestamp, model_mtimes=[now - 10], delay_hours=24.0, now=now,
        ))

    def test_eligible_once_older_than_the_delay_with_a_fresh_model(self):
        now = 1_000_000.0
        row_timestamp = now - (25 * 3600.0)  # 25 hours old
        self.assertTrue(auto_label.is_row_eligible(
            row_timestamp, model_mtimes=[now - 10], delay_hours=24.0, now=now,
        ))

    def test_ineligible_if_any_model_predates_the_row(self):
        now = 1_000_000.0
        row_timestamp = now - (25 * 3600.0)
        stale_model_mtime = row_timestamp - 10.0  # trained before this row was even captured
        fresh_model_mtime = now - 10.0
        self.assertFalse(auto_label.is_row_eligible(
            row_timestamp, model_mtimes=[fresh_model_mtime, stale_model_mtime], delay_hours=24.0, now=now,
        ))

    def test_eligible_only_when_every_model_postdates_the_row(self):
        now = 1_000_000.0
        row_timestamp = now - (25 * 3600.0)
        self.assertTrue(auto_label.is_row_eligible(
            row_timestamp, model_mtimes=[now - 5, now - 1], delay_hours=24.0, now=now,
        ))


class DecideLabelTests(unittest.TestCase):
    """A label is only ever produced when both models agree on the class
    and both individually clear the confidence threshold. Agreement is
    the safeguard: two differently built models making the same mistake
    on a genuinely novel row is far less likely than one model
    rehashing its own opinion."""

    def test_agreement_above_threshold_returns_the_agreed_class(self):
        rf_proba = [0.02, 0.03, 0.95]
        second_proba = [0.05, 0.05, 0.90]
        self.assertEqual(auto_label.decide_label(rf_proba, second_proba, confidence_threshold=0.90), 2)

    def test_disagreement_returns_none_even_if_both_are_confident(self):
        rf_proba = [0.02, 0.03, 0.95]      # top class 2
        second_proba = [0.95, 0.03, 0.02]  # top class 0
        self.assertIsNone(auto_label.decide_label(rf_proba, second_proba, confidence_threshold=0.90))

    def test_agreement_below_threshold_on_the_random_forest_returns_none(self):
        rf_proba = [0.15, 0.15, 0.70]      # agrees, but below 0.90
        second_proba = [0.05, 0.05, 0.90]
        self.assertIsNone(auto_label.decide_label(rf_proba, second_proba, confidence_threshold=0.90))

    def test_agreement_below_threshold_on_the_second_model_returns_none(self):
        rf_proba = [0.02, 0.03, 0.95]
        second_proba = [0.20, 0.20, 0.60]  # agrees, but below 0.90
        self.assertIsNone(auto_label.decide_label(rf_proba, second_proba, confidence_threshold=0.90))


class TrimCsvRowsTests(unittest.TestCase):
    """Without a cap, a fresh deployment left running with no model, or a
    long configured delay under heavy traffic, would grow an unbounded
    capture file. Timestamp is column index 11 in the 13-column base
    format both capture files share."""

    def _row(self, timestamp):
        return ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                "0.9", "0.1", "0.1", str(timestamp), ""]

    def test_rows_at_or_under_the_cap_are_left_untouched(self):
        rows = [self._row(t) for t in (1.0, 2.0, 3.0)]
        kept, dropped = auto_label.trim_csv_rows(rows, max_rows=3)
        self.assertEqual(len(kept), 3)
        self.assertEqual(dropped, 0)

    def test_over_the_cap_drops_the_oldest_rows_by_timestamp(self):
        rows = [self._row(t) for t in (3.0, 1.0, 2.0)]  # deliberately out of order
        kept, dropped = auto_label.trim_csv_rows(rows, max_rows=2)
        self.assertEqual(dropped, 1)
        self.assertEqual(sorted(float(r[11]) for r in kept), [2.0, 3.0])


class MainLeavesCapturedRowsUntouchedWithoutBothModelsTests(unittest.TestCase):
    """main() cannot check agreement with only one model, or with neither.
    A captured row must stay exactly where it is, not be guessed at, until
    both models exist."""

    def setUp(self):
        self.pretraining_path = temp_path(".csv")
        os.unlink(self.pretraining_path)
        self.original_pretraining_path = config.PRETRAINING_CSV_PATH
        config.PRETRAINING_CSV_PATH = self.pretraining_path
        self.original_model_path = config.MODEL_PATH
        self.original_second_model_path = config.SECOND_MODEL_PATH
        config.MODEL_PATH = self.pretraining_path + ".no-such-model"
        config.SECOND_MODEL_PATH = self.pretraining_path + ".no-such-second-model"
        with open(self.pretraining_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(auto_label.BASE_CSV_HEADER)
            w.writerow(["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
                        "0.9", "0.1", "0.1", "1000.0", ""])

    def tearDown(self):
        config.PRETRAINING_CSV_PATH = self.original_pretraining_path
        config.MODEL_PATH = self.original_model_path
        config.SECOND_MODEL_PATH = self.original_second_model_path
        unlink(self.pretraining_path)

    def test_the_captured_row_is_left_untouched_when_neither_model_exists(self):
        auto_label.main()
        with open(self.pretraining_path, newline="") as f:
            rows = list(csv.reader(f))
        self.assertEqual(len(rows), 2)  # header + the one row, unchanged


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd stage2 && python3 -m pytest tests/test_auto_label.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'auto_label'` (the file does not exist yet, this is expected).

- [ ] **Step 3: Write `auto_label.py`'s pure functions and orchestration**

Create `stage2/auto_label.py`:

```python
#!/usr/bin/env python3
"""
auto_label.py: Stage 2, V8's confidence gated automatic labeling.

Run periodically by a systemd timer (ddos-stage2-auto-label.timer), not a
background thread inside stage2.py: this reads and rewrites CSV files on
disk, the same "runs occasionally against accumulated state" shape as
scripts/calibrate.py.

Re-scores rows in config.PRETRAINING_CSV_PATH (cold-start windows) and
config.ANOMALOUS_CSV_PATH (Isolation-Forest-flagged windows) against the
RandomForest and a second, independently trained model. A row is only
auto-labeled when both models agree on the class, both clear the
confidence threshold, and both were trained after the row was captured.
See docs/specs/2026-09-13-confidence-gated-labeling-design.md for why:
re-running the same RF against a row it already has a blind spot for
would just reproduce that blind spot with new-found confidence.

Confidently labeled rows are staged in config.AUTO_LABELED_CSV_PATH, not
written into training_data.csv directly, so nothing enters the
authoritative training set without an operator's own deliberate merge.
"""

import os
import csv
import time
import logging

import joblib
import numpy as np
import pandas as pd

import config

FEATURE_COLS = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "delta_rate", "delta_entropy",
    "dominant_rate", "source_port_entropy", "ttl_variance", "fingerprint_diversity",
]
BASE_CSV_HEADER = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "source_port_entropy", "ttl_variance",
    "fingerprint_diversity", "timestamp", "label",
]
# Index of the timestamp column within a BASE_CSV_HEADER row.
TIMESTAMP_COL = 11


def is_row_eligible(row_timestamp, model_mtimes, delay_hours, now=None):
    """A captured row is eligible for automatic labeling only once it is
    older than delay_hours, and only if every model that will score it was
    trained after it was captured. The freshness half of this check is the
    core safeguard: a model that has not changed since a row was captured
    cannot be trusted to auto-label its own blind spot."""
    now = time.time() if now is None else now
    age_hours = (now - row_timestamp) / 3600.0
    if age_hours < delay_hours:
        return False
    return all(mtime > row_timestamp for mtime in model_mtimes)


def decide_label(rf_proba, second_proba, confidence_threshold):
    """Returns the agreed class (0, 1, or 2) if both models pick the same
    top class and both clear confidence_threshold on it, else None.
    Agreement is what makes this a real signal rather than a rubber
    stamp: two differently built models making the same mistake on a
    genuinely novel row is far less likely than one model rehashing its
    own opinion."""
    rf_top = int(np.argmax(rf_proba))
    second_top = int(np.argmax(second_proba))
    if rf_top != second_top:
        return None
    if rf_proba[rf_top] < confidence_threshold or second_proba[second_top] < confidence_threshold:
        return None
    return rf_top


def trim_csv_rows(rows, max_rows):
    """Keeps the newest max_rows rows by their timestamp column, dropping
    the oldest first. rows is a list of plain string lists as returned by
    csv.reader, header not included. Returns (kept_rows, dropped_count).
    Without this cap, a fresh deployment left running with no model, or a
    long configured delay under heavy traffic, would grow an unbounded
    file."""
    if len(rows) <= max_rows:
        return rows, 0
    sorted_rows = sorted(rows, key=lambda r: float(r[TIMESTAMP_COL]))
    dropped = len(sorted_rows) - max_rows
    return sorted_rows[dropped:], dropped


def _read_rows(path):
    """Returns (header, rows) for a capture CSV, or (None, []) if the file
    does not exist yet, which is the normal state for a fresh deployment
    that has not captured anything of this kind."""
    if not os.path.exists(path):
        return None, []
    with open(path, newline="") as f:
        reader = csv.reader(f)
        rows = list(reader)
    if not rows:
        return None, []
    return rows[0], rows[1:]


def _rewrite_csv(path, header, rows):
    """Atomic replace: write to a temp file in the same directory, then
    rename over the target, so a reader never sees a partially rewritten
    file and a crash mid-write leaves the previous complete file in place."""
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    os.replace(tmp, path)


def _row_to_features(row, header):
    """Builds the derived-feature row (matching FEATURE_COLS' order) a
    model's predict_proba expects, from one BASE_CSV_HEADER row."""
    by_name = dict(zip(header, row))
    entropy, ewma_rate = float(by_name["entropy"]), float(by_name["ewma_rate"])
    mean_h, mean_r = float(by_name["mean_h"]), float(by_name["mean_r"])
    sigma_h, sigma_r = float(by_name["sigma_h"]), float(by_name["sigma_r"])
    proto_ratio = float(by_name["proto_ratio"])
    dominant_ip_ratio = float(by_name["dominant_ip_ratio"])
    return {
        "entropy": entropy, "ewma_rate": ewma_rate, "mean_h": mean_h, "mean_r": mean_r,
        "sigma_h": sigma_h, "sigma_r": sigma_r, "proto_ratio": proto_ratio,
        "dominant_ip_ratio": dominant_ip_ratio,
        "delta_rate": ewma_rate - mean_r, "delta_entropy": entropy - mean_h,
        "dominant_rate": ewma_rate * dominant_ip_ratio,
        "source_port_entropy": float(by_name["source_port_entropy"]),
        "ttl_variance": float(by_name["ttl_variance"]),
        "fingerprint_diversity": float(by_name["fingerprint_diversity"]),
    }


def _process_capture_file(path, clf, second_clf, model_mtimes, labeled_out):
    """Trims path to config.AUTO_LABEL_MAX_QUEUE_ROWS, then scores every
    remaining row: eligible and confidently agreed rows are appended to
    labeled_out and removed here; everything else stays for the next run
    or for a human, exactly as it does today. Returns the number of rows
    auto-labeled."""
    header, rows = _read_rows(path)
    if header is None:
        logging.info(f"[+] {path} does not exist or is empty, nothing to process.")
        return 0

    rows, dropped = trim_csv_rows(rows, config.AUTO_LABEL_MAX_QUEUE_ROWS)
    if dropped:
        logging.warning(f"[!] {path} exceeded {config.AUTO_LABEL_MAX_QUEUE_ROWS} rows, "
                         f"dropped {dropped} oldest.")

    kept_rows = []
    labeled_count = 0
    for row in rows:
        row_timestamp = float(row[TIMESTAMP_COL])
        if not is_row_eligible(row_timestamp, model_mtimes, config.AUTO_LABEL_DELAY_HOURS):
            kept_rows.append(row)
            continue

        features = _row_to_features(row, BASE_CSV_HEADER)
        features_df = pd.DataFrame([[features[c] for c in FEATURE_COLS]], columns=FEATURE_COLS)
        rf_proba = clf.predict_proba(features_df)[0]
        second_proba = second_clf.predict_proba(features_df)[0]
        label = decide_label(rf_proba, second_proba, config.AUTO_LABEL_CONFIDENCE_THRESHOLD)

        if label is None:
            kept_rows.append(row)
            continue

        labeled_row = list(row)
        labeled_row[BASE_CSV_HEADER.index("label")] = str(label)
        _append_labeled_row(labeled_out, labeled_row)
        labeled_count += 1

    _rewrite_csv(path, header, kept_rows)
    return labeled_count


def _append_labeled_row(path, row):
    write_header = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(BASE_CSV_HEADER)
        w.writerow(row)


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if not os.path.exists(config.MODEL_PATH) or not os.path.exists(config.SECOND_MODEL_PATH):
        logging.info("[+] RandomForest and/or second model not present yet, "
                      "agreement cannot be checked with only one model. Nothing to do.")
        return

    clf = joblib.load(config.MODEL_PATH)
    clf.n_jobs = 1
    second_clf = joblib.load(config.SECOND_MODEL_PATH)
    model_mtimes = [os.path.getmtime(config.MODEL_PATH), os.path.getmtime(config.SECOND_MODEL_PATH)]

    total_labeled = 0
    for path in (config.PRETRAINING_CSV_PATH, config.ANOMALOUS_CSV_PATH):
        total_labeled += _process_capture_file(path, clf, second_clf, model_mtimes, config.AUTO_LABELED_CSV_PATH)

    logging.info(f"[+] Auto-labeled {total_labeled} row(s) into {config.AUTO_LABELED_CSV_PATH}.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd stage2 && python3 -m pytest tests/test_auto_label.py -v`
Expected: PASS, all 11 tests (4 `IsRowEligibleTests`, 4 `DecideLabelTests`, 2 `TrimCsvRowsTests`, 1 `MainLeavesCapturedRowsUntouchedWithoutBothModelsTests`).

- [ ] **Step 5: Manual end-to-end check against the synthetic model from Task 4**

```bash
cd stage2
cp /tmp/synthetic_v8_gb_model.joblib /tmp/synthetic_v8_gb_model_copy.joblib
python3 -c "
import os, csv, time
os.environ['PRETRAINING_CSV_PATH'] = '/tmp/pretraining_capture_test.csv'
os.environ['ANOMALOUS_CSV_PATH'] = '/tmp/anomalous_capture_test.csv'
os.environ['AUTO_LABELED_CSV_PATH'] = '/tmp/auto_labeled_capture_test.csv'
os.environ['MODEL_PATH'] = '/tmp/synthetic_v8_gb_model.joblib'  # stand-in RF for this smoke test
os.environ['SECOND_MODEL_PATH'] = '/tmp/synthetic_v8_gb_model_copy.joblib'
os.environ['AUTO_LABEL_DELAY_HOURS'] = '0'
import config, auto_label
old_time = time.time() - 10  # older than both model files, satisfies the freshness rule
with open('/tmp/pretraining_capture_test.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(auto_label.BASE_CSV_HEADER)
    w.writerow(['0.9', '20.0', '0.9', '20.0', '0.1', '7.1', '1.0', '0.1', '0.9', '0.1', '0.1', str(old_time), ''])
auto_label.main()
with open('/tmp/auto_labeled_capture_test.csv') as f:
    print(f.read())
"
```

Expected: prints `[+] Auto-labeled 1 row(s)...` (or `0` if the synthetic model's confidence on this particular row happens to fall under the 0.90 default threshold, in which case adjust the row's feature values to something closer to one of the three synthetic training clusters from Task 4 and re-run, rather than treating a 0 as a failure) followed by the contents of `auto_labeled_capture_test.csv` if a row was labeled. Clean up: `rm -f /tmp/pretraining_capture_test.csv /tmp/anomalous_capture_test.csv /tmp/auto_labeled_capture_test.csv /tmp/synthetic_v8_gb_model_copy.joblib`.

- [ ] **Step 6: Commit**

```bash
git add stage2/auto_label.py stage2/tests/test_auto_label.py
git commit -m "feat: add auto_label.py, V8's confidence-gated labeling job"
```

---

## Task 7: Systemd timer for the labeling job

**Files:**
- Modify: `scripts/install.sh` (right after the existing `ddos-stage2.service` heredoc block, `scripts/install.sh:657-691`)
- Modify: `scripts/update.sh` (the matching `ddos-stage2.service` regeneration block, `scripts/update.sh:239-266`)

**Interfaces:**
- Consumes: `stage2/auto_label.py` (Task 6), the existing `$STAGE2_INSTALL_DIR`/`$STAGE2_STATE_DIR`/`$SERVICE_DIR` variables both scripts already define.

No unit test: shell heredoc generation, verified by `bash -n` and by rendering the heredoc to confirm its content.

- [ ] **Step 1: Add the service and timer to `scripts/install.sh`**

Immediately after the closing `EOF` of the existing `ddos-stage2.service` block at `scripts/install.sh:689` (right before `fi` on line 691), insert:

```bash
        cat > "$SERVICE_DIR/ddos-stage2-auto-label.service" << EOF
# =============================================================================
# ddos-stage2-auto-label.service, V8's confidence gated labeling job
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

[Unit]
Description=Adaptive DDoS Mitigation Stage 2 Confidence Gated Labeling
Documentation=https://github.com/DevInBlack001/ddos-reduction-system/wiki

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=$STAGE2_INSTALL_DIR
ExecStart=/bin/bash -c 'source "$STAGE2_INSTALL_DIR/venv/bin/activate" && exec python3 auto_label.py'
Environment="FLOD_STATE_DIR=$STAGE2_STATE_DIR"
EOF

        cat > "$SERVICE_DIR/ddos-stage2-auto-label.timer" << EOF
# =============================================================================
# ddos-stage2-auto-label.timer, runs the labeling job periodically rather
# than as a background thread inside the long-running Stage 2 service.
# Generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# =============================================================================

[Timer]
OnBootSec=1h
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
        success "Systemd timer created for the confidence gated labeling job."
```

- [ ] **Step 2: Enable it alongside the other services**

In `scripts/install.sh`, find the block printing enable/start instructions (`scripts/install.sh:700-704`):

```bash
    info ""
    info "To enable at boot and start now:"
    info "    systemctl enable --now ddos-stage2"
    info "    systemctl enable --now ddos-stage1"
    info ""
```

Change to:

```bash
    info ""
    info "To enable at boot and start now:"
    info "    systemctl enable --now ddos-stage2"
    info "    systemctl enable --now ddos-stage1"
    info "    systemctl enable --now ddos-stage2-auto-label.timer"
    info ""
```

- [ ] **Step 3: Mirror both changes in `scripts/update.sh`**

Apply the same two edits to `scripts/update.sh`'s matching `ddos-stage2.service` block (`scripts/update.sh:239-266`) and its own enable/start instructions, using update.sh's own `$STAGE2_INSTALL_DIR`/`$STAGE2_STATE_DIR`/`$SERVICE_DIR` variable names (already the same names as install.sh's, confirmed earlier in this session). Insert the same two heredocs immediately after update.sh's `ddos-stage2.service` heredoc closes, and add the same `systemctl enable --now ddos-stage2-auto-label.timer` line to update.sh's own printed instructions.

- [ ] **Step 4: Syntax check both scripts**

Run: `bash -n scripts/install.sh && bash -n scripts/update.sh`
Expected: no output, exit code 0 for both.

- [ ] **Step 5: Render the heredocs to confirm real content, no unexpanded placeholders**

```bash
grep -A 20 "ddos-stage2-auto-label.service" scripts/install.sh | head -25
grep -A 15 "ddos-stage2-auto-label.timer" scripts/install.sh | head -20
```

Expected: real unit file content with `$STAGE2_INSTALL_DIR`, `$STAGE2_STATE_DIR`, and today's date substitution left as literal shell variables in the file (they expand when `install.sh` actually runs, not when read as source), no `TBD` or empty `ExecStart=`.

- [ ] **Step 6: Commit**

```bash
git add scripts/install.sh scripts/update.sh
git commit -m "feat: add a systemd timer for the confidence-gated labeling job"
```

---

## Final Verification

- [ ] Run the full Python test suite: `cd stage2 && python3 -m pytest tests/ -v`. Expected: every test passes, including all pre-existing tests (confirms Task 2's refactor introduced no regression).
- [ ] Run `bash -n` against every modified shell script: `bash -n scripts/train.sh scripts/install.sh scripts/update.sh`.
- [ ] Confirm this plan's spec coverage against `docs/specs/2026-09-13-confidence-gated-labeling-design.md`: the Core Safeguard (Task 6's freshness check), Building the Second Model (Task 4, Task 5), Capture (Task 2, Task 3), The Labeling Job (Task 6), Configuration (Task 1). The spec's two Open Questions (per-class confidence thresholds, a retention cap on `auto_labeled_capture.csv`) are explicitly deferred, not silently dropped, per the spec's own text.
- [ ] This entire milestone needs verification on the sensor VM before being trusted, per this project's own standing convention: `scripts/test.sh` locally is not authoritative (missing Python dependencies are a known local-environment gap, not a code problem). A real run needs a genuinely fresh deployment (no RandomForest model present) to exercise cold-start capture, and a later run once both models exist and enough time has passed the configured delay to exercise the labeling job itself.
