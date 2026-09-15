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
