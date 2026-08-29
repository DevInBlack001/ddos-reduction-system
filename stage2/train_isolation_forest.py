#!/usr/bin/env python3
"""
train_isolation_forest.py: Stage 2, V7's second model.

Separate from train.py on purpose: train.py stays RandomForest-only. This
script fits an unsupervised sklearn.ensemble.IsolationForest on the SAME
cleaned feature set train.py uses, but on the full dataset, all three
labels, ignoring the label column entirely.

Why full dataset rather than Normal-only: the goal is catching traffic the
RandomForest is not familiar with, unlike anything in the training set,
attack or normal, not narrowly "unlike normal traffic," which the
RandomForest is already reasonably equipped to judge on its own. An
Isolation Forest trained only on Normal rows would answer a different
question (is this normal-looking) than the one V7 needs answered (does this
look like anything either model has learned at all).

Both models run in production every window, side by side, see
stage2/ipc_receiver.py.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "stage1", "training_data.csv")
# Same IF_MODEL_PATH environment variable config.py honours, see train.py's
# matching MODEL_PATH comment.
IF_MODEL_PATH = os.environ.get("IF_MODEL_PATH", os.path.join(SCRIPT_DIR, "ddos_if_model.joblib"))

# Matches train.py's FEATURE_COLS exactly. Kept as a separate literal rather
# than imported from train.py, since train.py is not a module meant to be
# imported (it runs as a script), and duplicating one list is a smaller risk
# than coupling two independently run training scripts together.
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

# contamination is swept the same way train.py sweeps max_depth: rather than
# fix what fraction of the training set IsolationForest treats as outliers,
# try a range and keep whichever value best separates DDoS rows from benign
# ones in the outlier-rate sanity check below. Unlike max_depth's LOSO
# accuracy, the raw separation (DDoS outlier rate minus benign outlier rate)
# does not peak partway through this range, it keeps climbing as contamination
# grows, because a bigger contamination just flags more of everything. Picking
# the candidate with the largest raw separation would walk to the edge of
# whatever range is given here rather than finding a real optimum, the same
# failure shape already fixed once in this project for the entropy floor,
# where an unconstrained criterion flagged a large share of ordinary traffic.
# So the benign outlier rate is capped, and the winner is whichever
# contamination gives the best DDoS separation without exceeding it. This
# keeps "Anomalous" a rare signal on ordinary traffic instead of background
# noise. Both the cap and the candidate range are starting points, not values
# proven optimal against real traffic.
BENIGN_OUTLIER_RATE_CAP = 0.05
FALLBACK_CONTAMINATION = 0.05
CANDIDATE_CONTAMINATIONS = [0.01, 0.02, 0.05, 0.075, 0.1, 0.15, 0.2, 0.25]


def main():
    print("=== FLOD System: Stage 2 Isolation Forest Training (V7) ===")

    # Same arg handling as train.py: <csv_path> [<model_out_path>].
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
    model_out = sys.argv[2] if len(sys.argv) > 2 else IF_MODEL_PATH

    print(f"[+] Loading dataset from: {csv_file}")
    df = pd.read_csv(csv_file)
    print(f"[+] Loaded {len(df)} raw rows.")

    # Same schema check as train.py: a pre-V7 capture has no way to hold the
    # three V7 columns, fail loudly rather than train on NaNs or crash on a
    # raw KeyError later.
    derived_cols = {"delta_rate", "delta_entropy", "dominant_rate"}
    required_raw_cols = [c for c in FEATURE_COLS if c not in derived_cols] + [LABEL_COL, "timestamp"]
    missing_cols = [c for c in required_raw_cols if c not in df.columns]
    if missing_cols:
        print(f"[-] Error: '{csv_file}' is missing column(s): {', '.join(missing_cols)}")
        print("    This looks like a pre-V7 capture. Recapture with the current sensor")
        print("    before training, or point this script at a CSV that already has them.")
        sys.exit(1)

    # Same cleaning as train.py, so both models see the same shape of data.
    # An Isolation Forest fit against noise train.py would have dropped
    # would learn that noise as "familiar," undermining the whole point of
    # flagging genuinely unfamiliar traffic.
    df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)

    dup_count = df.duplicated().sum()
    if dup_count > 0:
        print(f"[!] Dropping {dup_count} exact-duplicate rows found in the dataset.")
        df = df.drop_duplicates().reset_index(drop=True)

    df = df[~((df[LABEL_COL] == 1) & (df["ewma_rate"] < 100))].reset_index(drop=True)

    dropped_idle_ddos = ((df[LABEL_COL] == 2) & (df["ewma_rate"] < 1.0)).sum()
    if dropped_idle_ddos > 0:
        print(f"[!] Dropping {dropped_idle_ddos} idle rows mislabeled as DDoS (rate < 1 pps).")
    df = df[~((df[LABEL_COL] == 2) & (df["ewma_rate"] < 1.0))].reset_index(drop=True)

    df["delta_rate"] = df["ewma_rate"] - df["mean_r"]
    df["delta_entropy"] = df["entropy"] - df["mean_h"]
    df["dominant_rate"] = df["ewma_rate"] * df["dominant_ip_ratio"]

    print(f"\n[+] Training set after cleaning: {len(df)} rows, all labels pooled, "
          "label column not used as an input.")

    X = df[FEATURE_COLS]

    # IsolationForest has no LOSO equivalent, there is no ground truth for
    # "was this an evasive attack." The label column is unused for fitting,
    # but it is still the best available signal for picking contamination:
    # whichever value flags DDoS rows as outliers most relative to benign
    # ones, without needing this to be a claim about held-out generalization.
    ddos_present = (df[LABEL_COL] == 2).any()
    if not ddos_present:
        print("\n[-] No DDoS-labeled rows present, contamination cannot be swept. "
              f"Falling back to an UNVALIDATED default contamination={FALLBACK_CONTAMINATION}.")
        best_contamination = FALLBACK_CONTAMINATION
        best_clf = None
        best_sep = None
    else:
        print("\n[+] Sweeping candidate contamination values against the "
              f"DDoS-vs-benign outlier rate gap (benign capped at {BENIGN_OUTLIER_RATE_CAP:.0%})...")
        best_contamination = None
        best_clf = None
        best_sep = None
        # Kept alongside the capped search so there is still something to
        # fall back to if every candidate happens to exceed the cap.
        least_noisy_contamination = None
        least_noisy_clf = None
        least_noisy_benign_rate = None
        for contamination in CANDIDATE_CONTAMINATIONS:
            candidate_clf = IsolationForest(
                n_estimators=100,
                contamination=contamination,
                random_state=42,
                n_jobs=-1,
            )
            candidate_clf.fit(X)
            outlier = candidate_clf.predict(X) == -1  # 1 = inlier, -1 = outlier
            ddos_rate = outlier[(df[LABEL_COL] == 2).to_numpy()].mean()
            benign_rate = outlier[(df[LABEL_COL] != 2).to_numpy()].mean()
            separation = ddos_rate - benign_rate
            within_cap = benign_rate <= BENIGN_OUTLIER_RATE_CAP
            print(f"[+] contamination={contamination}: DDoS outlier rate={ddos_rate:.1%}, "
                  f"benign outlier rate={benign_rate:.1%}, separation={separation:+.3f}"
                  f"{'' if within_cap else ' (over the benign cap, not eligible)'}")
            if within_cap and (best_sep is None or separation > best_sep):
                best_sep = separation
                best_contamination = contamination
                best_clf = candidate_clf
            if least_noisy_benign_rate is None or benign_rate < least_noisy_benign_rate:
                least_noisy_benign_rate = benign_rate
                least_noisy_contamination = contamination
                least_noisy_clf = candidate_clf

        if best_contamination is None:
            print(f"\n[!] No candidate kept the benign outlier rate at or below "
                  f"{BENIGN_OUTLIER_RATE_CAP:.0%}. Falling back to contamination="
                  f"{least_noisy_contamination}, the candidate with the lowest benign "
                  f"outlier rate ({least_noisy_benign_rate:.1%}).")
            best_contamination = least_noisy_contamination
            best_clf = least_noisy_clf
        else:
            print(f"\n[+] Selected contamination={best_contamination} (separation={best_sep:+.3f}, "
                  f"benign outlier rate at or below the {BENIGN_OUTLIER_RATE_CAP:.0%} cap) for "
                  "the production model below. This was chosen fresh from the sessions currently "
                  "in the CSV, a different or expanded capture set may select a different value, "
                  "so re-run this script (not just reuse this number) whenever sessions change.")

    if best_clf is not None:
        if_clf = best_clf
    else:
        print(f"\n[+] Fitting IsolationForest (contamination={best_contamination})...")
        if_clf = IsolationForest(
            n_estimators=100,
            contamination=best_contamination,
            random_state=42,
            n_jobs=-1,
        )
        if_clf.fit(X)
        print("[+] Fit complete.")

    # Sanity diagnostic on the selected model: how it scores its own
    # training data, split by the label those rows actually carry (unused
    # during fitting). Not a validation metric, this only confirms the
    # model is not, say, flagging every DDoS row as an outlier (which would
    # just mean it re-learned the RandomForest's job) or flagging almost
    # nothing (too permissive to be useful).
    predictions = if_clf.predict(X)  # 1 = inlier, -1 = outlier
    df["_if_outlier"] = predictions == -1
    print("\n== Outlier Rate By Label (sanity check, not a validation metric) ==")
    for label in sorted(df[LABEL_COL].unique()):
        lbl_df = df[df[LABEL_COL] == label]
        outlier_rate = lbl_df["_if_outlier"].mean()
        print(f"  label {label}: {outlier_rate:.1%} of {len(lbl_df)} rows flagged as outliers")

    print(f"\n[+] Saving trained model to: {model_out}")
    joblib.dump(if_clf, model_out)
    print("[+] Done!")


if __name__ == "__main__":
    main()
