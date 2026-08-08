#!/usr/bin/env python3
"""
train.py: Stage 2: Machine Learning Model Trainer
This script loads the raw CSV data collected from Stage 1, applies strict
preprocessing/cleaning rules to remove timing-jitter baseline contamination,
trains a Random Forest classifier, and saves the trained model.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils import resample

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "stage1", "training_data.csv")
MODEL_PATH = os.path.join(SCRIPT_DIR, "ddos_rf_model.joblib")
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
    "dominant_rate"
]
LABEL_COL = "label"


def balance_classes(X, y):
    """Upsample every class to the size of the largest class. Training-split
    only, never call this on evaluation data."""
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

def main():
    print("=== DDoS Reduction Project: Stage 2 Training ===")
    
    # 1. Load Dataset
    csv_file = CSV_PATH
    if not os.path.exists(csv_file):
        csv_file = "training_data.csv"
        if not os.path.exists(csv_file):
            print(f"[-] Error: Training data not found at '{CSV_PATH}' or './training_data.csv'")
            print("    Please copy the collected CSV file to this directory and run again.")
            sys.exit(1)
            
    print(f"[+] Loading dataset from: {csv_file}")
    df = pd.read_csv(csv_file)
    print(f"[+] Loaded {len(df)} raw rows.")
    
    # Drop rows with NaN or infinite values
    df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)

    # Drop exact-duplicate rows. Capture appends have landed the same rows in
    # the CSV more than once before (e.g. re-running a capture into the same
    # file); duplicates silently double a session's weight in the balanced
    # training set and in LOSO folds, which distorts both without raising
    # any error.
    dup_count = df.duplicated().sum()
    if dup_count > 0:
        print(f"[!] Dropping {dup_count} exact-duplicate rows found in the dataset.")
        df = df.drop_duplicates().reset_index(drop=True)

    # Filter out flash-crowd warm-up rows (rate < 100) that blur the boundary with Normal traffic
    df = df[~((df[LABEL_COL] == 1) & (df["ewma_rate"] < 100))].reset_index(drop=True)
    
    # Calculate delta features
    df["delta_rate"] = df["ewma_rate"] - df["mean_r"]
    df["delta_entropy"] = df["entropy"] - df["mean_h"]

    # dominant_rate: estimated pps of the single busiest source in the window
    # (ewma_rate * dominant_ip_ratio). Already used ad hoc in stage2.py's
    # enforcement guards; promoted here to an actual classifier input so the
    # RF sees it too, not just the post-classification block/ratelimit rule.
    df["dominant_rate"] = df["ewma_rate"] * df["dominant_ip_ratio"]

    print("\n== Raw Class Distribution ==")
    print(df[LABEL_COL].value_counts().to_string())

    # 2. Session Detection and Validation Snippet
    print("\n[+] Analysing capture sessions and features...")
    
    # Ensure chronological order
    df = df.sort_values(by="timestamp").reset_index(drop=True)
    
    # Session detection: timestamp gap > 30 seconds or label changes starts a new session
    df["time_diff"] = df["timestamp"].diff()
    df["label_changed"] = df[LABEL_COL] != df[LABEL_COL].shift()
    df["new_session"] = (df["time_diff"] > 30.0) | (df["time_diff"].isna()) | df["label_changed"]
    df["session_id"] = df["new_session"].cumsum()

    # Print Session Info & Validation ranges
    sessions_info = []
    for sess_id, sess_df in df.groupby("session_id"):
        label = sess_df[LABEL_COL].iloc[0]
        count = len(sess_df)
        duration = sess_df["timestamp"].max() - sess_df["timestamp"].min()
        min_rate = sess_df["ewma_rate"].min()
        max_rate = sess_df["ewma_rate"].max()
        min_entropy = sess_df["entropy"].min()
        max_entropy = sess_df["entropy"].max()
        
        sessions_info.append({
            "Session ID": sess_id,
            "Label": label,
            "Rows": count,
            "Duration (s)": round(duration, 1),
            "Rate Range": f"{min_rate:.1f} - {max_rate:.1f}",
            "Entropy Range": f"{min_entropy:.2f} - {max_entropy:.2f}"
        })
    print("\n== Detected Capture Sessions ==")
    print(pd.DataFrame(sessions_info).to_string(index=False))

    # Print overall feature ranges per class to evaluate overlap
    print("\n== Feature Ranges Per Class (Overlap Check) ==")
    overlap_info = []
    for label in [0, 1, 2]:
        lbl_df = df[df[LABEL_COL] == label]
        if len(lbl_df) > 0:
            overlap_info.append({
                "Label": label,
                "Min Rate": lbl_df["ewma_rate"].min(),
                "Max Rate": lbl_df["ewma_rate"].max(),
                "Mean Rate": lbl_df["ewma_rate"].mean(),
                "Min Entropy": lbl_df["entropy"].min(),
                "Max Entropy": lbl_df["entropy"].max(),
                "Mean Entropy": lbl_df["entropy"].mean(),
                "Min Dominant IP Ratio": lbl_df["dominant_ip_ratio"].min(),
                "Max Dominant IP Ratio": lbl_df["dominant_ip_ratio"].max(),
                "Mean Dominant IP Ratio": lbl_df["dominant_ip_ratio"].mean(),
                "Min Dominant Rate": lbl_df["dominant_rate"].min(),
                "Max Dominant Rate": lbl_df["dominant_rate"].max(),
                "Mean Dominant Rate": lbl_df["dominant_rate"].mean()
            })
    print(pd.DataFrame(overlap_info).to_string(index=False))

    # 3. Leave-One-Session-Out (LOSO) evaluation, sweeping tree depth.
    # For each session, hold it out entirely, train on every OTHER session
    # (all labels), and test on the held-out one. A session is only a fair
    # fold if its label has >=2 sessions total, otherwise holding it out
    # leaves zero training examples of that class, which is a dataset-
    # coverage gap, not a real generalization test, and would just report a
    # meaningless 0.00. Random splitting / percentage-of-session splitting
    # both leak: consecutive windows share EWMA/Welford state, so the RF can
    # memorize a session's fingerprint instead of learning to generalize.
    #
    # max_depth is swept rather than fixed because the right value depends
    # entirely on how many independent sessions THIS dataset has per class,
    # with only two sessions of a class, a deep tree can memorize one
    # session's specific fingerprint and completely fail on the other (one
    # capture set here saw a held-out session collapse from ~1.00 to ~0.02
    # accuracy once the tree was allowed more than a couple of splits). A
    # hardcoded depth tuned on one capture set has no reason to suit a
    # different one, so this picks whatever depth LOSO says generalizes best
    # on the CSV actually loaded, every time the script runs.
    print("\n[+] Running Leave-One-Session-Out (LOSO) evaluation across candidate tree depths...")
    sessions_per_label = df.groupby(LABEL_COL)["session_id"].nunique()
    all_sessions = sorted(df["session_id"].unique())

    eligible_sessions = []
    for sess_id in all_sessions:
        label = df[df["session_id"] == sess_id][LABEL_COL].iloc[0]
        if sessions_per_label.get(label, 0) < 2:
            print(f"[!] Session {sess_id} (label {label}): SKIPPED, only session for this "
                  f"label, holding it out would leave zero training examples of it. "
                  f"Capture >=1 more independent session of label {label} to make this a fair fold.")
        else:
            eligible_sessions.append(sess_id)

    CANDIDATE_MAX_DEPTHS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, None]
    best_depth = 5  # undocumented-data fallback if LOSO can't run at all below
    best_acc = -1.0
    best_fold_true, best_fold_pred, best_per_session = [], [], []

    if not eligible_sessions:
        print("[-] No label currently has >=2 sessions, LOSO cannot run yet. "
              "Every label needs at least one more independent session before tree depth "
              f"can be validated. Falling back to an UNVALIDATED default max_depth={best_depth}.")
    else:
        for depth in CANDIDATE_MAX_DEPTHS:
            fold_true, fold_pred, per_session = [], [], []
            for sess_id in eligible_sessions:
                test_df = df[df["session_id"] == sess_id]
                train_df = df[df["session_id"] != sess_id]
                label = test_df[LABEL_COL].iloc[0]

                X_fold_train, y_fold_train = balance_classes(train_df[FEATURE_COLS], train_df[LABEL_COL])
                X_fold_test, y_fold_test = test_df[FEATURE_COLS], test_df[LABEL_COL]

                fold_clf = RandomForestClassifier(n_estimators=100, max_depth=depth, random_state=42, n_jobs=-1)
                fold_clf.fit(X_fold_train, y_fold_train)
                y_fold_pred = fold_clf.predict(X_fold_test)

                acc = (y_fold_pred == y_fold_test.values).mean()
                per_session.append((sess_id, label, len(test_df), acc))
                fold_true.extend(y_fold_test.values)
                fold_pred.extend(y_fold_pred)

            overall_acc = float(np.mean(np.array(fold_true) == np.array(fold_pred)))
            print(f"[+] max_depth={depth}: LOSO accuracy={overall_acc:.3f}")
            if overall_acc > best_acc:
                best_acc, best_depth = overall_acc, depth
                best_fold_true, best_fold_pred, best_per_session = fold_true, fold_pred, per_session

        print(f"\n[+] Selected max_depth={best_depth} (LOSO accuracy={best_acc:.3f}) for the "
              "production model below. This was chosen fresh from the sessions currently in "
              "the CSV, a different or expanded capture set may select a different depth, "
              "so re-run this script (not just reuse this number) whenever sessions change.")
        print("\n== Per-Session Results at Selected Depth ==")
        for sess_id, label, n, acc in best_per_session:
            print(f"    Session {sess_id} (label {label}, {n} rows): accuracy={acc:.3f}")
        print("\n== LOSO Aggregate Classification Report (selected depth, all held-out folds combined) ==")
        print(classification_report(best_fold_true, best_fold_pred, target_names=["Normal (0)", "Flash Crowd (1)", "DDoS (2)"], zero_division=0))
        print("\n== LOSO Aggregate Confusion Matrix (selected depth) ==")
        print(confusion_matrix(best_fold_true, best_fold_pred))

    # 4. Final production model: train on ALL available data (every session),
    # balanced. This is a SEPARATE step from the LOSO evaluation above, LOSO
    # exists to tell you whether the approach generalizes, not to produce the
    # model you actually ship. Once LOSO results look acceptable, this is the
    # model that gets saved and deployed.
    print("\n[+] Training final production model on all available data...")
    X_all, y_all = balance_classes(df[FEATURE_COLS], df[LABEL_COL])
    print(f"[+] Balanced production training set size: {len(X_all)} rows.")
    print("\n== Balanced Training Class Distribution ==")
    print(y_all.value_counts().to_string())

    if len(X_all) < 100:
        print("[-] Warning: Dataset is very small. Classification results may be unreliable.")

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=best_depth,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_all, y_all)
    print("[+] Model training complete.")

    # Feature Importances
    print("\n== Feature Importances (production model) ==")
    importances = clf.feature_importances_
    for col, imp in sorted(zip(FEATURE_COLS, importances), key=lambda x: x[1], reverse=True):
        print(f"  {col:<20} : {imp:.4f}")

    # 5. Save Model
    print(f"\n[+] Saving trained model to: {MODEL_PATH}")
    joblib.dump(clf, MODEL_PATH)
    print("[+] Done!")

if __name__ == "__main__":
    main()
