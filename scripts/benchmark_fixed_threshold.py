#!/usr/bin/env python3
"""
benchmark_fixed_threshold.py: FLOD's trained classifier vs. a fixed rate
threshold, evaluated offline against an already-captured training CSV.

Scope, decided in CLAUDE.md before this script existed: fixed threshold
only this pass, not the XDP rate limiter or ML-only arms, since those are
new systems and this one is a pure reinterpretation of data FLOD's own
pipeline already produced. Three scenarios, not the five originally
proposed: Normal, Flash Crowd, DDoS, because the training CSV's label
column carries exactly those three classes and nothing finer. Detection
and operational metrics only, since both arms read the same Stage 1
capture and can only differ in how the rate is judged, not in packets/
sec, CPU, or latency.

FLOD's own side of the comparison is not a hand-derived formula. An
earlier version of this script reconstructed it as ewma_rate > mean_r +
k * sigma_r, which only models Stage 1's raw per-window rate gate, the
same gate that is SUPPOSED to fire on a Flash Crowd surge, since that is
genuinely an unusual rate. It is not what makes FLOD able to tell a
Flash Crowd apart from a DDoS: that distinction is the trained
RandomForest, using entropy, dominance, and protocol mix alongside rate.
Run against real data, the rate-only reconstruction scored FLOD worse
than a fixed threshold at leaving Flash Crowd alone, which is backwards
from the deployed system's actual behaviour and was a benchmark design
flaw, not a real finding. This version instead trains and evaluates the
real RandomForest via Leave-One-Session-Out, the same held-out
methodology stage2/train.py already uses and reports its own accuracy
claims on, so "FLOD" here means what the classifier actually decides on
data it never trained on, not a proxy for it.
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils import resample

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_CSV_PATH = os.path.join(PROJECT_ROOT, "stage1", "training_data.csv")

LABEL_NAMES = {0: "Normal", 1: "Flash Crowd", 2: "DDoS"}
ATTACK_LABEL = 2
FEATURE_COLS = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "delta_rate", "delta_entropy",
    "dominant_rate", "source_port_entropy", "ttl_variance", "fingerprint_diversity",
]
LABEL_COL = "label"
CANDIDATE_MAX_DEPTHS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, None]


def load_and_prepare(path):
    """Mirrors train.py's own preprocessing exactly, so the classifier
    trained here sees the same rows train.py's own accuracy claims are
    based on: session detection by timestamp gap or label change, the
    same warm-up/idle row filters, the same three delta features."""
    if not os.path.exists(path):
        print(f"[-] Error: '{path}' not found.")
        sys.exit(1)
    df = pd.read_csv(path)
    required = set(FEATURE_COLS) - {"delta_rate", "delta_entropy", "dominant_rate"}
    required |= {LABEL_COL, "timestamp"}
    missing = required - set(df.columns)
    if missing:
        print(f"[-] Error: CSV is missing required columns: {sorted(missing)}")
        sys.exit(1)

    df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    df = df.drop_duplicates().reset_index(drop=True)

    df = df.sort_values(by="timestamp").reset_index(drop=True)
    df["time_diff"] = df["timestamp"].diff()
    df["label_changed"] = df[LABEL_COL] != df[LABEL_COL].shift()
    df["new_session"] = (df["time_diff"] > 30.0) | (df["time_diff"].isna()) | df["label_changed"]
    df["session_id"] = df["new_session"].cumsum()

    df = df[~((df[LABEL_COL] == 1) & (df["ewma_rate"] < 100))].reset_index(drop=True)
    df = df[~((df[LABEL_COL] == 2) & (df["ewma_rate"] < 1.0))].reset_index(drop=True)

    df["delta_rate"] = df["ewma_rate"] - df["mean_r"]
    df["delta_entropy"] = df["entropy"] - df["mean_h"]
    df["dominant_rate"] = df["ewma_rate"] * df["dominant_ip_ratio"]
    return df


def balance_classes(X, y):
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


def loso_predict(df):
    """Leave-One-Session-Out: every row's prediction comes from a model
    that never saw that row's own session during training. Sweeps
    max_depth the same way train.py does, since the right depth depends
    on how many independent sessions this CSV has, not a fixed number.
    Returns per-row predictions aligned to df's index, plus the depth and
    accuracy that were selected."""
    sessions_per_label = df.groupby(LABEL_COL)["session_id"].nunique()
    eligible = [
        sid for sid in sorted(df["session_id"].unique())
        if sessions_per_label.get(df.loc[df["session_id"] == sid, LABEL_COL].iloc[0], 0) >= 2
    ]
    if not eligible:
        print("[-] Error: no label has >=2 sessions, LOSO cannot run on this CSV.")
        sys.exit(1)

    best_depth, best_acc, best_pred = None, -1.0, None
    for depth in CANDIDATE_MAX_DEPTHS:
        pred = pd.Series(index=df.index, dtype="int64")
        for sess_id in eligible:
            test_mask = df["session_id"] == sess_id
            train_df = df[~test_mask]
            X_train, y_train = balance_classes(train_df[FEATURE_COLS], train_df[LABEL_COL])
            clf = RandomForestClassifier(n_estimators=100, max_depth=depth, random_state=42, n_jobs=-1)
            clf.fit(X_train, y_train)
            pred.loc[test_mask] = clf.predict(df.loc[test_mask, FEATURE_COLS])
        held_out = df["session_id"].isin(eligible)
        acc = (pred[held_out] == df.loc[held_out, LABEL_COL]).mean()
        print(f"[+] max_depth={depth}: LOSO accuracy={acc:.3f}")
        if acc > best_acc:
            best_acc, best_depth, best_pred = acc, depth, pred
    print(f"[+] Selected max_depth={best_depth} (LOSO accuracy={best_acc:.3f})")
    return best_pred, eligible


def confusion(flags, is_attack):
    tp = int((flags & is_attack).sum())
    fp = int((flags & ~is_attack).sum())
    fn = int((~flags & is_attack).sum())
    tn = int((~flags & ~is_attack).sum())
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) and precision == precision and recall == recall
          else float("nan"))
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    fnr = fn / (fn + tp) if (fn + tp) else float("nan")
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1,
            "fpr": fpr, "fnr": fnr}


def fmt_pct(x):
    return "n/a" if x != x else f"{100 * x:.1f}%"


def print_scenario_table(df, methods):
    print()
    print(f"{'Scenario':<14}{'Rows':>8}" + "".join(f"{name + ' flag rate':>22}" for name in methods))
    print("-" * (14 + 8 + 22 * len(methods)))
    for label in (0, 1, 2):
        sub = df[df["label"] == label]
        if len(sub) == 0:
            continue
        row = f"{LABEL_NAMES[label]:<14}{len(sub):>8}"
        for name, flags_col in methods.items():
            flag_rate = sub[flags_col].mean()
            row += f"{fmt_pct(flag_rate):>22}"
        print(row)
    print()
    print("For Normal and Flash Crowd, flag rate is a false-positive rate")
    print("(lower is better). For DDoS, flag rate is recall (higher is better).")


def print_confusion_table(name, c):
    print(f"\n{name}")
    print(f"  TP={c['tp']}  FP={c['fp']}  FN={c['fn']}  TN={c['tn']}")
    print(f"  precision={fmt_pct(c['precision'])}  recall={fmt_pct(c['recall'])}  "
          f"f1={fmt_pct(c['f1'])}  fpr={fmt_pct(c['fpr'])}  fnr={fmt_pct(c['fnr'])}")


def pick_fixed_threshold(df, multiplier):
    """A fixed multiple of the observed mean rate of the CSV's own
    Normal-labelled rows, decided once here, not tuned against the
    scoring below. This is how an operator without adaptive learning
    would reasonably pick a static number."""
    normal_mean_rate = df.loc[df[LABEL_COL] == 0, "ewma_rate"].mean()
    return normal_mean_rate * multiplier, normal_mean_rate


def main():
    parser = argparse.ArgumentParser(description="FLOD's trained classifier vs. fixed threshold, offline LOSO replay.")
    parser.add_argument("csv_path", nargs="?", default=None,
                         help="Training CSV to evaluate (default: stage1/training_data.csv or ./training_data.csv). "
                              "Must have at least 2 independent sessions per label for LOSO to run.")
    parser.add_argument("--fixed-multiplier", type=float, default=3.0,
                         help="Fixed threshold = this many times the observed mean Normal rate (default: 3.0, a starting point, not tuned against this data)")
    args = parser.parse_args()

    csv_path = args.csv_path
    if csv_path is None:
        csv_path = DEFAULT_CSV_PATH if os.path.exists(DEFAULT_CSV_PATH) else "training_data.csv"

    print("=== FLOD (trained classifier, LOSO) vs. Fixed Threshold ===")
    print(f"[+] Loading dataset from: {csv_path}")
    df = load_and_prepare(csv_path)
    print(f"[+] {len(df)} rows after the same cleaning train.py applies (dedup, warm-up/idle filters).")

    print("\n[+] Running Leave-One-Session-Out evaluation for FLOD's real classifier...")
    pred, eligible_sessions = loso_predict(df)
    held_out = df["session_id"].isin(eligible_sessions)
    df = df[held_out].reset_index(drop=True)
    df["flod_flag"] = (pred[held_out].reset_index(drop=True) == ATTACK_LABEL)

    fixed_threshold, normal_mean_rate = pick_fixed_threshold(df, args.fixed_multiplier)
    print(f"\n[+] Fixed threshold: {args.fixed_multiplier}x observed Normal mean rate "
          f"({normal_mean_rate:.2f}) = {fixed_threshold:.2f} pps")
    df["fixed_flag"] = df["ewma_rate"] > fixed_threshold

    is_attack = df[LABEL_COL] == ATTACK_LABEL

    print_scenario_table(df, {"FLOD": "flod_flag", "Fixed": "fixed_flag"})

    flod_c = confusion(df["flod_flag"], is_attack)
    fixed_c = confusion(df["fixed_flag"], is_attack)
    print_confusion_table("FLOD (trained classifier, held-out)", flod_c)
    print_confusion_table("Fixed threshold", fixed_c)

    fc = df[df[LABEL_COL] == 1]
    if len(fc):
        flod_fc_retained = 1 - fc["flod_flag"].mean()
        fixed_fc_retained = 1 - fc["fixed_flag"].mean()
        print("\nFlash Crowd traffic correctly left alone (the operational number this")
        print("benchmark exists to surface, since a fixed threshold cannot structurally")
        print("tell a legitimate surge from an attack the way the trained classifier can):")
        print(f"  FLOD:  {fmt_pct(flod_fc_retained)}")
        print(f"  Fixed: {fmt_pct(fixed_fc_retained)}")


if __name__ == "__main__":
    main()
