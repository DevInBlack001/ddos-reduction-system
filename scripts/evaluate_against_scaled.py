#!/usr/bin/env python3
"""Score an already-trained model against a held-out CSV it never trained
on, for the generalized-feature-scaling experiment
(branch experiment/generalized-training).

Computes the same derived features train.py computes (delta_rate,
delta_entropy, dominant_rate, rate_z, rate_ratio, entropy_z), selects the
feature set (local or portable) the model was trained with, predicts, and
reports precision/recall/F1 per class plus the confusion matrix. See
scratch/specs/2026-10-12-generalized-feature-scaling-design.md, Validation
plan, steps 4-5.
"""

import argparse
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

FEATURE_COLS_LOCAL = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "delta_rate", "delta_entropy",
    "dominant_rate", "source_port_entropy", "ttl_variance", "fingerprint_diversity",
]
# Raw entropy deliberately excluded: "scale-free" (independent of traffic
# volume) is not the same claim as "portable" (independent of site).
# entropy_z, not raw entropy, is relative to this target's own baseline.
FEATURE_COLS_PORTABLE = [
    "proto_ratio", "dominant_ip_ratio", "source_port_entropy",
    "ttl_variance", "fingerprint_diversity", "rate_z", "rate_ratio", "entropy_z",
]
LABEL_COL = "label"
TARGET_NAMES = ["Normal (0)", "Flash Crowd (1)", "DDoS (2)"]
# Same relative floor as train.py's RATE_Z_FLOOR_FRACTION.
RATE_Z_FLOOR_FRACTION = float(os.environ.get("FLOD_RATE_Z_FLOOR_FRACTION", "0.05"))


def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["delta_rate"] = df["ewma_rate"] - df["mean_r"]
    df["delta_entropy"] = df["entropy"] - df["mean_h"]
    df["dominant_rate"] = df["ewma_rate"] * df["dominant_ip_ratio"]
    unsafe = (df["sigma_r"] <= 0) | (df["sigma_h"] <= 0) | (df["mean_r"] <= 0)
    if unsafe.sum() > 0:
        print(f"[!] Dropping {unsafe.sum()} rows with non-positive sigma_r/sigma_h/mean_r.")
    df = df[~unsafe].reset_index(drop=True)
    sigma_eff = df["sigma_r"].clip(lower=RATE_Z_FLOOR_FRACTION * df["mean_r"])
    df["rate_z"] = (df["ewma_rate"] - df["mean_r"]) / sigma_eff
    df["rate_ratio"] = df["ewma_rate"] / df["mean_r"]
    df["entropy_z"] = (df["entropy"] - df["mean_h"]) / df["sigma_h"]
    return df


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model_path", help="Path to a .joblib model from train.py")
    parser.add_argument("eval_csv", help="Held-out CSV to score the model against")
    parser.add_argument(
        "--feature-set", choices=["local", "portable"], default="local",
        help="Which feature set the model was trained with (default: local)",
    )
    args = parser.parse_args()

    feature_cols = FEATURE_COLS_PORTABLE if args.feature_set == "portable" else FEATURE_COLS_LOCAL

    print(f"[+] Loading model from: {args.model_path}")
    clf = joblib.load(args.model_path)

    print(f"[+] Loading held-out CSV from: {args.eval_csv}")
    df = pd.read_csv(args.eval_csv)
    df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    df = add_derived_features(df)

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        print(f"[-] Error: eval CSV is missing column(s): {', '.join(missing)}")
        sys.exit(1)

    X = df[feature_cols]
    y_true = df[LABEL_COL]
    y_pred = clf.predict(X)

    print(f"\n[+] Feature set: {args.feature_set} ({len(feature_cols)} features: {', '.join(feature_cols)})")
    print(f"[+] Scored {len(df)} held-out rows.")
    print("\n== Classification Report (held-out, never trained on) ==")
    print(classification_report(y_true, y_pred, target_names=TARGET_NAMES, zero_division=0))
    print("== Confusion Matrix ==")
    print(confusion_matrix(y_true, y_pred))


if __name__ == "__main__":
    main()
