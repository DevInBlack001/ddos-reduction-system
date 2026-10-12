#!/usr/bin/env python3
"""Leave-One-Session-Out validation for the generalized-feature-scaling
experiment (branch experiment/generalized-training). Scales or shifts
only the held-out session per fold; training stays on real data. Test
rows are further restricted to generator-labeled ones (excludes
auto_label.py output), via set difference against the pre-autolabel-merge
CSV. History and full results: scratch/specs/2026-10-12-generalized-
feature-scaling-design.md.

Scenarios: k in {0.1, 1.0, 10, 50} scale ewma_rate/mean_r by k and sigma_r
by k**SIGMA_EXPONENT (CLI flag, brackets independent-sources vs. bursty
real traffic). entropy_stress compresses entropy toward 1.0
(new_entropy = 1 - (1-entropy)*ENTROPY_STRESS_COMPRESSION) rather than a
flat shift, since a flat shift mostly clips away for already-high entropy.
topology_stress applies apply_topology_shift() (see its own docstring).

PASS/FAIL rule, declared before running: portable's per-class F1 on a
scenario stays within F1_TOLERANCE of its own k=1.0 F1. local is reported
for contrast, not held to the rule.

--feature-sets picks which of local/portable/portable_no_ratez/
portable_no_<ablation column> to run. --models picks rf/if.
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report

LABEL_COL = "label"
TARGET_NAMES = ["Normal (0)", "Flash Crowd (1)", "DDoS (2)"]
FLASHCROWD_WARMUP_SECONDS = float(os.environ.get("FLOD_FLASHCROWD_WARMUP_SECONDS", "15"))
ENTROPY_STRESS_COMPRESSION = 0.3  # new_entropy = 1 - (1 - entropy) * this
F1_TOLERANCE = 0.05
FIXED_DEPTH = 5  # Not re-derived per scenario; see module docstring.
# Isolation Forest has no ground-truth training target and no LOSO-accuracy
# equivalent, so it is scored the same way the project's own earlier
# fixed-threshold benchmark scored it: DDoS outlier rate (want high) and
# benign (Normal+Flash Crowd) outlier rate (want low), not per-class F1.
# contamination is fixed here, not swept per scenario, same reasoning as
# FIXED_DEPTH for the RandomForest: tractable across the k-sweep. train_isolation_forest.py's
# own contamination sweep on this dataset has landed between 0.1 and 0.15
# historically; 0.1 is the starting point here.
FIXED_CONTAMINATION = 0.1
IF_RATE_TOLERANCE = 0.05

FEATURE_COLS_LOCAL = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "delta_rate", "delta_entropy",
    "dominant_rate", "source_port_entropy", "ttl_variance", "fingerprint_diversity",
]
FEATURE_COLS_PORTABLE = [
    "proto_ratio", "dominant_ip_ratio", "source_port_entropy",
    "ttl_variance", "fingerprint_diversity", "rate_z", "rate_ratio", "entropy_z",
]
# Ablation: does rate_z add anything beyond rate_ratio? Relevant if a
# RATE_Z_FLOOR_FRACTION sweep picks a very large value, since rate_z then
# degenerates into a rescaled rate_ratio.
FEATURE_COLS_PORTABLE_NO_RATEZ = [c for c in FEATURE_COLS_PORTABLE if c != "rate_z"]
# One-feature-at-a-time ablation for the five portable columns that are
# scale-free (independent of traffic volume) but NOT yet baseline-relative
# the way rate_z/rate_ratio/entropy_z are: Stage 1 has no per-site baseline
# for these yet, so they cannot be z-scored, only used raw. A feature the
# model leans on heavily here is a portability risk worth flagging, not
# proof it fails at a different site, since this is still only this lab's
# data under a synthetic scaling transform.
ABLATION_COLS = ["proto_ratio", "dominant_ip_ratio", "source_port_entropy", "ttl_variance", "fingerprint_diversity"]
ALL_FEATURE_SETS = {
    "local": FEATURE_COLS_LOCAL,
    "portable": FEATURE_COLS_PORTABLE,
    "portable_no_ratez": FEATURE_COLS_PORTABLE_NO_RATEZ,
}
for _col in ABLATION_COLS:
    ALL_FEATURE_SETS[f"portable_no_{_col}"] = [c for c in FEATURE_COLS_PORTABLE if c != _col]
RAW_JOIN_COLS = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "source_port_entropy", "ttl_variance",
    "fingerprint_diversity", "timestamp", LABEL_COL,
]

K_VALUES = [0.1, 10.0, 50.0]  # k=1.0 is the baseline, added once regardless of exponent (sigma_r unaffected at k=1.0)


def build_scenarios(sigma_exponents):
    """Training doesn't depend on sigma_exponent at all, only the held-out
    transform does, so bracketing multiple exponents (0.5/0.8/1.0) costs
    nothing extra in training time, only a few more predict() calls per
    fold. k=1.0 needs only one entry since sigma_r is unaffected there
    regardless of exponent."""
    scenarios = [("k=1.0 (unscaled LOSO baseline)", {"rate_factor": 1.0, "entropy_compression": 1.0, "sigma_exponent": 0.5, "topology_shift": False})]
    for exponent in sigma_exponents:
        for k in K_VALUES:
            name = f"k={k:g} (sigma^{exponent:g})" if len(sigma_exponents) > 1 else f"k={k:g}"
            scenarios.append((name, {"rate_factor": k, "entropy_compression": 1.0, "sigma_exponent": exponent, "topology_shift": False}))
    scenarios.append((
        "entropy_stress (k=1.0, entropy compressed toward ceiling, STRESS TEST not a simulation)",
        {"rate_factor": 1.0, "entropy_compression": ENTROPY_STRESS_COMPRESSION, "sigma_exponent": 0.5, "topology_shift": False},
    ))
    scenarios.append((
        "topology_stress (k=1.0, synthetic alternate-topology shift, HYPOTHESIS not a real second site)",
        {"rate_factor": 1.0, "entropy_compression": 1.0, "sigma_exponent": 0.5, "topology_shift": True},
    ))
    return scenarios


def balance_classes(X, y):
    train_df = X.copy()
    train_df[LABEL_COL] = y.values
    per_class = [train_df[train_df[LABEL_COL] == lbl] for lbl in (0, 1, 2)]
    per_class = [d for d in per_class if len(d) > 0]
    if len(per_class) < 2:
        return X, y
    max_size = max(len(d) for d in per_class)
    from sklearn.utils import resample
    upsampled = [resample(d, replace=True, n_samples=max_size, random_state=42) for d in per_class]
    balanced = pd.concat(upsampled, ignore_index=True)
    return balanced[X.columns], balanced[LABEL_COL]


def cap_ddos_for_if(train_df: pd.DataFrame) -> pd.DataFrame:
    """Same subsampling train_isolation_forest.py applies: IsolationForest's
    scoring assumes whatever it flags as anomalous is a minority of what it
    fits on, so DDoS is capped at the smaller benign class's size, by random
    sample, before fitting. Not balance_classes (no upsampling): IF pools
    every label, unbalanced, and only needs DDoS kept a minority."""
    benign_counts = train_df[train_df[LABEL_COL] != 2][LABEL_COL].value_counts()
    ddos_count = (train_df[LABEL_COL] == 2).sum()
    if len(benign_counts) == 0 or ddos_count <= benign_counts.min():
        return train_df
    ddos_cap = int(benign_counts.min())
    ddos_rows = train_df[train_df[LABEL_COL] == 2].sample(n=ddos_cap, random_state=42)
    return pd.concat([train_df[train_df[LABEL_COL] != 2], ddos_rows]).sort_index()


def apply_scenario(df: pd.DataFrame, rate_factor: float, entropy_compression: float, sigma_exponent: float = 0.5) -> pd.DataFrame:
    """Scale/compress the held-out rows only. Deterministic (no added
    noise): this script isolates the effect of the transform itself,
    scale_training_data.py covers the noisier whole-file stand-in
    separately. entropy_compression=1.0 is a no-op; <1.0 squeezes entropy
    toward the ceiling (1.0) rather than adding a flat constant that
    mostly clips away for already-high entropy, see module docstring."""
    df = df.copy()
    df["ewma_rate"] = df["ewma_rate"] * rate_factor
    df["mean_r"] = df["mean_r"] * rate_factor
    df["sigma_r"] = df["sigma_r"] * (rate_factor ** sigma_exponent)
    df["entropy"] = 1.0 - (1.0 - df["entropy"]) * entropy_compression
    return df


# Stated hypothesis for a larger, more heterogeneous site, declared
# before the ablation results, per-column factor applied to benign
# (Normal/Flash Crowd) and DDoS rows separately. Not a measured fact.
# ttl_variance and fingerprint_diversity are unbounded (clip at 0); the
# rest clip to [0, 1].
TOPOLOGY_SHIFT_FACTORS = {
    "ttl_variance": {"benign": 1.5, "ddos": 4.0, "bounded": False},
    "source_port_entropy": {"benign": 1.3, "ddos": 1.0, "bounded": True},
    "proto_ratio": {"benign": 0.8, "ddos": 1.0, "bounded": True},
    "dominant_ip_ratio": {"benign": 0.6, "ddos": 1.0, "bounded": True},
    "fingerprint_diversity": {"benign": 1.8, "ddos": 0.7, "bounded": False},
}


def apply_topology_shift(df: pd.DataFrame) -> pd.DataFrame:
    """Synthetic hypothesis, not a real site. See TOPOLOGY_SHIFT_FACTORS."""
    df = df.copy()
    is_ddos = df[LABEL_COL] == 2
    for col, cfg in TOPOLOGY_SHIFT_FACTORS.items():
        factor = np.where(is_ddos, cfg["ddos"], cfg["benign"])
        shifted = df[col] * factor
        df[col] = shifted.clip(0.0, 1.0) if cfg["bounded"] else shifted.clip(lower=0.0)
    return df


def add_derived_features(df: pd.DataFrame, rate_z_floor_fraction: float) -> pd.DataFrame:
    df = df.copy()
    df["delta_rate"] = df["ewma_rate"] - df["mean_r"]
    df["delta_entropy"] = df["entropy"] - df["mean_h"]
    df["dominant_rate"] = df["ewma_rate"] * df["dominant_ip_ratio"]
    sigma_eff = df["sigma_r"].clip(lower=rate_z_floor_fraction * df["mean_r"])
    df["rate_z"] = (df["ewma_rate"] - df["mean_r"]) / sigma_eff
    df["rate_ratio"] = df["ewma_rate"] / df["mean_r"]
    df["entropy_z"] = (df["entropy"] - df["mean_h"]) / df["sigma_h"]
    return df


def load_and_clean(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df = df.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    df = df.drop_duplicates().reset_index(drop=True)

    df = df.sort_values(by="timestamp").reset_index(drop=True)
    df["time_diff"] = df["timestamp"].diff()
    df["label_changed"] = df[LABEL_COL] != df[LABEL_COL].shift()
    df["new_session"] = (df["time_diff"] > 30.0) | (df["time_diff"].isna()) | df["label_changed"]
    df["session_id"] = df["new_session"].cumsum()

    session_start = df.groupby("session_id")["timestamp"].transform("min")
    elapsed = df["timestamp"] - session_start
    warmup_mask = (df[LABEL_COL] == 1) & (elapsed < FLASHCROWD_WARMUP_SECONDS)
    df = df[~warmup_mask].reset_index(drop=True)

    df = df[~((df[LABEL_COL] == 2) & (df["ewma_rate"] < 1.0))].reset_index(drop=True)
    return df


def mark_generator_labeled(df: pd.DataFrame, generator_csv: str) -> pd.DataFrame:
    gen = pd.read_csv(generator_csv).drop_duplicates()
    missing = [c for c in RAW_JOIN_COLS if c not in gen.columns or c not in df.columns]
    if missing:
        print(f"[-] Error: join columns missing from one of the two files: {missing}")
        sys.exit(1)
    gen_keys = gen[RAW_JOIN_COLS].drop_duplicates()
    gen_keys["_is_generator"] = True
    df = df.merge(gen_keys, on=RAW_JOIN_COLS, how="left")
    df["_is_generator"] = df["_is_generator"].fillna(False)
    return df


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("full_csv", help="The full training CSV (may include auto-labeled rows)")
    parser.add_argument("generator_csv", help="Pre-autolabel-merge CSV, used to identify generator-labeled rows")
    parser.add_argument(
        "--exclude-autolabel-from-training", action="store_true",
        help="Train only on generator-labeled rows too, instead of every row (default: use every row for training)",
    )
    parser.add_argument(
        "--feature-sets", default="local,portable",
        help="Comma-separated subset of local,portable,portable_no_ratez to run (default: local,portable). "
             "Skip local when sweeping a parameter (e.g. the floor fraction) that local doesn't use at all.",
    )
    parser.add_argument(
        "--sigma-exponents", default="0.5",
        help="Comma-separated exponent(s) applied to k for sigma_r's scaling (default: 0.5, central-limit/"
             "independent-sources assumption). Real traffic is more correlated, so the true exponent likely "
             "sits between 0.5 and 1.0; pass e.g. 0.5,0.8,1.0 to bracket it in one run, no retraining cost.",
    )
    parser.add_argument(
        "--rate-z-floor-fraction", type=float,
        default=float(os.environ.get("FLOD_RATE_Z_FLOOR_FRACTION", "0.05")),
        help="RATE_Z_FLOOR_FRACTION for rate_z's relative floor (default: 0.05, or $FLOD_RATE_Z_FLOOR_FRACTION).",
    )
    parser.add_argument(
        "--models", default="rf,if",
        help="Comma-separated subset of rf,if to run (default: rf,if). Both models are trained on the "
             "SAME feature set per train_isolation_forest.py's own stated parity with train.py.",
    )
    args = parser.parse_args()
    model_names = args.models.split(",")
    unknown_models = [m for m in model_names if m not in ("rf", "if")]
    if unknown_models:
        print(f"[-] Error: unknown model(s) {unknown_models}, choose from rf, if")
        sys.exit(1)

    feature_set_names = args.feature_sets.split(",")
    unknown = [n for n in feature_set_names if n not in ALL_FEATURE_SETS]
    if unknown:
        print(f"[-] Error: unknown feature set(s) {unknown}, choose from {list(ALL_FEATURE_SETS)}")
        sys.exit(1)
    sigma_exponents = [float(x) for x in args.sigma_exponents.split(",")]
    SCENARIOS = build_scenarios(sigma_exponents)

    print(f"[+] PASS/FAIL RULE (declared before running): portable per-class F1 on a scaled "
          f"scenario must stay within {F1_TOLERANCE} of portable's own k=1.0 per-class F1. "
          "local is reported for contrast only, not held to this rule.")
    print(f"[+] Fixed max_depth={FIXED_DEPTH} for every scenario (not re-derived per scenario, see docstring).")
    print(f"[+] sigma_exponents={sigma_exponents}, rate_z_floor_fraction={args.rate_z_floor_fraction}, "
          f"feature_sets={feature_set_names}")

    print(f"\n[+] Loading full dataset from: {args.full_csv}")
    df = load_and_clean(args.full_csv)
    print(f"[+] {len(df)} rows after cleaning.")

    print(f"[+] Loading generator-only dataset from: {args.generator_csv}")
    df = mark_generator_labeled(df, args.generator_csv)
    gen_count = df["_is_generator"].sum()
    print(f"[+] {gen_count} / {len(df)} rows are generator-labeled (not auto_label.py-derived).")

    sessions_per_label = df.groupby(LABEL_COL)["session_id"].nunique()
    all_sessions = sorted(df["session_id"].unique())
    eligible_sessions = []
    for sess_id in all_sessions:
        sess_df = df[df["session_id"] == sess_id]
        label = sess_df[LABEL_COL].iloc[0]
        gen_rows_in_session = sess_df["_is_generator"].sum()
        if sessions_per_label.get(label, 0) < 2:
            print(f"[!] Session {sess_id} (label {label}): SKIPPED, only session for this label.")
        elif gen_rows_in_session == 0:
            print(f"[!] Session {sess_id} (label {label}): SKIPPED, zero generator-labeled rows to "
                  "evaluate on (all auto-labeled).")
        else:
            eligible_sessions.append(sess_id)
    print(f"[+] {len(eligible_sessions)} / {len(all_sessions)} sessions eligible for LOSO evaluation.")

    results = {}  # (feature_set, scenario_name) -> (y_true, y_pred), RandomForest
    if_results = {}  # (feature_set, scenario_name) -> (y_true, is_outlier), IsolationForest
    for feature_set in feature_set_names:
        feature_cols = ALL_FEATURE_SETS[feature_set]
        print(f"\n[+] ===== Feature set: {feature_set} =====")
        for scenario_name, params in SCENARIOS:
            results[(feature_set, scenario_name)] = ([], [])
            if_results[(feature_set, scenario_name)] = ([], [])

        for sess_id in eligible_sessions:
            if args.exclude_autolabel_from_training:
                train_df = df[(df["session_id"] != sess_id) & (df["_is_generator"])]
            else:
                train_df = df[df["session_id"] != sess_id]
            train_df = add_derived_features(train_df, args.rate_z_floor_fraction)

            held_out = df[(df["session_id"] == sess_id) & (df["_is_generator"])]

            clf = None
            if "rf" in model_names:
                X_train, y_train = balance_classes(train_df[feature_cols], train_df[LABEL_COL])
                clf = RandomForestClassifier(n_estimators=100, max_depth=FIXED_DEPTH, random_state=42, n_jobs=-1)
                clf.fit(X_train, y_train)

            if_clf = None
            if "if" in model_names:
                if_train_df = cap_ddos_for_if(train_df)
                if_clf = IsolationForest(contamination=FIXED_CONTAMINATION, random_state=42, n_jobs=-1)
                if_clf.fit(if_train_df[feature_cols])

            for scenario_name, params in SCENARIOS:
                scaled = apply_scenario(held_out, params["rate_factor"], params["entropy_compression"], params["sigma_exponent"])
                if params.get("topology_shift"):
                    scaled = apply_topology_shift(scaled)
                scaled = add_derived_features(scaled, args.rate_z_floor_fraction)

                if clf is not None:
                    y_pred = clf.predict(scaled[feature_cols])
                    y_true_list, y_pred_list = results[(feature_set, scenario_name)]
                    y_true_list.extend(scaled[LABEL_COL].tolist())
                    y_pred_list.extend(y_pred.tolist())

                if if_clf is not None:
                    is_outlier = if_clf.predict(scaled[feature_cols]) == -1
                    y_true_list, outlier_list = if_results[(feature_set, scenario_name)]
                    y_true_list.extend(scaled[LABEL_COL].tolist())
                    outlier_list.extend(is_outlier.tolist())

            print(f"[+] Session {sess_id} done, {len(held_out)} generator-labeled held-out rows.")

    print("\n\n== Results ==")
    f1_by_scenario = {}
    for feature_set in feature_set_names:
        for scenario_name, _ in SCENARIOS:
            y_true, y_pred = results[(feature_set, scenario_name)]
            if not y_true:
                print(f"\n[{feature_set} / {scenario_name}] no evaluable rows, skipped.")
                continue
            report = classification_report(
                y_true, y_pred, target_names=TARGET_NAMES, output_dict=True, zero_division=0
            )
            print(f"\n[{feature_set} / {scenario_name}] ({len(y_true)} rows)")
            print(classification_report(y_true, y_pred, target_names=TARGET_NAMES, zero_division=0))
            f1_by_scenario[(feature_set, scenario_name)] = {
                name: report[name]["f1-score"] for name in TARGET_NAMES
            }

    for feature_set in feature_set_names:
        if not feature_set.startswith("portable"):
            continue
        baseline_key = (feature_set, "k=1.0 (unscaled LOSO baseline)")
        if baseline_key not in f1_by_scenario:
            continue
        baseline_f1 = f1_by_scenario[baseline_key]
        print(f"\n== PASS/FAIL against the rule declared above ({feature_set}, baseline={baseline_key[1]}) ==")
        for scenario_name, _ in SCENARIOS:
            key = (feature_set, scenario_name)
            if key not in f1_by_scenario or scenario_name == baseline_key[1]:
                continue
            for cls in TARGET_NAMES:
                delta = f1_by_scenario[key][cls] - baseline_f1[cls]
                verdict = "PASS" if abs(delta) <= F1_TOLERANCE else "FAIL"
                print(f"  [{verdict}] {scenario_name} / {cls}: F1={f1_by_scenario[key][cls]:.3f} "
                      f"(baseline={baseline_f1[cls]:.3f}, delta={delta:+.3f})")

    if "if" in model_names:
        print("\n\n== Isolation Forest Results (DDoS outlier rate high is good, benign outlier rate low is good) ==")
        rates_by_scenario = {}
        for feature_set in feature_set_names:
            for scenario_name, _ in SCENARIOS:
                y_true, is_outlier = if_results[(feature_set, scenario_name)]
                if not y_true:
                    print(f"\n[{feature_set} / {scenario_name}] no evaluable rows, skipped.")
                    continue
                y_true_arr = np.array(y_true)
                outlier_arr = np.array(is_outlier)
                ddos_mask = y_true_arr == 2
                benign_mask = ~ddos_mask
                ddos_rate = float(outlier_arr[ddos_mask].mean()) if ddos_mask.any() else float("nan")
                benign_rate = float(outlier_arr[benign_mask].mean()) if benign_mask.any() else float("nan")
                print(f"[{feature_set} / {scenario_name}] ({len(y_true)} rows) "
                      f"DDoS outlier rate={ddos_rate:.3f}, benign outlier rate={benign_rate:.3f}")
                rates_by_scenario[(feature_set, scenario_name)] = {"ddos": ddos_rate, "benign": benign_rate}

        for feature_set in feature_set_names:
            if not feature_set.startswith("portable"):
                continue
            baseline_key = (feature_set, "k=1.0 (unscaled LOSO baseline)")
            if baseline_key not in rates_by_scenario:
                continue
            baseline_rates = rates_by_scenario[baseline_key]
            print(f"\n== Isolation Forest PASS/FAIL ({feature_set}, baseline={baseline_key[1]}, "
                  f"tolerance={IF_RATE_TOLERANCE}) ==")
            for scenario_name, _ in SCENARIOS:
                key = (feature_set, scenario_name)
                if key not in rates_by_scenario or scenario_name == baseline_key[1]:
                    continue
                for rate_name in ("ddos", "benign"):
                    delta = rates_by_scenario[key][rate_name] - baseline_rates[rate_name]
                    verdict = "PASS" if abs(delta) <= IF_RATE_TOLERANCE else "FAIL"
                    print(f"  [{verdict}] {scenario_name} / {rate_name} outlier rate: "
                          f"{rates_by_scenario[key][rate_name]:.3f} "
                          f"(baseline={baseline_rates[rate_name]:.3f}, delta={delta:+.3f})")


if __name__ == "__main__":
    main()
