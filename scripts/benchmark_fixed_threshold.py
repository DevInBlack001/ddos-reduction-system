#!/usr/bin/env python3
"""
benchmark_fixed_threshold.py: FLOD (both trained models) vs. a fixed rate
threshold, evaluated offline against an already-captured training CSV.

Scope, decided in CLAUDE.md before this script existed: fixed threshold
only this pass, not the XDP rate limiter or ML-only arms, since those are
new systems and this one is a pure reinterpretation of data FLOD's own
pipeline already produced. Three scenarios, not the five originally
proposed: Normal, Flash Crowd, DDoS, because the training CSV's label
column carries exactly those three classes and nothing finer.

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

Also covers the Isolation Forest and real performance numbers, both
absent from the first version. The Isolation Forest's own training
script, train_isolation_forest.py, evaluates itself on the same data it
trained on, which is the only option available to it in production (it
is unsupervised, there is no held-out label to score against there), but
a benchmark can and should hold it to the same standard as the
RandomForest: LOSO, fit on every session but one, scored on the one held
out. Sweeping the contamination hyperparameter itself inside every LOSO
fold would multiply the cost by the number of candidate values for a
refinement that does not change the story, so contamination is chosen
once against the full dataset first, the same way train_isolation_forest.py
already does it, and only the resulting single value is then evaluated
under LOSO. The chosen value is a hyperparameter pick, not a claim; the
LOSO evaluation of it is the part that is genuinely held out.

Performance here means what this script can measure honestly from a CSV
replay: training wall time, prediction latency, and serialized model
size for both real models. It does not mean packets/sec, Gbps, or Stage 1
CPU overhead, none of which a CSV replay can produce; those need a live
traffic phase and belong with the XDP rate limiter comparison this
project has already deferred to a later phase.
"""

import argparse
import io
import os
import resource
import shutil
import sys
import time
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils import resample

# See stage2/train.py's matching comment: n_jobs=-1 below triggers a
# cosmetic sklearn/joblib warning about config propagation that doesn't
# apply here, since nothing in this script touches sklearn's global config.
warnings.filterwarnings(
    "ignore",
    message=r".*should be used with `sklearn\.utils\.parallel\.Parallel`.*",
    category=UserWarning,
)

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
# Matches train_isolation_forest.py's own constants exactly.
BENIGN_OUTLIER_RATE_CAP = 0.05
CANDIDATE_CONTAMINATIONS = [0.01, 0.02, 0.05, 0.075, 0.1, 0.15, 0.2, 0.25]


class PhaseTracker:
    """CPU time and memory high-water mark, measured from this process's
    own accounting (the standard-library resource module), not an
    external sampler polling over SSH. utime/stime accumulate
    monotonically, so a before/after delta gives exact CPU time for
    exactly the phase in between; ru_maxrss is a whole-process high-water
    mark that only ever grows, so a phase's own reading is the mark
    up to and including that phase, not an isolated peak for it alone,
    reported as such rather than overstated as more precise than it is.
    Disk usage is checked once at the very start and once at the end:
    this workload writes at most a few hundred KB of model files, so a
    per-phase disk trace would not show anything a single before/after
    reading does not already cover.
    """

    def __init__(self):
        self.phases = []
        self._wall0 = time.perf_counter()
        self._start_usage = resource.getrusage(resource.RUSAGE_SELF)
        self._disk_start = shutil.disk_usage(SCRIPT_DIR)

    def mark(self, name):
        wall = time.perf_counter() - self._wall0
        usage = resource.getrusage(resource.RUSAGE_SELF)
        cpu_total = usage.ru_utime + usage.ru_stime
        prev_wall = self.phases[-1][1] if self.phases else 0.0
        prev_cpu = self.phases[-1][2] if self.phases else 0.0
        self.phases.append((name, wall, cpu_total, usage.ru_maxrss / 1024))
        return {
            "phase_wall_seconds": wall - prev_wall,
            "phase_cpu_seconds": cpu_total - prev_cpu,
            "peak_rss_mb_so_far": usage.ru_maxrss / 1024,
        }

    def report(self):
        print("\n=== System Resource Usage ===")
        print("Measured from this process's own CPU accounting (getrusage), not an")
        print("external sampler. Peak RSS is a whole-process high-water mark: each")
        print("phase's figure is the peak up to and including that phase, not an")
        print("isolated reading for it alone.\n")
        header = f"{'Phase':<32}{'Wall':>10}{'CPU':>10}{'Cores~':>8}{'Peak RSS':>12}"
        print(header)
        print("-" * len(header))
        prev_wall, prev_cpu = 0.0, 0.0
        for name, wall, cpu, rss_mb in self.phases:
            phase_wall = wall - prev_wall
            phase_cpu = cpu - prev_cpu
            # Below ~0.5s wall time, getrusage's own sampling granularity
            # makes a CPU/wall ratio noise, not a reading. Shown as n/a
            # rather than a plausible-looking but meaningless number.
            cores = f"{phase_cpu / phase_wall:.1f}" if phase_wall > 0.5 else "n/a"
            print(f"{name:<32}{phase_wall:>9.1f}s{phase_cpu:>9.1f}s{cores:>8}{rss_mb:>10.0f} MB")
            prev_wall, prev_cpu = wall, cpu
        total_wall = self.phases[-1][1] if self.phases else 0.0
        total_cpu = self.phases[-1][2] if self.phases else 0.0
        print("-" * len(header))
        print(f"{'total':<32}{total_wall:>9.1f}s{total_cpu:>9.1f}s"
              f"{(total_cpu / total_wall if total_wall > 0 else 0.0):>8.1f}"
              f"{self.phases[-1][3] if self.phases else 0.0:>10.0f} MB")

        disk_end = shutil.disk_usage(SCRIPT_DIR)
        used_delta_kb = (disk_end.used - self._disk_start.used) / 1024
        print(f"\nDisk: {used_delta_kb:+.0f} KB used over the run "
              f"({disk_end.free / (1024**3):.1f} GB free at the end). This workload's own "
              "footprint is a few hundred KB of model files; a swing much larger than "
              "that reflects something else on the host, not this script.")


def load_and_prepare(path):
    """Mirrors train.py's own preprocessing exactly, so the classifiers
    evaluated here see the same rows train.py's own accuracy claims are
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


def eligible_sessions(df):
    sessions_per_label = df.groupby(LABEL_COL)["session_id"].nunique()
    return [
        sid for sid in sorted(df["session_id"].unique())
        if sessions_per_label.get(df.loc[df["session_id"] == sid, LABEL_COL].iloc[0], 0) >= 2
    ]


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


def rf_loso(df, eligible):
    """Leave-One-Session-Out for the RandomForest: every row's prediction
    comes from a model that never saw that row's own session during
    training. Sweeps max_depth the same way train.py does, since the
    right depth depends on how many independent sessions this CSV has,
    not a fixed number."""
    best_depth, best_acc, best_pred = None, -1.0, None
    t0 = time.perf_counter()
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
    sweep_seconds = time.perf_counter() - t0
    print(f"[+] Selected max_depth={best_depth} (LOSO accuracy={best_acc:.3f})")
    return best_pred, best_depth, best_acc, sweep_seconds


def if_pick_contamination(df):
    """Same selection as train_isolation_forest.py: fit on the full
    dataset once per candidate, no LOSO here, since this step is picking
    a hyperparameter, not making a generalization claim. The LOSO
    evaluation of whichever value this picks is a separate step below."""
    X = df[FEATURE_COLS]
    is_ddos = (df[LABEL_COL] == 2).to_numpy()
    best_contamination, best_sep = None, None
    least_noisy_contamination, least_noisy_rate = None, None
    for contamination in CANDIDATE_CONTAMINATIONS:
        clf = IsolationForest(n_estimators=100, contamination=contamination, random_state=42, n_jobs=-1)
        clf.fit(X)
        outlier = clf.predict(X) == -1
        ddos_rate = outlier[is_ddos].mean()
        benign_rate = outlier[~is_ddos].mean()
        separation = ddos_rate - benign_rate
        within_cap = benign_rate <= BENIGN_OUTLIER_RATE_CAP
        print(f"[+] contamination={contamination}: DDoS outlier rate={ddos_rate:.1%}, "
              f"benign outlier rate={benign_rate:.1%}, separation={separation:+.3f}"
              f"{'' if within_cap else ' (over the benign cap, not eligible)'}")
        if within_cap and (best_sep is None or separation > best_sep):
            best_sep, best_contamination = separation, contamination
        if least_noisy_rate is None or benign_rate < least_noisy_rate:
            least_noisy_rate, least_noisy_contamination = benign_rate, contamination
    if best_contamination is None:
        print(f"[!] No candidate kept the benign outlier rate at or below "
              f"{BENIGN_OUTLIER_RATE_CAP:.0%}. Falling back to contamination="
              f"{least_noisy_contamination} (lowest benign outlier rate, {least_noisy_rate:.1%}).")
        return least_noisy_contamination, None
    print(f"[+] Selected contamination={best_contamination} (separation={best_sep:+.3f})")
    return best_contamination, best_sep


def if_loso(df, eligible, contamination):
    """Leave-One-Session-Out for the Isolation Forest, at a single,
    already-chosen contamination: fit on every session but one, score
    the one held out. Unlike train_isolation_forest.py's own reported
    outlier rate, which is measured on the same data the model trained
    on, this is a genuine held-out reading."""
    outlier = pd.Series(index=df.index, dtype="bool")
    t0 = time.perf_counter()
    for sess_id in eligible:
        test_mask = df["session_id"] == sess_id
        train_df = df[~test_mask]
        clf = IsolationForest(n_estimators=100, contamination=contamination, random_state=42, n_jobs=-1)
        clf.fit(train_df[FEATURE_COLS])
        outlier.loc[test_mask] = clf.predict(df.loc[test_mask, FEATURE_COLS]) == -1
    loso_seconds = time.perf_counter() - t0
    return outlier, loso_seconds


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
    print("(lower is better). For DDoS, flag rate is recall or outlier rate")
    print("(higher is better).")


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


def model_size_kb(fitted_model):
    """Serialized size of a fitted model, the same bytes that would land
    on disk as the .joblib file this project actually deploys, measured
    in memory rather than via a throwaway file."""
    buf = io.BytesIO()
    joblib.dump(fitted_model, buf)
    return len(buf.getvalue()) / 1024


def measure_performance(df, rf_depth, if_contamination):
    """Trains one production-shaped copy of each model on the full
    dataset, the same shape of fit stage2/train.py and
    train_isolation_forest.py do for the model that actually ships, and
    times it plus prediction over the full dataset. This is deliberately
    separate from the LOSO sweeps above, which exist to select a
    hyperparameter and evaluate generalisation, not to represent
    real-world training or inference cost."""
    results = {}

    X_train, y_train = balance_classes(df[FEATURE_COLS], df[LABEL_COL])
    t0 = time.perf_counter()
    rf = RandomForestClassifier(n_estimators=100, max_depth=rf_depth, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_fit_seconds = time.perf_counter() - t0

    n_predict = len(df)
    t0 = time.perf_counter()
    rf.predict(df[FEATURE_COLS])
    rf_predict_seconds = time.perf_counter() - t0

    results["rf"] = {
        "fit_seconds": rf_fit_seconds,
        "fit_rows": len(X_train),
        "predict_seconds": rf_predict_seconds,
        "predict_rows": n_predict,
        "rows_per_second": n_predict / rf_predict_seconds if rf_predict_seconds > 0 else float("inf"),
        "size_kb": model_size_kb(rf),
    }

    t0 = time.perf_counter()
    isof = IsolationForest(n_estimators=100, contamination=if_contamination, random_state=42, n_jobs=-1)
    isof.fit(df[FEATURE_COLS])
    if_fit_seconds = time.perf_counter() - t0

    t0 = time.perf_counter()
    isof.predict(df[FEATURE_COLS])
    if_predict_seconds = time.perf_counter() - t0

    results["if"] = {
        "fit_seconds": if_fit_seconds,
        "fit_rows": len(df),
        "predict_seconds": if_predict_seconds,
        "predict_rows": n_predict,
        "rows_per_second": n_predict / if_predict_seconds if if_predict_seconds > 0 else float("inf"),
        "size_kb": model_size_kb(isof),
    }
    return results


def print_performance_report(perf, rf_sweep_seconds, if_loso_seconds):
    print("\n=== Performance ===")
    print("Training and prediction cost of a production-shaped fit on the full")
    print("dataset (not the LOSO sweeps above, which exist to pick a hyperparameter")
    print("and measure generalisation, not real-world cost). This is CSV-replay")
    print("cost only: packets/sec, Gbps, and Stage 1 overhead need a live traffic")
    print("phase and are out of reach of this script by construction.\n")
    for name, key in (("RandomForest", "rf"), ("Isolation Forest", "if")):
        p = perf[key]
        print(f"{name}:")
        print(f"  fit:     {p['fit_seconds']:.2f}s on {p['fit_rows']} rows")
        print(f"  predict: {p['predict_seconds']:.3f}s on {p['predict_rows']} rows "
              f"({p['rows_per_second']:.0f} rows/sec, "
              f"{1000 * p['predict_seconds'] / p['predict_rows']:.3f} ms/row)")
        print(f"  model size on disk: {p['size_kb']:.1f} KB")
        print()
    print(f"RandomForest LOSO depth sweep (11 depths, evaluation only): {rf_sweep_seconds:.1f}s")
    print(f"Isolation Forest LOSO evaluation (1 contamination, evaluation only): {if_loso_seconds:.1f}s")


def main():
    parser = argparse.ArgumentParser(description="FLOD (RandomForest + Isolation Forest) vs. fixed threshold, offline LOSO replay.")
    parser.add_argument("csv_path", nargs="?", default=None,
                         help="Training CSV to evaluate (default: stage1/training_data.csv or ./training_data.csv). "
                              "Must have at least 2 independent sessions per label for LOSO to run.")
    parser.add_argument("--fixed-multiplier", type=float, default=3.0,
                         help="Fixed threshold = this many times the observed mean Normal rate (default: 3.0, a starting point, not tuned against this data)")
    args = parser.parse_args()

    csv_path = args.csv_path
    if csv_path is None:
        csv_path = DEFAULT_CSV_PATH if os.path.exists(DEFAULT_CSV_PATH) else "training_data.csv"

    tracker = PhaseTracker()

    print("=== FLOD (trained classifiers, LOSO) vs. Fixed Threshold ===")
    print(f"[+] Loading dataset from: {csv_path}")
    df = load_and_prepare(csv_path)
    print(f"[+] {len(df)} rows after the same cleaning train.py applies (dedup, warm-up/idle filters).")
    tracker.mark("load and prepare")

    eligible = eligible_sessions(df)
    if not eligible:
        print("[-] Error: no label has >=2 sessions, LOSO cannot run on this CSV.")
        sys.exit(1)

    print("\n--- RandomForest: Leave-One-Session-Out ---")
    rf_pred, rf_depth, rf_acc, rf_sweep_seconds = rf_loso(df, eligible)
    tracker.mark("RandomForest LOSO sweep")

    print("\n--- Isolation Forest: picking contamination on the full dataset ---")
    if_contamination, if_sep = if_pick_contamination(df)
    tracker.mark("Isolation Forest contamination pick")
    print("\n--- Isolation Forest: Leave-One-Session-Out at the selected contamination ---")
    if_outlier, if_loso_seconds = if_loso(df, eligible, if_contamination)
    tracker.mark("Isolation Forest LOSO")

    held_out = df["session_id"].isin(eligible)
    df = df[held_out].reset_index(drop=True)
    df["rf_class"] = rf_pred[held_out].reset_index(drop=True)
    df["flod_flag"] = df["rf_class"] == ATTACK_LABEL
    df["if_flag"] = if_outlier[held_out].reset_index(drop=True)

    print("\n=== RandomForest: full 3-class LOSO report ===")
    print(classification_report(df[LABEL_COL], df["rf_class"],
                                 target_names=["Normal (0)", "Flash Crowd (1)", "DDoS (2)"],
                                 zero_division=0))
    print("Confusion matrix:")
    print(confusion_matrix(df[LABEL_COL], df["rf_class"]))

    print("\n=== Isolation Forest: outlier rate by scenario (held out) ===")
    print(f"Selected contamination={if_contamination}"
          + (f", full-dataset separation={if_sep:+.3f}" if if_sep is not None else ""))
    for label in (0, 1, 2):
        sub = df[df[LABEL_COL] == label]
        if len(sub) == 0:
            continue
        print(f"  {LABEL_NAMES[label]:<12} {sub['if_flag'].mean():.1%} of {len(sub)} rows flagged as outliers")
    print("This is not a DDoS/not-DDoS decision, the Isolation Forest was never")
    print("trained to make one; it flags traffic unlike anything in training,")
    print("attack or benign. The binary view below treats an outlier flag as a")
    print("DDoS vote purely to give it a comparable number against the fixed")
    print("threshold, which is a narrower question than what it is actually for.")

    fixed_threshold, normal_mean_rate = pick_fixed_threshold(df, args.fixed_multiplier)
    print(f"\n[+] Fixed threshold: {args.fixed_multiplier}x observed Normal mean rate "
          f"({normal_mean_rate:.2f}) = {fixed_threshold:.2f} pps")
    df["fixed_flag"] = df["ewma_rate"] > fixed_threshold

    is_attack = df[LABEL_COL] == ATTACK_LABEL

    print("\n=== Detection comparison: RandomForest vs. Isolation Forest vs. Fixed threshold ===")
    print_scenario_table(df, {"RandomForest": "flod_flag", "Isolation Forest": "if_flag", "Fixed": "fixed_flag"})

    rf_c = confusion(df["flod_flag"], is_attack)
    if_c = confusion(df["if_flag"], is_attack)
    fixed_c = confusion(df["fixed_flag"], is_attack)
    print_confusion_table("RandomForest (trained classifier, held-out)", rf_c)
    print_confusion_table("Isolation Forest (held-out, outlier-as-DDoS-vote)", if_c)
    print_confusion_table("Fixed threshold", fixed_c)

    fc = df[df[LABEL_COL] == 1]
    if len(fc):
        print("\nFlash Crowd traffic correctly left alone (the operational number this")
        print("benchmark exists to surface, since a fixed threshold cannot structurally")
        print("tell a legitimate surge from an attack the way the trained models can):")
        print(f"  RandomForest:      {fmt_pct(1 - fc['flod_flag'].mean())}")
        print(f"  Isolation Forest:  {fmt_pct(1 - fc['if_flag'].mean())}")
        print(f"  Fixed threshold:   {fmt_pct(1 - fc['fixed_flag'].mean())}")

    print("\n--- Measuring production-shaped training and prediction performance ---")
    perf = measure_performance(df, rf_depth, if_contamination)
    tracker.mark("production-shaped fit and predict")
    print_performance_report(perf, rf_sweep_seconds, if_loso_seconds)
    tracker.report()


if __name__ == "__main__":
    main()
