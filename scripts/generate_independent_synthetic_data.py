#!/usr/bin/env python3
"""Generate a standalone synthetic dataset, parameters chosen
independently of this lab's measured data (no fitting, no derivation
from real captures). NOT REAL, NOT ANY ACTUAL INSTITUTION; a directional
sanity check only. Schema matches training_data.csv. mean_r/sigma_r/
mean_h/sigma_h are a slowly-drifting learned baseline, matching how a
real Welford baseline behaves.

Four DDoS archetypes, mixed within the DDoS class:
  concentrated:  one dominant source, low entropy, high dominant_ip_ratio.
  distributed:   spoofed/many-source, high entropy, low dominant_ip_ratio.
  low_rate:      stealth flood, modest rate, concentrated signature.
  protocol_syn:  SYN-flood-shaped, proto_ratio skewed TCP, low
                 fingerprint_diversity.
"""

import argparse

import numpy as np
import pandas as pd

LABEL_COL = "label"
RAW_COLS = [
    "entropy", "ewma_rate", "mean_h", "mean_r", "sigma_h", "sigma_r",
    "proto_ratio", "dominant_ip_ratio", "source_port_entropy", "ttl_variance",
    "fingerprint_diversity", "timestamp", LABEL_COL,
]

# Independently chosen baseline for this hypothetical larger institution.
# Not fit to this lab's data in any way; see module docstring.
BASELINE = {
    "mean_r": 5000.0, "sigma_r": 400.0,
    "mean_h": 0.75, "sigma_h": 0.12,
    "proto_ratio": 0.65, "dominant_ip_ratio": 0.08,
    "source_port_entropy": 0.85, "ttl_variance": 3.0, "fingerprint_diversity": 6.0,
}


def clip01(x):
    return np.clip(x, 0.0, 1.0)


def clip0(x):
    return np.clip(x, 0.0, None)


def gen_baseline_columns(n, rng):
    """mean_r/sigma_r/mean_h/sigma_h as a slowly drifting learned baseline,
    not an exact per-row statistic: real noise around BASELINE, not a
    constant, since a real Welford baseline is never perfectly settled."""
    mean_r = clip0(rng.normal(BASELINE["mean_r"], BASELINE["mean_r"] * 0.05, n))
    sigma_r = clip0(rng.normal(BASELINE["sigma_r"], BASELINE["sigma_r"] * 0.1, n))
    mean_h = clip01(rng.normal(BASELINE["mean_h"], 0.02, n))
    sigma_h = clip0(rng.normal(BASELINE["sigma_h"], 0.01, n))
    return mean_r, sigma_r, mean_h, sigma_h


def gen_normal(n, rng):
    mean_r, sigma_r, mean_h, sigma_h = gen_baseline_columns(n, rng)
    df = pd.DataFrame({
        "ewma_rate": clip0(rng.normal(mean_r, sigma_r)),
        "entropy": clip01(rng.normal(mean_h, sigma_h)),
        "mean_r": mean_r, "sigma_r": sigma_r, "mean_h": mean_h, "sigma_h": sigma_h,
        "proto_ratio": clip01(rng.normal(BASELINE["proto_ratio"], 0.05, n)),
        "dominant_ip_ratio": clip01(rng.normal(BASELINE["dominant_ip_ratio"], 0.02, n)),
        "source_port_entropy": clip01(rng.normal(BASELINE["source_port_entropy"], 0.03, n)),
        "ttl_variance": clip0(rng.normal(BASELINE["ttl_variance"], 0.3, n)),
        "fingerprint_diversity": clip0(rng.normal(BASELINE["fingerprint_diversity"], 0.5, n)),
    })
    df[LABEL_COL] = 0
    return df


def gen_flash_crowd(n, rng):
    mean_r, sigma_r, mean_h, sigma_h = gen_baseline_columns(n, rng)
    surge = rng.uniform(5.0, 15.0, n)
    df = pd.DataFrame({
        "ewma_rate": clip0(mean_r * surge + rng.normal(0, sigma_r, n)),
        "entropy": clip01(rng.normal(mean_h, sigma_h, n)),
        "mean_r": mean_r, "sigma_r": sigma_r, "mean_h": mean_h, "sigma_h": sigma_h,
        "proto_ratio": clip01(rng.normal(BASELINE["proto_ratio"], 0.05, n)),
        # More real distinct users joining, dominance if anything lower than Normal.
        "dominant_ip_ratio": clip01(rng.normal(BASELINE["dominant_ip_ratio"] * 0.7, 0.02, n)),
        "source_port_entropy": clip01(rng.normal(BASELINE["source_port_entropy"], 0.03, n)),
        "ttl_variance": clip0(rng.normal(BASELINE["ttl_variance"], 0.3, n)),
        "fingerprint_diversity": clip0(rng.normal(BASELINE["fingerprint_diversity"] * 1.1, 0.5, n)),
    })
    df[LABEL_COL] = 1
    return df


def gen_ddos_concentrated(n, rng):
    mean_r, sigma_r, mean_h, sigma_h = gen_baseline_columns(n, rng)
    surge = rng.uniform(20.0, 100.0, n)
    df = pd.DataFrame({
        "ewma_rate": clip0(mean_r * surge),
        "entropy": clip01(rng.normal(0.08, 0.05, n)),
        "mean_r": mean_r, "sigma_r": sigma_r, "mean_h": mean_h, "sigma_h": sigma_h,
        "proto_ratio": clip01(rng.normal(0.5, 0.1, n)),
        "dominant_ip_ratio": clip01(rng.normal(0.92, 0.04, n)),
        "source_port_entropy": clip01(rng.normal(0.3, 0.1, n)),
        "ttl_variance": clip0(rng.normal(0.4, 0.15, n)),
        "fingerprint_diversity": clip0(rng.normal(1.0, 0.3, n)),
    })
    df[LABEL_COL] = 2
    return df


def gen_ddos_distributed(n, rng):
    mean_r, sigma_r, mean_h, sigma_h = gen_baseline_columns(n, rng)
    surge = rng.uniform(20.0, 100.0, n)
    df = pd.DataFrame({
        "ewma_rate": clip0(mean_r * surge),
        # The project's own documented blind spot: spoofing raises entropy.
        "entropy": clip01(rng.normal(0.95, 0.03, n)),
        "mean_r": mean_r, "sigma_r": sigma_r, "mean_h": mean_h, "sigma_h": sigma_h,
        "proto_ratio": clip01(rng.normal(0.3, 0.15, n)),
        "dominant_ip_ratio": clip01(rng.normal(0.03, 0.02, n)),
        "source_port_entropy": clip01(rng.normal(0.9, 0.05, n)),
        "ttl_variance": clip0(rng.normal(6.0, 1.0, n)),
        "fingerprint_diversity": clip0(rng.normal(4.0, 1.0, n)),
    })
    df[LABEL_COL] = 2
    return df


def gen_ddos_low_rate(n, rng):
    mean_r, sigma_r, mean_h, sigma_h = gen_baseline_columns(n, rng)
    surge = rng.uniform(2.0, 5.0, n)
    df = pd.DataFrame({
        "ewma_rate": clip0(mean_r * surge),
        "entropy": clip01(rng.normal(0.15, 0.08, n)),
        "mean_r": mean_r, "sigma_r": sigma_r, "mean_h": mean_h, "sigma_h": sigma_h,
        "proto_ratio": clip01(rng.normal(0.5, 0.1, n)),
        "dominant_ip_ratio": clip01(rng.normal(0.85, 0.06, n)),
        "source_port_entropy": clip01(rng.normal(0.35, 0.1, n)),
        "ttl_variance": clip0(rng.normal(0.5, 0.2, n)),
        "fingerprint_diversity": clip0(rng.normal(1.2, 0.4, n)),
    })
    df[LABEL_COL] = 2
    return df


def gen_ddos_protocol_syn(n, rng):
    mean_r, sigma_r, mean_h, sigma_h = gen_baseline_columns(n, rng)
    surge = rng.uniform(20.0, 100.0, n)
    df = pd.DataFrame({
        "ewma_rate": clip0(mean_r * surge),
        "entropy": clip01(rng.normal(0.2, 0.08, n)),
        "mean_r": mean_r, "sigma_r": sigma_r, "mean_h": mean_h, "sigma_h": sigma_h,
        "proto_ratio": clip01(rng.normal(0.97, 0.02, n)),
        "dominant_ip_ratio": clip01(rng.normal(0.6, 0.1, n)),
        "source_port_entropy": clip01(rng.normal(0.5, 0.1, n)),
        "ttl_variance": clip0(rng.normal(0.6, 0.2, n)),
        "fingerprint_diversity": clip0(rng.normal(0.5, 0.2, n)),
    })
    df[LABEL_COL] = 2
    return df


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("output_csv")
    parser.add_argument("--total-rows", type=int, default=500_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    rng = np.random.default_rng(args.seed)

    n_normal = int(args.total_rows * 0.4)
    n_flash = int(args.total_rows * 0.3)
    n_ddos_each = (args.total_rows - n_normal - n_flash) // 4

    parts = [
        gen_normal(n_normal, rng),
        gen_flash_crowd(n_flash, rng),
        gen_ddos_concentrated(n_ddos_each, rng),
        gen_ddos_distributed(n_ddos_each, rng),
        gen_ddos_low_rate(n_ddos_each, rng),
        gen_ddos_protocol_syn(n_ddos_each, rng),
    ]
    df = pd.concat(parts, ignore_index=True)

    # Session-like timestamp structure: contiguous blocks per generated
    # part, 2 second windows, >30s gaps between parts, matching the
    # session-detection heuristic train.py/loso_scaled_validation.py use,
    # so this file can be read by the same tooling without special-casing.
    timestamps = []
    t = 1_700_000_000.0
    for part in parts:
        timestamps.extend(t + np.arange(len(part)) * 2.0)
        t += len(part) * 2.0 + 60.0
    df["timestamp"] = timestamps

    df = df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)
    df = df[RAW_COLS]
    df.to_csv(args.output_csv, index=False)
    print(f"[+] Wrote {len(df)} rows to {args.output_csv}")
    print(df[LABEL_COL].value_counts().to_string())
    print("\n[!] SYNTHETIC, INDEPENDENTLY PARAMETERIZED, NOT REAL TRAFFIC. See module docstring.")


if __name__ == "__main__":
    main()
