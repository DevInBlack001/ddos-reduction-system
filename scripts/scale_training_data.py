#!/usr/bin/env python3
"""Produce a synthetic larger-institution copy of a training CSV. See
scratch/specs/2026-10-12-generalized-feature-scaling-design.md, Validation
plan: an earlier version scaled ewma_rate/mean_r/sigma_r by the same
factor, which made rate_z/rate_ratio cancel exactly.

Scales unevenly: ewma_rate/mean_r by --rate-factor (k); sigma_r by
sqrt(k) (central limit behavior for independent sources, so rate_z
doesn't cancel); entropy shifted by --entropy-shift with independent
noise, not mirrored into mean_h/sigma_h; the five ratio/diversity columns
get independent noise too, clipped to valid range.

A stress check on the trained coefficients, not proof of cross-
institution generalization.
"""

import argparse

import numpy as np
import pandas as pd

RATE_SCALE_COLUMNS = ["ewma_rate", "mean_r"]
RATE_SIGMA_COLUMN = "sigma_r"
NOISY_RATIO_COLUMNS = ["proto_ratio", "dominant_ip_ratio", "source_port_entropy"]
NOISY_UNBOUNDED_COLUMNS = ["ttl_variance", "fingerprint_diversity"]


def scale_copy(
    input_csv: str,
    output_csv: str,
    rate_factor: float,
    entropy_shift: float,
    noise_std: float,
    seed: int,
) -> None:
    rng = np.random.default_rng(seed)
    df = pd.read_csv(input_csv)

    required = RATE_SCALE_COLUMNS + [RATE_SIGMA_COLUMN, "entropy"] + NOISY_RATIO_COLUMNS + NOISY_UNBOUNDED_COLUMNS
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise SystemExit(f"[-] Error: '{input_csv}' is missing column(s): {', '.join(missing)}")

    for col in RATE_SCALE_COLUMNS:
        df[col] = df[col] * rate_factor
    df[RATE_SIGMA_COLUMN] = df[RATE_SIGMA_COLUMN] * np.sqrt(rate_factor)

    df["entropy"] = (df["entropy"] + entropy_shift + rng.normal(0, noise_std, len(df))).clip(0.0, 1.0)

    for col in NOISY_RATIO_COLUMNS:
        df[col] = (df[col] + rng.normal(0, noise_std, len(df))).clip(0.0, 1.0)
    for col in NOISY_UNBOUNDED_COLUMNS:
        df[col] = (df[col] + rng.normal(0, noise_std, len(df))).clip(lower=0.0)

    df.to_csv(output_csv, index=False)
    print(
        f"[+] Wrote {len(df)} rows to {output_csv}: "
        f"{RATE_SCALE_COLUMNS} x{rate_factor}, {RATE_SIGMA_COLUMN} x{rate_factor ** 0.5:.3f} "
        f"(sqrt of rate_factor), entropy shifted by {entropy_shift} with noise_std={noise_std}, "
        f"{NOISY_RATIO_COLUMNS + NOISY_UNBOUNDED_COLUMNS} given independent noise_std={noise_std}."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_csv", help="Source training CSV (unscaled)")
    parser.add_argument("output_csv", help="Destination path for the scaled copy")
    parser.add_argument(
        "--rate-factor", type=float, default=50.0,
        help="Multiplier on ewma_rate/mean_r; sigma_r scales by its square root (default: 50.0)",
    )
    parser.add_argument(
        "--entropy-shift", type=float, default=0.3,
        help="Additive shift applied to raw entropy only, not mean_h/sigma_h (default: 0.3)",
    )
    parser.add_argument(
        "--noise-std", type=float, default=0.03,
        help="Std dev of independent Gaussian noise added to entropy and the ratio/diversity columns (default: 0.03)",
    )
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for the added noise (default: 42)")
    args = parser.parse_args()
    scale_copy(args.input_csv, args.output_csv, args.rate_factor, args.entropy_shift, args.noise_std, args.seed)


if __name__ == "__main__":
    main()
