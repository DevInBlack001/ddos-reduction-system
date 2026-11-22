"""Baseline-relative features for FLOD_FEATURE_SET=portable.

Shared by train.py, train_isolation_forest.py and train_second_model.py so the
three models see identical values.
"""

import os

FEATURE_SETS = ("local", "portable")
PORTABLE_COLS = [
    "proto_ratio",
    "dominant_ip_ratio",
    "source_port_entropy",
    "ttl_variance",
    "fingerprint_diversity",
    "rate_z",
    "rate_ratio",
    "entropy_z",
]
DERIVED_COLS = {"delta_rate", "delta_entropy", "dominant_rate", "rate_z", "rate_ratio", "entropy_z"}
BASE_RAW_COLS = {"ewma_rate", "mean_r", "sigma_r", "mean_h", "sigma_h"}
# Floor on sigma_r as a share of mean_r. A starting point, not a proven value.
DEFAULT_RATE_Z_FLOOR_FRACTION = 0.05


def feature_set_from_env():
    """The FLOD_FEATURE_SET value, or raises ValueError if it is not recognised."""
    value = os.environ.get("FLOD_FEATURE_SET", "local").lower()
    if value not in FEATURE_SETS:
        raise ValueError(f"FLOD_FEATURE_SET must be 'local' or 'portable', got '{value}'")
    return value


def rate_z_floor_fraction_from_env():
    return float(os.environ.get("FLOD_RATE_Z_FLOOR_FRACTION", str(DEFAULT_RATE_Z_FLOOR_FRACTION)))


def required_raw_cols(feature_cols):
    """Raw CSV columns needed to build feature_cols. The baseline columns are always needed."""
    return sorted(BASE_RAW_COLS | {c for c in feature_cols if c not in DERIVED_COLS})


def add_portable_features(df, floor_fraction):
    """Adds rate_z, rate_ratio and entropy_z. Returns (frame, rows dropped).

    Rows with a non-positive mean_r, sigma_r or sigma_h are dropped, since the
    features divide by them.
    """
    unsafe = (df["sigma_r"] <= 0) | (df["sigma_h"] <= 0) | (df["mean_r"] <= 0)
    df = df[~unsafe].reset_index(drop=True)
    sigma_eff = df["sigma_r"].clip(lower=floor_fraction * df["mean_r"])
    df["rate_z"] = (df["ewma_rate"] - df["mean_r"]) / sigma_eff
    df["rate_ratio"] = df["ewma_rate"] / df["mean_r"]
    df["entropy_z"] = (df["entropy"] - df["mean_h"]) / df["sigma_h"]
    return df, int(unsafe.sum())
