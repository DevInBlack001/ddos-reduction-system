import importlib
import os
import sys
import unittest
from unittest import mock

import pandas as pd

import _support  # noqa: F401
import portable_features as pf


def frame(**overrides):
    row = {"ewma_rate": 1000.0, "mean_r": 100.0, "sigma_r": 20.0,
           "entropy": 0.5, "mean_h": 0.8, "sigma_h": 0.1}
    row.update(overrides)
    return pd.DataFrame([row])


class AddPortableFeaturesTests(unittest.TestCase):
    def test_rate_and_entropy_are_expressed_against_the_hosts_own_baseline(self):
        df, dropped = pf.add_portable_features(frame(), 0.05)
        self.assertEqual(dropped, 0)
        self.assertAlmostEqual(df["rate_z"][0], (1000 - 100) / 20)
        self.assertAlmostEqual(df["rate_ratio"][0], 10.0)
        self.assertAlmostEqual(df["entropy_z"][0], (0.5 - 0.8) / 0.1)

    def test_a_tiny_sigma_is_raised_to_the_relative_floor(self):
        df, _ = pf.add_portable_features(frame(sigma_r=0.5), 0.05)
        self.assertAlmostEqual(df["rate_z"][0], (1000 - 100) / (0.05 * 100))

    def test_the_floor_fraction_can_be_changed(self):
        df, _ = pf.add_portable_features(frame(sigma_r=0.5), 0.5)
        self.assertAlmostEqual(df["rate_z"][0], (1000 - 100) / 50)

    def test_rows_that_would_divide_by_zero_are_dropped_and_counted(self):
        rows = pd.concat([frame(), frame(sigma_r=0.0), frame(sigma_h=0.0), frame(mean_r=0.0)], ignore_index=True)
        df, dropped = pf.add_portable_features(rows, 0.05)
        self.assertEqual(dropped, 3)
        self.assertEqual(len(df), 1)
        self.assertTrue(df[["rate_z", "rate_ratio", "entropy_z"]].notna().all().all())


class EnvironmentTests(unittest.TestCase):
    def test_the_default_feature_set_is_local(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FLOD_FEATURE_SET", None)
            self.assertEqual(pf.feature_set_from_env(), "local")

    def test_the_feature_set_is_case_insensitive(self):
        with mock.patch.dict(os.environ, {"FLOD_FEATURE_SET": "Portable"}):
            self.assertEqual(pf.feature_set_from_env(), "portable")

    def test_an_unknown_feature_set_is_refused(self):
        with mock.patch.dict(os.environ, {"FLOD_FEATURE_SET": "global"}):
            with self.assertRaises(ValueError):
                pf.feature_set_from_env()

    def test_the_floor_fraction_comes_from_the_environment(self):
        with mock.patch.dict(os.environ, {"FLOD_RATE_Z_FLOOR_FRACTION": "0.2"}):
            self.assertEqual(pf.rate_z_floor_fraction_from_env(), 0.2)


class RequiredColumnTests(unittest.TestCase):
    def test_the_baseline_columns_are_required_even_for_the_portable_set(self):
        needed = pf.required_raw_cols(pf.PORTABLE_COLS)
        for column in ("ewma_rate", "mean_r", "sigma_r", "mean_h", "sigma_h", "proto_ratio"):
            self.assertIn(column, needed)
        self.assertNotIn("rate_z", needed)


class TrainingScriptTests(unittest.TestCase):
    MODULES = (("train", "MODEL_PATH", "ddos_rf_model"),
               ("train_isolation_forest", "IF_MODEL_PATH", "ddos_if_model"),
               ("train_second_model", "SECOND_MODEL_PATH", "ddos_gb_model"))

    def load(self, name, feature_set):
        env = {"FLOD_FEATURE_SET": feature_set}
        with mock.patch.dict(os.environ, env):
            for key in ("MODEL_PATH", "IF_MODEL_PATH", "SECOND_MODEL_PATH"):
                os.environ.pop(key, None)
            sys.modules.pop(name, None)
            return importlib.import_module(name)

    def test_the_portable_set_uses_the_shared_columns_and_its_own_model_file(self):
        for name, path_attr, stem in self.MODULES:
            module = self.load(name, "portable")
            self.assertEqual(module.FEATURE_COLS, pf.PORTABLE_COLS, name)
            self.assertTrue(getattr(module, path_attr).endswith(f"{stem}_portable.joblib"), name)

    def test_the_local_set_keeps_the_original_columns_and_model_file(self):
        for name, path_attr, stem in self.MODULES:
            module = self.load(name, "local")
            self.assertIn("ewma_rate", module.FEATURE_COLS, name)
            self.assertTrue(getattr(module, path_attr).endswith(f"{stem}.joblib"), name)

    def test_an_unknown_feature_set_stops_the_training_script(self):
        with self.assertRaises(SystemExit):
            self.load("train", "global")

    def tearDown(self):
        for name, _, _ in self.MODULES:
            sys.modules.pop(name, None)


if __name__ == "__main__":
    unittest.main()
