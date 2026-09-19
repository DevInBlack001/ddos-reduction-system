import unittest

import numpy as np

import _support  # noqa: F401

import train


def candidate(depth, accuracy, share):
    return (depth, accuracy, share, [], [], [])


class ConfidentShareTests(unittest.TestCase):
    def test_only_correct_rows_above_the_threshold_count(self):
        probas = np.array([
            [0.05, 0.05, 0.90],  # correct, confident
            [0.10, 0.10, 0.80],  # correct, below the threshold
            [0.95, 0.03, 0.02],  # confident but wrong
            [0.02, 0.96, 0.02],  # correct, confident
        ])
        share = train.confident_share([2, 2, 2, 1], probas, [0, 1, 2], 0.90)
        self.assertAlmostEqual(share, 0.5)

    def test_classes_are_read_from_the_model_not_from_the_column_position(self):
        probas = np.array([[0.05, 0.95]])
        self.assertEqual(train.confident_share([2], probas, [0, 2], 0.90), 1.0)


class PickDepthTests(unittest.TestCase):
    def test_a_depth_outside_the_accuracy_tolerance_is_never_picked(self):
        chosen = train.pick_depth(
            [candidate(2, 0.90, 0.99), candidate(4, 0.997, 0.70), candidate(6, 0.996, 0.72)],
            0.005, 0.02,
        )
        self.assertEqual(chosen[0], 4)

    def test_equal_accuracy_goes_to_the_depth_that_clears_the_confidence_bar_more_often(self):
        chosen = train.pick_depth(
            [candidate(3, 0.997, 0.64), candidate(4, 0.997, 0.91), candidate(5, 0.997, 0.90)],
            0.005, 0.02,
        )
        self.assertEqual(chosen[0], 4)

    def test_confident_shares_within_the_tolerance_resolve_to_the_simplest_depth(self):
        chosen = train.pick_depth(
            [candidate(3, 0.997, 0.90), candidate(5, 0.997, 0.91), candidate(8, 0.997, 0.905)],
            0.005, 0.02,
        )
        self.assertEqual(chosen[0], 3)

    def test_unlimited_depth_counts_as_the_most_complex(self):
        chosen = train.pick_depth(
            [candidate(None, 0.997, 0.95), candidate(6, 0.997, 0.95)], 0.005, 0.02,
        )
        self.assertEqual(chosen[0], 6)


if __name__ == "__main__":
    unittest.main()
