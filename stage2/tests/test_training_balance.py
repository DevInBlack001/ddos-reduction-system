"""Tests for training_balance.py's session-aware DDoS trimming, the
stage2 counterpart to scripts/trim_ddos_class.py used by the dashboard's
Auto Label page."""

import unittest

from training_balance import trim_ddos_sessions


def _row(timestamp, label):
    return ["0.9", "20.0", "0.9", "20.0", "0.1", "7.1", "1.0", "0.1",
            "0.9", "0.1", "0.1", timestamp, label]


class TrimDdosSessionsTests(unittest.TestCase):
    def test_nothing_dropped_when_ddos_is_already_at_or_under_the_cap(self):
        rows = [_row(str(i), "0") for i in range(5)] + \
               [_row(str(1000 + i), "1") for i in range(5)] + \
               [_row(str(2000 + i), "2") for i in range(3)]
        kept, dropped, cap = trim_ddos_sessions(rows)
        self.assertEqual(dropped, 0)
        self.assertEqual(cap, 5)
        self.assertEqual(len(kept), len(rows))

    def test_cap_is_the_smaller_of_normal_and_flash_crowd(self):
        rows = [_row(str(i), "0") for i in range(7)] + \
               [_row(str(1000 + i), "1") for i in range(4)] + \
               [_row(str(2000 + i), "2") for i in range(20)]
        _, _, cap = trim_ddos_sessions(rows)
        self.assertEqual(cap, 4)

    def test_every_normal_and_flash_crowd_row_survives_untouched(self):
        rows = [_row(str(i), "0") for i in range(5)] + \
               [_row(str(1000 + i), "1") for i in range(5)] + \
               [_row(str(2000 + i), "2") for i in range(50)]
        kept, _, _ = trim_ddos_sessions(rows)
        kept_normal = [r for r in kept if r[-1] == "0"]
        kept_flash = [r for r in kept if r[-1] == "1"]
        self.assertEqual(len(kept_normal), 5)
        self.assertEqual(len(kept_flash), 5)

    def test_resulting_ddos_count_never_exceeds_the_cap(self):
        rows = [_row(str(i), "0") for i in range(5)] + \
               [_row(str(1000 + i), "1") for i in range(5)] + \
               [_row(str(2000 + i), "2") for i in range(50)]
        kept, dropped, cap = trim_ddos_sessions(rows)
        kept_ddos = [r for r in kept if r[-1] == "2"]
        self.assertLessEqual(len(kept_ddos), cap)
        self.assertGreater(dropped, 0)

    def test_a_ddos_session_is_kept_or_dropped_whole_never_fragmented(self):
        # Two DDoS sessions, gap of 40s between them (over the 30s
        # session boundary), sized 3 and 3, cap 3: exactly one of the two
        # three-row sessions should survive intact, never a partial mix.
        rows = (
            [_row(str(i), "0") for i in range(3)]
            + [_row(str(1000 + i), "1") for i in range(3)]
            + [_row(str(2000 + i), "2") for i in range(3)]
            + [_row(str(2100 + i), "2") for i in range(3)]
        )
        kept, dropped, cap = trim_ddos_sessions(rows)
        self.assertEqual(cap, 3)
        self.assertEqual(dropped, 3)
        kept_ts = {r[-2] for r in kept if r[-1] == "2"}
        first_session = {"2000", "2001", "2002"}
        second_session = {"2100", "2101", "2102"}
        self.assertTrue(kept_ts == first_session or kept_ts == second_session)

    def test_a_gap_under_30_seconds_does_not_start_a_new_session(self):
        # One DDoS session of 10 rows, 5 seconds apart throughout (well
        # under the 30s boundary): with a cap smaller than 10, the whole
        # session cannot fit, so every DDoS row is dropped, not a
        # partial slice of it.
        rows = (
            [_row(str(i), "0") for i in range(2)]
            + [_row(str(1000 + i), "1") for i in range(2)]
            + [_row(str(2000 + i * 5), "2") for i in range(10)]
        )
        kept, dropped, cap = trim_ddos_sessions(rows)
        self.assertEqual(cap, 2)
        kept_ddos = [r for r in kept if r[-1] == "2"]
        self.assertEqual(len(kept_ddos), 0)
        self.assertEqual(dropped, 10)

    def test_result_is_reproducible_for_the_same_seed(self):
        rows = (
            [_row(str(i), "0") for i in range(3)]
            + [_row(str(1000 + i), "1") for i in range(3)]
            + [_row(str(2000 + i), "2") for i in range(3)]
            + [_row(str(2100 + i), "2") for i in range(3)]
            + [_row(str(2200 + i), "2") for i in range(3)]
        )
        kept_a, _, _ = trim_ddos_sessions(rows, seed=7)
        kept_b, _, _ = trim_ddos_sessions(rows, seed=7)
        self.assertEqual(kept_a, kept_b)


if __name__ == "__main__":
    unittest.main()
