from __future__ import annotations

import unittest
from datetime import timedelta

from kinegrant.models import utc_now
from kinegrant.trust import TrustedClock, TrustedClockError


class TrustedClockTests(unittest.TestCase):
    def test_monotonic_sequence_is_accepted(self) -> None:
        times = [utc_now(), utc_now() + timedelta(seconds=1)]
        clock = TrustedClock(source=iter(times).__next__)
        first = clock.now()
        second = clock.now()
        self.assertLessEqual(first, second)

    def test_backwards_time_is_rejected(self) -> None:
        base = utc_now()
        times = [base, base - timedelta(seconds=1)]
        clock = TrustedClock(source=iter(times).__next__)
        clock.now()
        with self.assertRaises(TrustedClockError):
            clock.now()

    def test_large_forward_jump_is_rejected(self) -> None:
        base = utc_now()
        times = [base, base + timedelta(hours=2)]
        clock = TrustedClock(source=iter(times).__next__, max_forward_jump_seconds=3600)
        clock.now()
        with self.assertRaises(TrustedClockError):
            clock.now()

    def test_reset_allows_new_epoch(self) -> None:
        base = utc_now()
        times = [base, base - timedelta(seconds=5), base]
        source = iter(times)
        clock = TrustedClock(source=source.__next__)
        clock.now()
        with self.assertRaises(TrustedClockError):
            clock.now()
        clock.reset()
        self.assertIsNotNone(clock.now())

    def test_naive_time_is_rejected(self) -> None:
        clock = TrustedClock(source=lambda: utc_now().replace(tzinfo=None))
        with self.assertRaises(TrustedClockError):
            clock.now()

    def test_invalid_jump_bound_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            TrustedClock(max_forward_jump_seconds=0)


if __name__ == "__main__":
    unittest.main()
