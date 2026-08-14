from __future__ import annotations

import unittest

from kinegrant.fuzz import AdapterFuzzHarness


class AdapterFuzzTests(unittest.TestCase):
    def test_fuzz_is_clean_and_deterministic(self) -> None:
        first = AdapterFuzzHarness(seed=7, iterations=10).run()
        second = AdapterFuzzHarness(seed=7, iterations=10).run()
        self.assertEqual(first["overall_result"], "PASS")
        self.assertEqual(first["summary"]["clean"], first["summary"]["total"])
        self.assertEqual(first["cases"], second["cases"])
        self.assertEqual(len(first["cases"]), 30)  # 3 adapters x 10 iterations

    def test_different_seeds_give_different_cases(self) -> None:
        first = AdapterFuzzHarness(seed=1, iterations=5).run()
        second = AdapterFuzzHarness(seed=2, iterations=5).run()
        self.assertNotEqual(first["cases"], second["cases"])

    def test_invalid_iterations_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            AdapterFuzzHarness(iterations=0)


if __name__ == "__main__":
    unittest.main()
