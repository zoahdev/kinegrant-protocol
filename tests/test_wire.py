from __future__ import annotations

import unittest

from kinegrant.wire import SUPPORTED_WIRE_VERSIONS, check_compatibility, supports


class WireCompatibilityTests(unittest.TestCase):
    def test_supported_versions(self) -> None:
        self.assertEqual(SUPPORTED_WIRE_VERSIONS, ("0.1", "0.2"))
        self.assertTrue(supports("0.1"))
        self.assertTrue(supports("0.2"))
        self.assertFalse(supports("0.3"))
        self.assertFalse(supports("1.0"))

    def test_exact_version_required(self) -> None:
        self.assertTrue(check_compatibility("0.1", "0.1"))
        self.assertTrue(check_compatibility("0.2", "0.2"))
        self.assertFalse(check_compatibility("0.1", "0.2"))
        self.assertFalse(check_compatibility("0.2", "0.1"))
        self.assertFalse(check_compatibility("0.2", "0.3"))


if __name__ == "__main__":
    unittest.main()
