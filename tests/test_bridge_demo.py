from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

from kinegrant.experimental.bridge_demo import BridgeDemo, main


class BridgeDemoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = BridgeDemo().run()

    def test_overall_pass(self) -> None:
        self.assertEqual(self.report["overall_result"], "PASS")
        self.assertTrue(self.report["fidelity_ok"])
        self.assertEqual(self.report["summary"], {"total": 4, "passed": 4, "failed": 0})

    def test_allowed_scenarios_are_allowed(self) -> None:
        allowed = [item for item in self.report["outcomes"] if item["scenario"] == "allowed"]
        self.assertEqual(len(allowed), 3)
        self.assertTrue(all(item["allowed"] for item in allowed))
        self.assertEqual(
            {item["stack"] for item in allowed},
            {"matter", "opcua", "ros2"},
        )

    def test_wrong_purpose_is_denied(self) -> None:
        outcome = next(
            item for item in self.report["outcomes"] if item["scenario"] == "wrong-purpose"
        )
        self.assertFalse(outcome["allowed"])

    def test_adapter_fidelity(self) -> None:
        self.assertEqual(self.report["adapter_fidelity"]["ros2"]["transport"], "ros2")
        self.assertEqual(self.report["adapter_fidelity"]["matter"]["transport"], "matter")
        self.assertEqual(self.report["adapter_fidelity"]["opcua"]["transport"], "opcua")
        self.assertTrue(
            self.report["adapter_fidelity"]["matter"]["target"].startswith("matter:")
        )
        self.assertTrue(
            self.report["adapter_fidelity"]["opcua"]["target"].startswith("opcua:")
        )

    def test_cli_emits_machine_readable_pass(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main([])
        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["overall_result"], "PASS")


if __name__ == "__main__":
    unittest.main()
