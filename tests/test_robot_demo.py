from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

from kinegrant.experimental.robot_demo import RobotDemo, main


class RobotDemoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.demo = RobotDemo()
        self.report = self.demo.run()

    def test_demo_overall_pass(self) -> None:
        self.assertEqual(self.report["overall_result"], "PASS")
        self.assertEqual(self.report["summary"], {"total": 8, "passed": 8, "failed": 0})
        self.assertTrue(self.report["obligation_compliance_ok"])

    def test_both_stacks_obey_the_same_policy(self) -> None:
        self.assertGreaterEqual(self.report["actuator_calls"]["ros2"], 2)
        self.assertGreaterEqual(self.report["actuator_calls"]["matter"], 1)
        by_scenario = {item["scenario"]: item for item in self.report["outcomes"]}
        self.assertTrue(by_scenario["happy-path"]["allowed"])
        self.assertTrue(by_scenario["record"]["allowed"])
        for scenario in ("happy-path", "record"):
            self.assertTrue(by_scenario[scenario]["obligation_compliant"])

    def test_fault_injections_are_denied(self) -> None:
        denied = {
            "replay",
            "untrusted-issuer",
            "prompt-injection",
            "physical-violation",
            "forbidden-combination",
        }
        by_scenario = {item["scenario"]: item for item in self.report["outcomes"]}
        for scenario in denied:
            self.assertFalse(
                by_scenario[scenario]["allowed"],
                f"{scenario} should have been denied",
            )

    def test_forbidden_combination_reason_is_recorded(self) -> None:
        outcome = next(
            item
            for item in self.report["outcomes"]
            if item["scenario"] == "forbidden-combination"
        )
        self.assertIn("forbidden_combination", outcome["reason"])

    def test_every_outcome_is_self_consistent(self) -> None:
        for outcome in self.report["outcomes"]:
            self.assertEqual(
                outcome["passed"],
                outcome["allowed"] == ("ALLOW" in outcome["expected"]),
            )

    def test_cli_emits_machine_readable_pass(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main([])
        self.assertEqual(exit_code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["overall_result"], "PASS")


if __name__ == "__main__":
    unittest.main()
