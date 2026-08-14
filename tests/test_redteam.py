from __future__ import annotations

import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

from kinegrant.redteam import RED_TEAM_CASES, RedTeamSuite, main


class RedTeamSuiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = RedTeamSuite().run()

    def test_overall_pass_with_all_cases(self) -> None:
        self.assertEqual(self.report["overall_result"], "PASS")
        self.assertEqual(
            self.report["summary"],
            {"total": 10, "passed": 10, "failed": 0},
        )

    def test_case_ids_match_the_corpus(self) -> None:
        self.assertEqual(
            [case["id"] for case in self.report["cases"]],
            [case["id"] for case in RED_TEAM_CASES],
        )

    def test_categories_cover_roadmap_attacks(self) -> None:
        categories = {case["category"] for case in self.report["cases"]}
        for required in ("replay", "mutation", "confused-deputy", "conflict",
                         "downgrade", "clock", "revocation", "delegation",
                         "adapter", "sequence"):
            self.assertIn(required, categories)

    def test_cli_emits_machine_readable_pass(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main([])
        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["overall_result"], "PASS")


if __name__ == "__main__":
    unittest.main()
