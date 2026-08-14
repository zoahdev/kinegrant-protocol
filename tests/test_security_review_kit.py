from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.environ.get("KINEGRANT_KIT_TEST") == "1", "nested kit run")
class SecurityReviewKitTests(unittest.TestCase):
    def _run(self) -> dict:
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            import security_review_kit as kit
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "kit.json"
            exit_code = kit.main(
                [
                    "--output",
                    str(output),
                    "--source-commit",
                    "e" * 40,
                ]
            )
            self.assertEqual(exit_code, 0)
            return json.loads(output.read_text(encoding="utf-8"))

    def test_kit_overall_pass(self) -> None:
        kit = self._run()
        self.assertEqual(kit["type"], "kinegrant:SecurityReviewKit")
        self.assertEqual(kit["overall_result"], "PASS")
        for key in ("conformance", "machine_permission_test", "red_team", "unit_tests"):
            self.assertEqual(kit["checks"][key]["status"], "PASS")

    def test_kit_contains_checklist_and_commands(self) -> None:
        kit = self._run()
        self.assertGreaterEqual(len(kit["checklist"]), 6)
        self.assertGreaterEqual(len(kit["commands"]), 6)
        self.assertIn("releases", kit["artifacts"])


if __name__ == "__main__":
    unittest.main()
