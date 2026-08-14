from __future__ import annotations

import json
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_reports_sane_throughput(self) -> None:
        sys.path.insert(0, str(ROOT))
        try:
            import benchmarks.bench as bench
        finally:
            sys.path.pop(0)
        output = StringIO()
        with redirect_stdout(output):
            bench.main([])
        report = json.loads(output.getvalue())
        ops = report["operations_per_second"]
        self.assertGreaterEqual(ops["policy_evaluate"], 2000)
        self.assertGreaterEqual(ops["capability_issue"], 200)
        self.assertGreaterEqual(ops["gate_authorize"], 100)
        self.assertGreaterEqual(ops["receipt_append"], 20)
        self.assertGreaterEqual(ops["obligation_compliance"], 1)
        self.assertGreaterEqual(ops["gatekeeper_execute"], 1)
        self.assertGreaterEqual(ops["audit_summary"], 1)
        self.assertGreaterEqual(ops["revocation_distribute"], 1)
        self.assertGreaterEqual(ops["jcs_digest"], 5000)

    def test_benchmark_cli_is_json(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "benchmarks" / "bench.py")],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["type"], "kinegrant:BenchmarkReport")


if __name__ == "__main__":
    unittest.main()
