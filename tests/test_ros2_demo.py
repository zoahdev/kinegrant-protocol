from __future__ import annotations

import unittest

from kinegrant.adapters.mcp import mcp_tool_request
from kinegrant.experimental.ros2_demo import Ros2McpDemo, main
from kinegrant.receipt import verify_receipt_chain


class Ros2McpDemoTests(unittest.TestCase):
    def test_demo_reports_pass(self) -> None:
        report = Ros2McpDemo().run()
        self.assertEqual(report["overall_result"], "PASS")
        self.assertTrue(report["obligation_compliance_ok"])
        self.assertEqual(report["summary"]["failed"], 0)
        self.assertTrue(all(outcome["passed"] for outcome in report["outcomes"]))
        allowed = [outcome for outcome in report["outcomes"] if outcome["allowed"]]
        self.assertTrue(all(outcome["obligation_compliant"] for outcome in allowed))

    def test_demo_covers_all_fault_classes(self) -> None:
        report = Ros2McpDemo().run()
        scenarios = {outcome["scenario"] for outcome in report["outcomes"]}
        self.assertIn("ros2-replay", scenarios)
        self.assertIn("mcp-untrusted-issuer", scenarios)
        self.assertIn("ros2-wrong-purpose", scenarios)
        self.assertIn("mcp-physical-limit", scenarios)
        self.assertIn("ros2-enter-after-open", scenarios)

    def test_receipts_verify(self) -> None:
        demo = Ros2McpDemo()
        report = demo.run()
        self.assertTrue(report["receipts_verified"])
        self.assertEqual(report["receipt_count"], 2)
        self.assertTrue(
            verify_receipt_chain(demo.log.entries, trusted_executors={demo.authority.kid})
        )

    def test_main_returns_zero(self) -> None:
        self.assertEqual(main([]), 0)

    def test_mcp_adapter_records_transport(self) -> None:
        request = mcp_tool_request(
            server_identity="urn:kinegrant:demo:agent:robot-1",
            tool_name="open",
            physical_target="urn:kinegrant:demo:target:door-7",
            purpose="delivery",
            request_id="req-mcp-1",
        )
        self.assertEqual(request.context["transport"], "mcp")
        self.assertEqual(request.context["adapter_profile"], "mcp-tool-v0.1")

    def test_mcp_adapter_rejects_context_spoofing(self) -> None:
        with self.assertRaises(ValueError):
            mcp_tool_request(
                server_identity="urn:kinegrant:demo:agent:robot-1",
                tool_name="open",
                physical_target="urn:kinegrant:demo:target:door-7",
                purpose="delivery",
                request_id="req-mcp-2",
                context={"transport": "spoofed"},
            )


if __name__ == "__main__":
    unittest.main()
