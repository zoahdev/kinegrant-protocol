from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "implementations" / "kinegrant-js" / "src" / "cli.mjs"


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    bundled = (
        Path(r"C:\Users\zoah\.cache\codex-runtimes\codex-primary-runtime")
        / "dependencies" / "node" / "bin" / "node.exe"
    )
    return str(bundled) if bundled.exists() else None


@unittest.skipUnless(_node(), "node.js is not available")
class JavaScriptInteropTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.request = ActionRequest(
            request_id="urn:kinegrant:interop:request:1",
            agent="urn:kinegrant:interop:agent:1",
            target="urn:kinegrant:interop:target:door-7",
            action="open",
            purpose="delivery",
        )
        rule = PolicyRule(
            policy_id="interop-rule-1",
            issuer=self.authority.kid,
            target="urn:kinegrant:interop:target:*",
            effect="allow",
            actions=("open",),
        )
        self.decision = PolicyEngine(
            [rule], trusted_policy_issuers={self.authority.kid}
        ).evaluate(self.request)

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [_node(), CLI, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )

    def test_javascript_verifies_python_capability(self) -> None:
        capability = self.issuer.issue(self.request, self.decision, ttl_seconds=300)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            envelope_path = base / "capability.json"
            request_path = base / "request.json"
            issuers_path = base / "issuers.json"
            envelope_path.write_text(json.dumps(capability), encoding="utf-8")
            request_path.write_text(json.dumps(self.request.to_dict()), encoding="utf-8")
            issuers_path.write_text(
                json.dumps([self.authority.kid]), encoding="utf-8"
            )
            result = self._run(
                "verify-capability",
                str(envelope_path),
                str(request_path),
                str(issuers_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CAPABILITY VALID", result.stdout)

    def test_javascript_rejects_tampered_capability(self) -> None:
        import copy

        capability = self.issuer.issue(self.request, self.decision, ttl_seconds=300)
        tampered = copy.deepcopy(capability)
        tampered["payload"]["action"] = "close"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            envelope_path = base / "capability.json"
            request_path = base / "request.json"
            issuers_path = base / "issuers.json"
            envelope_path.write_text(json.dumps(tampered), encoding="utf-8")
            request_path.write_text(json.dumps(self.request.to_dict()), encoding="utf-8")
            issuers_path.write_text(
                json.dumps([self.authority.kid]), encoding="utf-8"
            )
            result = self._run(
                "verify-capability",
                str(envelope_path),
                str(request_path),
                str(issuers_path),
            )
            self.assertEqual(result.returncode, 2)

    def test_javascript_verifies_python_receipt_chain(self) -> None:
        capability = self.issuer.issue(self.request, self.decision, ttl_seconds=300)
        verified = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, self.request)
        executor = Ed25519KeyPair.generate()
        receipt = ReceiptLog(executor).append(verified, result="succeeded")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            entries_path = base / "receipts.json"
            executors_path = base / "executors.json"
            entries_path.write_text(json.dumps([receipt]), encoding="utf-8")
            executors_path.write_text(json.dumps([executor.kid]), encoding="utf-8")
            result = self._run("verify-receipts", str(entries_path), str(executors_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RECEIPT CHAIN VALID", result.stdout)

    def test_javascript_verifies_python_scoped_capability(self) -> None:
        capability = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=300,
            target="urn:kinegrant:interop:target:*",
            actions=["open"],
            purposes=["delivery"],
            wire_version="1.0",
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            envelope_path = base / "capability.json"
            request_path = base / "request.json"
            issuers_path = base / "issuers.json"
            envelope_path.write_text(json.dumps(capability), encoding="utf-8")
            request_path.write_text(json.dumps(self.request.to_dict()), encoding="utf-8")
            issuers_path.write_text(
                json.dumps([self.authority.kid]), encoding="utf-8"
            )
            result = self._run(
                "verify-capability",
                str(envelope_path),
                str(request_path),
                str(issuers_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("CAPABILITY VALID", result.stdout)


if __name__ == "__main__":
    unittest.main()
