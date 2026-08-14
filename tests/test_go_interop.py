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
from kinegrant.policy_bundle import PolicyAuthority
from kinegrant.receipt import ReceiptLog

ROOT = Path(__file__).resolve().parents[1]
GO_DIR = ROOT / "implementations" / "kinegrant-go"


@unittest.skipUnless(shutil.which("go"), "go toolchain is not available")
class GoInteropTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.request = ActionRequest(
            request_id="urn:kinegrant:interop-go:request:1",
            agent="urn:kinegrant:interop-go:agent:1",
            target="urn:kinegrant:interop-go:target:door-7",
            action="open",
            purpose="delivery",
        )
        rule = PolicyRule(
            policy_id="interop-go-rule-1",
            issuer=self.authority.kid,
            target="urn:kinegrant:interop-go:target:*",
            effect="allow",
            actions=("open",),
        )
        self.decision = PolicyEngine(
            [rule], trusted_policy_issuers={self.authority.kid}
        ).evaluate(self.request)

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["go", "run", "./cmd/kinegrant-verify", *args],
            cwd=GO_DIR,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )

    def test_go_verifies_python_capability(self) -> None:
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

    def test_go_verifies_python_receipt_chain(self) -> None:
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

    def test_go_verifies_python_policy_bundle(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:interop-go:policy:door"
        rules_v1 = [
            PolicyRule(
                policy_id,
                authority.kid,
                "urn:kinegrant:interop-go:target:*",
                "allow",
                ("open",),
                purposes=("delivery",),
            )
        ]
        v1 = authority.publish(policy_id, rules_v1, ttl_seconds=3600)
        rules_v2 = [
            PolicyRule(
                policy_id,
                authority.kid,
                "urn:kinegrant:interop-go:target:*",
                "allow",
                ("open",),
                purposes=("delivery", "maintenance"),
            )
        ]
        v2 = authority.publish(policy_id, rules_v2, ttl_seconds=3600)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundle_path = base / "policy-bundle-v2.json"
            authorities_path = base / "policy-authorities.json"
            bundles_path = base / "policy-bundles.json"
            revoked_path = base / "policy-revoked.json"
            bundle_path.write_text(json.dumps(v2), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([authority.kid]),
                encoding="utf-8",
            )
            bundles_path.write_text(
                json.dumps([v1["payload"], v2["payload"]]),
                encoding="utf-8",
            )
            revoked_path.write_text(
                json.dumps([f"{policy_id}:2"]),
                encoding="utf-8",
            )
            verified = self._run(
                "verify-policy-bundle",
                str(bundle_path),
                str(authorities_path),
                policy_id,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY BUNDLE VALID", verified.stdout)
            current = self._run(
                "current-policy-version",
                str(bundles_path),
            )
            self.assertEqual(current.returncode, 0, current.stderr)
            self.assertEqual(json.loads(current.stdout)["version"], 2)
            rollback = self._run(
                "current-policy-version",
                str(bundles_path),
                str(revoked_path),
            )
            self.assertEqual(rollback.returncode, 0, rollback.stderr)
            self.assertEqual(json.loads(rollback.stdout)["version"], 1)

    def test_go_verifies_python_extended_receipt(self) -> None:
        capability = self.issuer.issue(self.request, self.decision, ttl_seconds=300)
        verified = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, self.request)
        executor = Ed25519KeyPair.generate()
        receipt = ReceiptLog(executor).append(
            verified,
            result="succeeded",
            obligation_results=[
                {"obligation": "emitActionReceipt", "status": "satisfied"}
            ],
            failure_reason=None,
        )
        self.assertEqual(receipt["payload"]["version"], "1.0")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            entries_path = base / "receipts.json"
            executors_path = base / "executors.json"
            entries_path.write_text(json.dumps([receipt]), encoding="utf-8")
            executors_path.write_text(json.dumps([executor.kid]), encoding="utf-8")
            result = self._run("verify-receipts", str(entries_path), str(executors_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RECEIPT CHAIN VALID", result.stdout)

    def test_go_verifies_python_scoped_capability(self) -> None:
        capability = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=300,
            target="urn:kinegrant:interop-go:target:*",
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

    def test_go_accepts_all_known_obligations(self) -> None:
        rule = PolicyRule(
            policy_id="interop-go-rule-obligations",
            issuer=self.authority.kid,
            target="urn:kinegrant:interop-go:target:*",
            effect="allow",
            actions=("open",),
            obligations=("emitActionReceipt", "logAuditEvent", "preserveEvidence"),
        )
        decision = PolicyEngine(
            [rule], trusted_policy_issuers={self.authority.kid}
        ).evaluate(self.request)
        capability = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=300,
            target="urn:kinegrant:interop-go:target:*",
            actions=["open"],
            purposes=["delivery"],
            wire_version="1.0",
        )
        self.assertEqual(
            sorted(capability["payload"]["obligations"]),
            ["emitActionReceipt", "logAuditEvent", "preserveEvidence"],
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
