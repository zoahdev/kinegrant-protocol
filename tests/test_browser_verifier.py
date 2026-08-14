from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kinegrant.capability import CapabilityIssuer
from kinegrant.audit import ReceiptAuditor
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.mpt import run_machine_permission_test
from kinegrant.policy import PolicyEngine
from kinegrant.policy_bundle import PolicyAuthority, PolicyDistributor, PolicyRegistry
from kinegrant.receipt import ReceiptLog
from kinegrant.revocation import (
    RevocationList,
    build_revocation_bundle,
    sign_revocation_bundle,
)
from challenge.reproduce import create_reproduction

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "verify" / "verify_policy_bundle.mjs"


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    bundled = (
        Path(r"C:\Users\zoah\.cache\codex-runtimes\codex-primary-runtime")
        / "dependencies"
        / "node"
        / "bin"
        / "node.exe"
    )
    return str(bundled) if bundled.exists() else None


@unittest.skipUnless(_node(), "node.js is not available")
class BrowserVerifierInteropTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = PolicyAuthority(Ed25519KeyPair.generate())
        self.policy_id = "urn:kinegrant:browser:policy:door"
        self.rules_v1 = [
            PolicyRule(
                self.policy_id,
                self.authority.kid,
                "urn:space:browser:door-1",
                "allow",
                ("open",),
                purposes=("delivery",),
            )
        ]
        self.v1 = self.authority.publish(
            self.policy_id,
            self.rules_v1,
            ttl_seconds=3600,
        )
        self.v2 = self.authority.publish(
            self.policy_id,
            [
                PolicyRule(
                    self.policy_id,
                    self.authority.kid,
                    "urn:space:browser:door-1",
                    "allow",
                    ("open",),
                    purposes=("delivery", "maintenance"),
                )
            ],
            ttl_seconds=3600,
        )

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [_node(), CLI, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

    def test_browser_verifier_accepts_python_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundle_path = base / "bundle.json"
            authorities_path = base / "authorities.json"
            bundle_path.write_text(json.dumps(self.v2), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([self.authority.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "verify",
                str(bundle_path),
                str(authorities_path),
                self.policy_id,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY BUNDLE VALID", verified.stdout)

    def test_browser_verifier_current_version_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundles_path = base / "bundles.json"
            revoked_path = base / "revoked.json"
            bundles_path.write_text(
                json.dumps([self.v1["payload"], self.v2["payload"]]),
                encoding="utf-8",
            )
            revoked_path.write_text(
                json.dumps([f"{self.policy_id}:2"]),
                encoding="utf-8",
            )
            current = self._run("current", str(bundles_path))
            self.assertEqual(current.returncode, 0, current.stderr)
            self.assertEqual(json.loads(current.stdout)["version"], 2)
            rollback = self._run("current", str(bundles_path), str(revoked_path))
            self.assertEqual(rollback.returncode, 0, rollback.stderr)
            self.assertEqual(json.loads(rollback.stdout)["version"], 1)

    def test_browser_verifier_rejects_tampered_bundle(self) -> None:
        tampered = dict(self.v2)
        tampered["payload"] = dict(self.v2["payload"])
        tampered["payload"]["rules"] = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundle_path = base / "bundle.json"
            authorities_path = base / "authorities.json"
            bundle_path.write_text(json.dumps(tampered), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([self.authority.kid]),
                encoding="utf-8",
            )
            rejected = self._run(
                "verify",
                str(bundle_path),
                str(authorities_path),
                self.policy_id,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_capability(self) -> None:
        authority = Ed25519KeyPair.generate()
        issuer = CapabilityIssuer(authority)
        request = ActionRequest(
            "urn:kinegrant:browser:request:1",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "open",
            "delivery",
        )
        rule = PolicyRule(
            "browser-rule-1",
            authority.kid,
            "urn:space:browser:*",
            "allow",
            ("open",),
        )
        decision = PolicyEngine(
            [rule],
            trusted_policy_issuers={authority.kid},
        ).evaluate(request)
        capability = issuer.issue(request, decision, ttl_seconds=300)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            envelope_path = base / "capability.json"
            request_path = base / "request.json"
            issuers_path = base / "issuers.json"
            envelope_path.write_text(json.dumps(capability), encoding="utf-8")
            request_path.write_text(
                json.dumps(request.to_dict()),
                encoding="utf-8",
            )
            issuers_path.write_text(
                json.dumps([authority.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "capability",
                str(envelope_path),
                str(request_path),
                str(issuers_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("CAPABILITY VALID", verified.stdout)

    def test_browser_verifier_verifies_python_receipt_chain(self) -> None:
        authority = Ed25519KeyPair.generate()
        issuer = CapabilityIssuer(authority)
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        gate = ActionGate(
            trusted_issuers={authority.kid},
            replay_store=InMemoryReplayStore(),
        )
        receipts = []
        for index in range(2):
            request = ActionRequest(
                f"urn:kinegrant:browser:request:{index}",
                "urn:robot:browser:1",
                "urn:space:browser:door-1",
                "open",
                "delivery",
            )
            rule = PolicyRule(
                f"browser-rule-{index}",
                authority.kid,
                "urn:space:browser:*",
                "allow",
                ("open",),
            )
            decision = PolicyEngine(
                [rule],
                trusted_policy_issuers={authority.kid},
            ).evaluate(request)
            capability = issuer.issue(request, decision, ttl_seconds=300)
            verified = gate.authorize(capability, request)
            receipts.append(
                log.append(verified, result="succeeded", request=request)
            )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            entries_path = base / "receipts.json"
            executors_path = base / "executors.json"
            entries_path.write_text(json.dumps(receipts), encoding="utf-8")
            executors_path.write_text(
                json.dumps([executor.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "receipts",
                str(entries_path),
                str(executors_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("RECEIPT CHAIN VALID", verified.stdout)

    def test_browser_verifier_verifies_python_mpt_evidence(self) -> None:
        evidence = run_machine_permission_test()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            evidence_path = base / "evidence.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            verified = self._run("mpt", str(evidence_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("MPT EVIDENCE VALID", verified.stdout)

    def test_browser_verifier_verifies_python_revocation_bundle(self) -> None:
        authority = Ed25519KeyPair.generate()
        revocations = RevocationList()
        revocations.revoke(
            "kinegrant:cap:" + "d" * 64,
            reason="fleet maintenance",
        )
        bundle = sign_revocation_bundle(
            build_revocation_bundle(
                revocations,
                issuer=authority.kid,
            ),
            authority,
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundle_path = base / "revocation.json"
            authorities_path = base / "authorities.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([authority.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "revocation",
                str(bundle_path),
                str(authorities_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("REVOCATION BUNDLE VALID", verified.stdout)

    def test_browser_verifier_verifies_python_distribution_report(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:browser:policy:door"
        bundle = authority.publish(
            policy_id,
            self.rules_v1,
            ttl_seconds=3600,
        )
        registry = PolicyRegistry(trusted_authorities={authority.kid})
        report = PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(bundle, {"gate-a": registry})
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "report.json"
            bundle_path = base / "bundle.json"
            authorities_path = base / "authorities.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([authority.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "distribution-report",
                str(report_path),
                str(bundle_path),
                str(authorities_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY DISTRIBUTION REPORT VALID", verified.stdout)

    def test_browser_verifier_verifies_python_evidence_packet(self) -> None:
        authority = Ed25519KeyPair.generate()
        issuer = CapabilityIssuer(authority)
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        gate = ActionGate(
            trusted_issuers={authority.kid},
            replay_store=InMemoryReplayStore(),
        )
        for index in range(2):
            request = ActionRequest(
                f"urn:kinegrant:browser:request:{index}",
                "urn:robot:browser:1",
                "urn:space:browser:door-1",
                "open",
                "delivery",
            )
            rule = PolicyRule(
                f"browser-rule-{index}",
                authority.kid,
                "urn:space:browser:*",
                "allow",
                ("open",),
            )
            decision = PolicyEngine(
                [rule],
                trusted_policy_issuers={authority.kid},
            ).evaluate(request)
            capability = issuer.issue(request, decision, ttl_seconds=300)
            verified = gate.authorize(capability, request)
            log.append(verified, result="succeeded", request=request)
        auditor = ReceiptAuditor(
            log.entries,
            trusted_executors={executor.kid},
        )
        packet = auditor.export_packet()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "packet.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("evidence-packet", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("EVIDENCE PACKET VALID", verified.stdout)

    def test_browser_verifier_verifies_python_audit_csv(self) -> None:
        authority = Ed25519KeyPair.generate()
        issuer = CapabilityIssuer(authority)
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        gate = ActionGate(
            trusted_issuers={authority.kid},
            replay_store=InMemoryReplayStore(),
        )
        request = ActionRequest(
            "urn:kinegrant:browser:request:1",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "open",
            "delivery",
        )
        rule = PolicyRule(
            "browser-rule-1",
            authority.kid,
            "urn:space:browser:*",
            "allow",
            ("open",),
        )
        decision = PolicyEngine(
            [rule],
            trusted_policy_issuers={authority.kid},
        ).evaluate(request)
        capability = issuer.issue(request, decision, ttl_seconds=300)
        verified = gate.authorize(capability, request)
        log.append(verified, result="succeeded", request=request)
        auditor = ReceiptAuditor(
            log.entries,
            trusted_executors={executor.kid},
        )
        csv_text = auditor.export_csv()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            csv_path = base / "audit.csv"
            csv_path.write_text(csv_text, encoding="utf-8")
            verified = self._run("audit-csv", str(csv_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("AUDIT CSV VALID", verified.stdout)

    def test_browser_verifier_verifies_python_reproduction_report(self) -> None:
        commit = "a" * 40

        def fake_git(args: list[str]) -> str:
            return commit if args == ["rev-parse", "HEAD"] else ""

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with patch("challenge.reproduce._git", side_effect=fake_git):
                create_reproduction(output, source_commit=commit)
            report_path = output / "reproduction-report.json"
            verified = self._run("reproduction-report", str(report_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("REPRODUCTION REPORT VALID", verified.stdout)


if __name__ == "__main__":
    unittest.main()
