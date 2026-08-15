from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from kinegrant.capability import CapabilityIssuer
from kinegrant.audit import ReceiptAuditor
from kinegrant.canonical import content_id, digest
from kinegrant.crypto import Ed25519KeyPair, MLDSA65KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule, isoformat, utc_now
from kinegrant.mpt import run_machine_permission_test
from kinegrant.policy import PolicyEngine
from kinegrant.policy_bundle import (
    PolicyAuthority,
    PolicyDistributor,
    PolicyRegistry,
    analyze_policy_bundle,
    audit_policy_bundles,
    bundle_to_odrl,
)
from kinegrant.receipt import ReceiptLog
from kinegrant.distribution import RevocationDistributor
from kinegrant.vocabulary import ACTION_TERMS
from kinegrant.obligations import KNOWN_OBLIGATIONS
from kinegrant.identity import agent_id, policy_id, target_id
from kinegrant.sequence import ActionJournal, ForbiddenCombination, SequencePolicy
from kinegrant.revocation import (
    RevocationList,
    build_revocation_bundle,
    sign_revocation_bundle,
)
from kinegrant.sensor_evidence import SensorReading, build_sensor_commitment
from kinegrant.checkpoint import build_receipt_checkpoint
from kinegrant.attestation import build_device_attestation
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

    def test_browser_verifier_verifies_python_revocation_distribution(self) -> None:
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
        gate_a = RevocationList()
        gate_b = RevocationList()
        report = RevocationDistributor(
            trusted_authorities={authority.kid}
        ).distribute(
            bundle,
            {"gate-a": gate_a, "gate-b": gate_b},
        )
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
                "revocation-distribution",
                str(report_path),
                str(bundle_path),
                str(authorities_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("REVOCATION DISTRIBUTION REPORT VALID", verified.stdout)

    def test_browser_verifier_maps_python_bundle_to_odrl(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:browser:policy:odrl"
        rules = [
            PolicyRule(
                policy_id,
                authority.kid,
                "urn:space:browser:door-1",
                "allow",
                ("open",),
                purposes=("delivery",),
                constraints={"max_force_newtons": 5},
                obligations=("emitActionReceipt",),
            )
        ]
        bundle = authority.publish(policy_id, rules, ttl_seconds=3600)
        python_document = bundle_to_odrl(
            bundle,
            trusted_authorities={authority.kid},
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundle_path = base / "bundle.json"
            authorities_path = base / "authorities.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([authority.kid]),
                encoding="utf-8",
            )
            mapped = self._run(
                "bundle-odrl",
                str(bundle_path),
                str(authorities_path),
            )
            self.assertEqual(mapped.returncode, 0, mapped.stderr)
            document = json.loads(mapped.stdout)
            self.assertEqual(document["uid"], python_document["uid"])
            self.assertEqual(document["profile"], python_document["profile"])
            self.assertEqual(
                len(document["permission"]),
                len(python_document["permission"]),
            )
            self.assertEqual(
                document["permission"][0]["duty"][0]["action"],
                "emitActionReceipt",
            )

    def test_browser_verifier_validates_action_vocabulary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            actions_path = base / "actions.json"
            actions_path.write_text(
                json.dumps(list(ACTION_TERMS)),
                encoding="utf-8",
            )
            verified = self._run("vocabulary", str(actions_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("ACTION VOCABULARY VALID", verified.stdout)
            bad_path = base / "bad.json"
            bad_path.write_text(
                json.dumps(["kg.action.explode"]),
                encoding="utf-8",
            )
            rejected = self._run("vocabulary", str(bad_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_validates_obligation_vocabulary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            obligations_path = base / "obligations.json"
            obligations_path.write_text(
                json.dumps(list(KNOWN_OBLIGATIONS)),
                encoding="utf-8",
            )
            verified = self._run("obligations", str(obligations_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("OBLIGATION VOCABULARY VALID", verified.stdout)
            bad_path = base / "bad.json"
            bad_path.write_text(
                json.dumps(["eraseMemory"]),
                encoding="utf-8",
            )
            rejected = self._run("obligations", str(bad_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_validates_identity_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            identifiers_path = base / "identifiers.json"
            identifiers_path.write_text(
                json.dumps(
                    [
                        agent_id("zoah", "delivery-robot-07"),
                        target_id("zoah", "door-7"),
                        policy_id("zoah", "delivery-door#permission-0"),
                    ]
                ),
                encoding="utf-8",
            )
            verified = self._run("identities", str(identifiers_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("IDENTITY SYNTAX VALID", verified.stdout)
            self.assertIn("delivery-robot-07", verified.stdout)
            bad_path = base / "bad.json"
            bad_path.write_text(
                json.dumps(["urn:kinegrant:agent:ZOAH:robot"]),
                encoding="utf-8",
            )
            rejected = self._run("identities", str(bad_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_policy_analysis(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:browser:policy:analysis"
        rules = [
            PolicyRule(
                policy_id,
                authority.kid,
                "urn:space:browser:door-1",
                "allow",
                ("open",),
                purposes=("delivery",),
            ),
            PolicyRule(
                policy_id,
                authority.kid,
                "urn:space:browser:door-*",
                "deny",
                ("open",),
                purposes=("delivery",),
            ),
        ]
        bundle = authority.publish(policy_id, rules, ttl_seconds=3600)
        report = analyze_policy_bundle(
            bundle,
            trusted_authorities={authority.kid},
        )
        self.assertEqual(report["overall_result"], "FAIL")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "analysis.json"
            bundle_path = base / "bundle.json"
            authorities_path = base / "authorities.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([authority.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "analysis",
                str(report_path),
                str(bundle_path),
                str(authorities_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY ANALYSIS VALID", verified.stdout)
            tampered = dict(report)
            tampered["summary"] = dict(report["summary"])
            tampered["summary"]["errors"] = 0
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run(
                "analysis",
                str(tampered_path),
                str(bundle_path),
                str(authorities_path),
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_delegation_chain(self) -> None:
        issuer = CapabilityIssuer(Ed25519KeyPair.generate())
        rule = PolicyRule(
            "delegation-rule-1",
            issuer.key_pair.kid,
            "door-*",
            "allow",
            ("open", "close"),
            purposes=("delivery",),
        )
        engine = PolicyEngine(
            [rule],
            trusted_policy_issuers={issuer.key_pair.kid},
        )
        request = ActionRequest(
            "req-delegation-1",
            "robot-1",
            "door-7",
            "open",
            "delivery",
        )
        decision = engine.evaluate(request)
        root = issuer.issue_scoped(
            request,
            decision,
            ttl_seconds=60,
            target="door-*",
            actions=["open", "close"],
            purposes=["delivery"],
            delegation_allowed=True,
            max_delegation_depth=2,
            delegate_allowlist=["delegate-*"],
            wire_version="1.0",
        )
        delegate_request = ActionRequest(
            "req-delegation-2",
            "delegate-1",
            "door-7",
            "open",
            "delivery",
        )
        child = issuer.issue_attenuated(
            root,
            target="door-7",
            actions=["open"],
            purposes=["delivery"],
            ttl_seconds=30,
            delegate_agent="delegate-1",
            delegate_request=delegate_request,
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            chain_path = base / "chain.json"
            request_path = base / "request.json"
            issuers_path = base / "issuers.json"
            chain_path.write_text(json.dumps([root, child]), encoding="utf-8")
            request_path.write_text(
                json.dumps(delegate_request.to_dict()),
                encoding="utf-8",
            )
            issuers_path.write_text(
                json.dumps([issuer.key_pair.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "delegation",
                str(chain_path),
                str(request_path),
                str(issuers_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("DELEGATION CHAIN VALID", verified.stdout)

            bad_body = dict(child["payload"])
            bad_body["delegate_agent"] = "other-1"
            unsigned = {
                key: value
                for key, value in bad_body.items()
                if key not in ("capability_id", "root_capability_id")
            }
            bad_body["capability_id"] = content_id("kinegrant:cap", unsigned)
            bad_child = issuer.key_pair.sign_envelope(bad_body)
            bad_chain_path = base / "bad-chain.json"
            bad_chain_path.write_text(
                json.dumps([root, bad_child]),
                encoding="utf-8",
            )
            rejected = self._run(
                "delegation",
                str(bad_chain_path),
                str(request_path),
                str(issuers_path),
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_sequence_check(self) -> None:
        journal = ActionJournal()
        journal.record(
            "record",
            "cam-1",
            at=datetime(2026, 8, 15, 0, 8, tzinfo=timezone.utc),
        )
        journal.record(
            "train_on_data",
            "cam-1",
            at=datetime(2026, 8, 15, 0, 9, tzinfo=timezone.utc),
        )
        policy = SequencePolicy(
            [
                ForbiddenCombination(
                    "forbid-camera",
                    (("record", "*"), ("train_on_data", "*")),
                    trigger=("train_on_data", "*"),
                )
            ]
        )
        request = ActionRequest(
            "req-train-1",
            "robot-1",
            "cam-1",
            "train_on_data",
            "training",
        )
        verdict = policy.evaluate(request, journal)
        self.assertFalse(verdict.allowed)
        entries = [
            {"action": entry.action, "target": entry.target, "at": isoformat(entry.at)}
            for entry in journal.entries
        ]
        report = {
            "type": "kinegrant:SequenceCheckReport",
            "schema_version": "0.1",
            "policy_id": "forbid-camera-policy",
            "request_digest": request.digest,
            "journal_digest": content_id("sha256", entries),
            "checked_at": "2026-08-15T00:10:00Z",
            "verdict": verdict.to_dict(),
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "sequence-report.json"
            policy_path = base / "sequence-policy.json"
            request_path = base / "sequence-request.json"
            journal_path = base / "sequence-journal.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            policy_path.write_text(
                json.dumps(
                    {
                        "combinations": [
                            {
                                "combination_id": combination.combination_id,
                                "patterns": [
                                    list(pattern)
                                    for pattern in combination.patterns
                                ],
                                "window_seconds": combination.window_seconds,
                                "trigger": (
                                    list(combination.trigger)
                                    if combination.trigger is not None
                                    else None
                                ),
                            }
                            for combination in policy.combinations
                        ]
                    }
                ),
                encoding="utf-8",
            )
            request_path.write_text(
                json.dumps(request.to_dict()),
                encoding="utf-8",
            )
            journal_path.write_text(json.dumps(entries), encoding="utf-8")
            verified = self._run(
                "sequence",
                str(report_path),
                str(policy_path),
                str(request_path),
                str(journal_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("SEQUENCE CHECK VALID", verified.stdout)
            evaluated = self._run(
                "sequence-eval",
                str(policy_path),
                str(request_path),
                str(journal_path),
            )
            self.assertEqual(evaluated.returncode, 0, evaluated.stderr)
            self.assertIn("SEQUENCE EVAL (allowed=false", evaluated.stdout)
            tampered = dict(report)
            tampered["verdict"] = dict(report["verdict"])
            tampered["verdict"]["allowed"] = True
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run(
                "sequence",
                str(tampered_path),
                str(policy_path),
                str(request_path),
                str(journal_path),
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_mldsa65_bundle(self) -> None:
        key = MLDSA65KeyPair.generate()
        now = utc_now()
        payload = {
            "type": "kinegrant:PolicyBundle",
            "schema_version": "0.1",
            "policy_id": "urn:kinegrant:policy:mldsa:1",
            "issuer": key.kid,
            "version": 1,
            "previous_version_digest": None,
            "issued_at": isoformat(now),
            "not_before": isoformat(now),
            "not_after": isoformat(now.replace(year=2099)),
            "rules": [
                {
                    "policy_id": "urn:kinegrant:policy:mldsa:1",
                    "issuer": key.kid,
                    "target": "urn:space:door-1",
                    "effect": "allow",
                    "actions": ["open"],
                    "subjects": ["*"],
                    "purposes": ["delivery"],
                    "constraints": {},
                    "obligations": [],
                    "priority": 0,
                    "source": {},
                }
            ],
        }
        payload["policy_digest"] = digest({"rules": payload["rules"]})
        payload["bundle_id"] = content_id("kinegrant:policy-bundle", payload)
        envelope = key.sign_envelope(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            bundle_path = base / "mldsa-bundle.json"
            authorities_path = base / "mldsa-authorities.json"
            bundle_path.write_text(json.dumps(envelope), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([key.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "verify",
                str(bundle_path),
                str(authorities_path),
                "urn:kinegrant:policy:mldsa:1",
            )
            if (
                verified.returncode == 2
                and "ML-DSA-65 is not supported" in verified.stderr
            ):
                self.skipTest("ML-DSA-65 WebCrypto is not available in node")
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY BUNDLE VALID", verified.stdout)
            mldsa = self._run("mldsa", str(bundle_path))
            if (
                mldsa.returncode == 2
                and "ML-DSA-65 is not supported" in mldsa.stderr
            ):
                self.skipTest("ML-DSA-65 WebCrypto is not available in node")
            self.assertEqual(mldsa.returncode, 0, mldsa.stderr)
            self.assertIn("ML-DSA-65 ENVELOPE VALID", mldsa.stdout)
            tampered = dict(envelope)
            tampered["payload"] = dict(envelope["payload"])
            tampered["payload"]["rules"] = []
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run(
                "verify",
                str(tampered_path),
                str(authorities_path),
                "urn:kinegrant:policy:mldsa:1",
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_conformance_report(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "kinegrant.conformance"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:1000])
        report = json.loads(proc.stdout)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "conformance.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            verified = self._run("conformance", str(report_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("CONFORMANCE REPORT VALID", verified.stdout)
            tampered = dict(report)
            tampered["summary"] = dict(report["summary"])
            tampered["summary"]["passed"] -= 1
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("conformance", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_fleet_audit_summary(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        bundle = authority.publish(
            "urn:kinegrant:policy:audit:1",
            [
                PolicyRule(
                    "audit-rule-1",
                    authority.kid,
                    "door-1",
                    "allow",
                    ("open",),
                    purposes=("delivery",),
                )
            ],
            ttl_seconds=3600,
        )
        report = audit_policy_bundles(
            {"fleet-a": bundle},
            trusted_authorities={authority.kid},
        )
        self.assertEqual(report["overall_result"], "PASS")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "audit.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            verified = self._run("fleet-audit", str(report_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY AUDIT SUMMARY VALID", verified.stdout)
            tampered = dict(report)
            tampered["summary"] = dict(report["summary"])
            tampered["summary"]["verified"] = 0
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("fleet-audit", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

            tampered_bundle = dict(bundle)
            tampered_bundle["payload"] = dict(bundle["payload"])
            tampered_bundle["payload"]["rules"] = []
            fail_report = audit_policy_bundles(
                {"fleet-b": tampered_bundle},
                trusted_authorities={authority.kid},
            )
            self.assertEqual(fail_report["overall_result"], "FAIL")
            fail_path = base / "fail.json"
            fail_path.write_text(json.dumps(fail_report), encoding="utf-8")
            checked = self._run("fleet-audit", str(fail_path))
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertIn("POLICY AUDIT SUMMARY VALID (FAIL", checked.stdout)

    def test_browser_verifier_verifies_python_security_review_kit(self) -> None:
        from kinegrant import __version__

        kit = {
            "type": "kinegrant:SecurityReviewKit",
            "schema_version": "0.1",
            "generated_at": "2026-08-15T01:00:00Z",
            "reference_implementation": __version__,
            "source_commit": "0" * 40,
            "overall_result": "PASS",
            "checks": {
                "conformance": {"status": "PASS", "detail": "23/23"},
                "machine_permission_test": {
                    "status": "PASS",
                    "detail": "22/22",
                    "schema_version": "0.5",
                },
                "red_team": {"status": "PASS", "detail": "11/11"},
                "benchmarks": {
                    "status": "PASS",
                    "detail": "machine-readable throughput emitted",
                    "operations_per_second": 1234.5,
                },
                "unit_tests": {"status": "PASS", "detail": "OK (skipped=10)"},
                "release_packet": {
                    "status": "SKIP",
                    "detail": "no release directory supplied",
                },
            },
            "checklist": [
                {
                    "id": "default-deny",
                    "name": "Default deny and deny-overrides",
                    "evidence": "spec/KGP-001.md",
                    "status": "PASS",
                }
            ],
            "commands": ["python -m unittest discover -s tests"],
            "artifacts": {
                "specification": "spec/KGP-001.md",
                "threat_model": "spec/THREAT-MODEL.md",
                "standards_mapping": "spec/STANDARD-MAPPING.md",
                "reproducing": "REPRODUCING.md",
                "deployment_cases": "docs/DEPLOYMENT-CASES.md",
                "releases": [
                    "https://github.com/zoahdev/kinegrant-protocol/releases/tag/v2.24.0"
                ],
            },
            "limitations": ["not a security audit"],
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            kit_path = base / "kit.json"
            kit_path.write_text(json.dumps(kit), encoding="utf-8")
            verified = self._run("kit", str(kit_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("SECURITY REVIEW KIT VALID", verified.stdout)
            tampered = dict(kit)
            tampered["overall_result"] = "FAIL"
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("kit", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)
            failed = dict(kit)
            failed["overall_result"] = "FAIL"
            failed["checks"] = dict(kit["checks"])
            failed["checks"]["unit_tests"] = {
                "status": "FAIL",
                "detail": "FAILED (errors=1)",
            }
            failed_path = base / "failed.json"
            failed_path.write_text(json.dumps(failed), encoding="utf-8")
            checked = self._run("kit", str(failed_path))
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertIn("SECURITY REVIEW KIT VALID (FAIL", checked.stdout)

    def test_browser_verifier_verifies_python_esp32c3_evidence(self) -> None:
        template_path = ROOT / "proof" / "esp32-c3" / "physical-proof-evidence.template.json"
        template = json.loads(template_path.read_text(encoding="utf-8"))
        profile = {
            "HWP-001": (20, 0, 0, 20),
            "HWP-002": (20, 20, 20, 0),
            "HWP-003": (20, 0, 0, 20),
            "HWP-004": (3, 0, 0, 3),
            "HWP-005": (1, 0, 0, 1),
            "HWP-006": (2, 0, 0, 2),
            "HWP-007": (64, 1, 1, 63),
            "HWP-008": (1, 0, 0, 1),
            "HWP-009": (2, 0, 0, 2),
            "HWP-010": (4, 0, 0, 0),
            "HWP-011": (100, 100, 100, 0),
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            template_out = base / "template.json"
            template_out.write_text(json.dumps(template), encoding="utf-8")
            verified = self._run("esp32", str(template_out))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("ESP32-C3 EVIDENCE VALID (NOT_RUN", verified.stdout)
            tampered = dict(template)
            tampered["cases"] = [dict(case) for case in template["cases"]]
            tampered["cases"][0]["attempts"] = 1
            tampered_out = base / "tampered.json"
            tampered_out.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("esp32", str(tampered_out))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)
            cases = []
            for case_id, (attempts, calls, movements, denials) in profile.items():
                cases.append(
                    {
                        "id": case_id,
                        "name": "case " + case_id,
                        "attempts": attempts,
                        "passed": True,
                        "measurements": {
                            "actuator_calls": calls,
                            "observed_movements": movements,
                            "denials": denials,
                            "abnormal_resets": 0,
                            "overheat_events": 0,
                        },
                        "artifact_digests": [],
                        "notes": "ok",
                    }
                )
            sim = dict(template)
            sim["overall_result"] = "SIMULATION_PASS"
            sim["started_at"] = "2026-08-10T00:00:00Z"
            sim["finished_at"] = "2026-08-10T00:30:00Z"
            sim["verification"] = {
                "allow_receipts_verified": True,
                "deny_receipts_verified": True,
                "tampered_receipts_rejected": True,
                "untrusted_executor_rejected": True,
                "device_acks_verified": True,
            }
            sim["cases"] = cases
            sim_out = base / "sim.json"
            sim_out.write_text(json.dumps(sim), encoding="utf-8")
            checked = self._run("esp32", str(sim_out))
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertIn("ESP32-C3 EVIDENCE VALID (SIMULATION_PASS", checked.stdout)

    def test_browser_verifier_verifies_python_fleet_operations_report(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:ops:1"
        bundle = authority.publish(
            policy_id,
            [
                PolicyRule(
                    "ops-rule-1",
                    authority.kid,
                    "door-1",
                    "allow",
                    ("open",),
                    purposes=("delivery",),
                )
            ],
            ttl_seconds=3600,
        )
        registry_a = PolicyRegistry(trusted_authorities={authority.kid})
        registry_b = PolicyRegistry(trusted_authorities={authority.kid})
        policy_report = PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(
            bundle,
            {"gate-a": registry_a, "gate-b": registry_b},
        )
        revocations = RevocationList()
        revocations.revoke(
            "kinegrant:cap:" + "d" * 64,
            reason="fleet maintenance",
        )
        revocation_key = Ed25519KeyPair.generate()
        revocation_bundle = sign_revocation_bundle(
            build_revocation_bundle(
                revocations,
                issuer=revocation_key.kid,
            ),
            revocation_key,
        )
        gate_a = RevocationList()
        gate_b = RevocationList()
        revocation_report = RevocationDistributor(
            trusted_authorities={revocation_key.kid}
        ).distribute(
            revocation_bundle,
            {"gate-a": gate_a, "gate-b": gate_b},
        )
        gates_total = len(policy_report["acks"])
        policy_applied = sum(
            1 for ack in policy_report["acks"] if ack["applied"]
        )
        revocation_applied = sum(
            1 for ack in revocation_report["acks"] if ack["applied"]
        )
        fleet = {
            "type": "kinegrant:FleetOperationsReport",
            "schema_version": "0.1",
            "generated_at": "2026-08-15T01:00:00Z",
            "overall_result": (
                "PASS"
                if policy_applied == gates_total
                and revocation_applied == gates_total
                else "FAIL"
            ),
            "summary": {
                "gates_total": gates_total,
                "policy_applied": policy_applied,
                "policy_failures": gates_total - policy_applied,
                "revocation_applied": revocation_applied,
                "revocation_failures": gates_total - revocation_applied,
            },
            "policy_distribution": policy_report,
            "revocation_distribution": revocation_report,
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fleet_path = base / "fleet-ops.json"
            policy_path = base / "policy.json"
            revocation_path = base / "revocation.json"
            authorities_path = base / "authorities.json"
            fleet_path.write_text(json.dumps(fleet), encoding="utf-8")
            policy_path.write_text(json.dumps(bundle), encoding="utf-8")
            revocation_path.write_text(
                json.dumps(revocation_bundle),
                encoding="utf-8",
            )
            authorities_path.write_text(
                json.dumps([authority.kid, revocation_key.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "fleet-ops",
                str(fleet_path),
                str(policy_path),
                str(revocation_path),
                str(authorities_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("FLEET OPERATIONS REPORT VALID", verified.stdout)
            tampered = dict(fleet)
            tampered["summary"] = dict(fleet["summary"])
            tampered["summary"]["policy_applied"] -= 1
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run(
                "fleet-ops",
                str(tampered_path),
                str(policy_path),
                str(revocation_path),
                str(authorities_path),
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)
            mismatched = dict(fleet)
            mismatched["policy_distribution"] = dict(policy_report)
            mismatched["policy_distribution"]["acks"] = [
                dict(ack) for ack in policy_report["acks"]
            ]
            mismatched["policy_distribution"]["acks"][0]["gate_id"] = "gate-c"
            mismatched_path = base / "mismatched.json"
            mismatched_path.write_text(json.dumps(mismatched), encoding="utf-8")
            gate_rejected = self._run(
                "fleet-ops",
                str(mismatched_path),
                str(policy_path),
                str(revocation_path),
                str(authorities_path),
            )
            self.assertEqual(gate_rejected.returncode, 2)
            self.assertIn("INVALID", gate_rejected.stderr)

    def test_browser_verifier_verifies_python_benchmark_report(self) -> None:
        import benchmarks.bench as bench_module

        report = bench_module.run(iterations=30)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "bench.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            verified = self._run("bench", str(report_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("BENCHMARK REPORT VALID", verified.stdout)
            tampered = dict(report)
            tampered["operations_per_second"] = dict(
                report["operations_per_second"]
            )
            del tampered["operations_per_second"]["jcs_digest"]
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("bench", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_policy_lifecycle_trace(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:lifecycle:1"
        bundle = authority.publish(
            policy_id,
            [
                PolicyRule(
                    "lifecycle-rule-1",
                    authority.kid,
                    "door-1",
                    "allow",
                    ("open",),
                    purposes=("delivery",),
                )
            ],
            ttl_seconds=3600,
        )
        phases = []
        for phase in ("publish", "enforce", "odrl", "distribute", "audit", "revoke"):
            phases.append(
                {
                    "phase": phase,
                    "status": "PASS",
                    "detail": f"{phase} verified",
                    "artifact": None,
                }
            )
        trace = {
            "type": "kinegrant:PolicyLifecycleTrace",
            "schema_version": "0.1",
            "policy_id": policy_id,
            "bundle_id": bundle["payload"]["bundle_id"],
            "bundle_version": 1,
            "generated_at": "2026-08-15T01:00:00Z",
            "phases": phases,
            "summary": {"phases_total": 6, "passed": 6, "failed": 0},
            "overall_result": "PASS",
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            trace_path = base / "trace.json"
            bundle_path = base / "bundle.json"
            authorities_path = base / "authorities.json"
            trace_path.write_text(json.dumps(trace), encoding="utf-8")
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([authority.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "lifecycle",
                str(trace_path),
                str(bundle_path),
                str(authorities_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY LIFECYCLE TRACE VALID", verified.stdout)
            tampered = dict(trace)
            tampered["summary"] = dict(trace["summary"])
            tampered["summary"]["passed"] = 5
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run(
                "lifecycle",
                str(tampered_path),
                str(bundle_path),
                str(authorities_path),
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)
            swapped = dict(trace)
            swapped["phases"] = [dict(phase) for phase in trace["phases"]]
            swapped["phases"][0], swapped["phases"][1] = (
                swapped["phases"][1],
                swapped["phases"][0],
            )
            swapped_path = base / "swapped.json"
            swapped_path.write_text(json.dumps(swapped), encoding="utf-8")
            order_rejected = self._run(
                "lifecycle",
                str(swapped_path),
                str(bundle_path),
                str(authorities_path),
            )
            self.assertEqual(order_rejected.returncode, 2)
            self.assertIn("INVALID", order_rejected.stderr)

    def test_browser_verifier_verifies_python_sensor_and_checkpoint(self) -> None:
        key = Ed25519KeyPair.generate()
        reading = SensorReading(
            kind="force",
            value={"newtons": 1.5},
            source_id="sensor-1",
            confidence=0.9,
            observed_at="2026-08-15T00:00:00Z",
        )
        commitment = build_sensor_commitment(
            [reading],
            sensor_kid=key.kid,
            key_pair=key,
            committed_at="2026-08-15T00:00:00Z",
        )
        checkpoint = build_receipt_checkpoint(
            "sha256:" + "b" * 64,
            notary_kid=key.kid,
            key_pair=key,
            period="daily",
            issued_at="2026-08-15T00:00:00Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            commitment_path = base / "commitment.json"
            checkpoint_path = base / "checkpoint.json"
            commitment_path.write_text(json.dumps(commitment), encoding="utf-8")
            checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
            verified = self._run("sensor", str(commitment_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("SENSOR COMMITMENT VALID", verified.stdout)
            checkpoint_verified = self._run("checkpoint", str(checkpoint_path))
            self.assertEqual(checkpoint_verified.returncode, 0, checkpoint_verified.stderr)
            self.assertIn("RECEIPT CHECKPOINT VALID", checkpoint_verified.stdout)
            tampered = dict(commitment)
            tampered["payload"] = dict(commitment["payload"])
            tampered["payload"]["readings"] = [
                dict(commitment["payload"]["readings"][0])
            ]
            tampered["payload"]["readings"][0]["confidence"] = 1.5
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("sensor", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)
            bad_checkpoint = dict(checkpoint)
            bad_checkpoint["payload"] = dict(checkpoint["payload"])
            bad_checkpoint["payload"]["period"] = "hourly"
            bad_path = base / "bad-checkpoint.json"
            bad_path.write_text(json.dumps(bad_checkpoint), encoding="utf-8")
            checkpoint_rejected = self._run("checkpoint", str(bad_path))
            self.assertEqual(checkpoint_rejected.returncode, 2)
            self.assertIn("INVALID", checkpoint_rejected.stderr)

    def test_browser_verifier_verifies_python_device_attestation(self) -> None:
        key = Ed25519KeyPair.generate()
        attestation = build_device_attestation(
            device_id="device:esp32c3:paper-barrier:unit-1",
            firmware_digest="sha256:" + "c" * 64,
            boot_counter=3,
            device_key=key,
            measured_boot=[
                {"stage": "bootloader", "digest": "sha256:" + "d" * 64}
            ],
            issued_at="2026-08-15T00:00:00Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            attestation_path = base / "attestation.json"
            attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
            verified = self._run("attestation", str(attestation_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("DEVICE ATTESTATION VALID", verified.stdout)
            tampered = dict(attestation)
            tampered["payload"] = dict(attestation["payload"])
            tampered["payload"]["boot_counter"] = -1
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("attestation", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_bridge_demo_reports(self) -> None:
        for module in (
            "kinegrant.experimental.ros2_demo",
            "kinegrant.experimental.bridge_demo",
        ):
            proc = subprocess.run(
                [sys.executable, "-m", module],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[:1000])
            report = json.loads(proc.stdout)
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                report_path = base / "bridge.json"
                report_path.write_text(json.dumps(report), encoding="utf-8")
                verified = self._run("bridge", str(report_path))
                self.assertEqual(verified.returncode, 0, verified.stderr)
                self.assertIn("BRIDGE DEMO REPORT VALID", verified.stdout)
                tampered = dict(report)
                tampered["summary"] = dict(report["summary"])
                tampered["summary"]["passed"] -= 1
                tampered_path = base / "tampered.json"
                tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
                rejected = self._run("bridge", str(tampered_path))
                self.assertEqual(rejected.returncode, 2)
                self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_hardware_trust_packet(self) -> None:
        key = Ed25519KeyPair.generate()
        attestation = build_device_attestation(
            device_id="device:esp32c3:paper-barrier:unit-1",
            firmware_digest="sha256:" + "c" * 64,
            boot_counter=3,
            device_key=key,
            measured_boot=[
                {"stage": "bootloader", "digest": "sha256:" + "d" * 64}
            ],
            issued_at="2026-08-15T00:00:00Z",
        )
        reading = SensorReading(
            kind="force",
            value={"newtons": 1.5},
            source_id="sensor-1",
            confidence=0.9,
            observed_at="2026-08-15T00:00:00Z",
        )
        commitment = build_sensor_commitment(
            [reading],
            sensor_kid=key.kid,
            key_pair=key,
            committed_at="2026-08-15T00:00:00Z",
        )
        checkpoint = build_receipt_checkpoint(
            "sha256:" + "b" * 64,
            notary_kid=key.kid,
            key_pair=key,
            period="daily",
            issued_at="2026-08-15T00:00:00Z",
        )
        packet = {
            "type": "kinegrant:HardwareTrustPacket",
            "schema_version": "0.1",
            "device_id": "device:esp32c3:paper-barrier:unit-1",
            "generated_at": "2026-08-15T01:00:00Z",
            "overall_result": "PASS",
            "device_attestation": attestation,
            "sensor_commitments": [commitment],
            "receipt_checkpoints": [checkpoint],
            "summary": {
                "device_attestations": 1,
                "sensor_commitments": 1,
                "receipt_checkpoints": 1,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "packet.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("hardware-packet", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("HARDWARE TRUST PACKET VALID", verified.stdout)
            tampered = dict(packet)
            tampered["summary"] = dict(packet["summary"])
            tampered["summary"]["sensor_commitments"] = 2
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("hardware-packet", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_robot_demo_report(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "kinegrant.experimental.robot_demo"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:1000])
        report = json.loads(proc.stdout)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "robot.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            verified = self._run("robot-demo", str(report_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("ROBOT DEMO REPORT VALID", verified.stdout)
            tampered = dict(report)
            tampered["summary"] = dict(report["summary"])
            tampered["summary"]["passed"] -= 1
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("robot-demo", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_camera_consent_trace(self) -> None:
        proc = subprocess.run(
            [sys.executable, "examples/camera-consent/camera_consent.py"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:1000])
        trace = json.loads(proc.stdout)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            trace_path = base / "camera.json"
            trace_path.write_text(json.dumps(trace), encoding="utf-8")
            verified = self._run("camera-consent", str(trace_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("CAMERA CONSENT TRACE VALID", verified.stdout)
            tampered = dict(trace)
            tampered["passed"] = not trace["passed"]
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("camera-consent", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_full_lifecycle_report(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:lifecycle:1"
        bundle = authority.publish(
            policy_id,
            [
                PolicyRule(
                    "lifecycle-rule-1",
                    authority.kid,
                    "door-1",
                    "allow",
                    ("open",),
                    purposes=("delivery",),
                )
            ],
            ttl_seconds=3600,
        )
        registry = PolicyRegistry(trusted_authorities={authority.kid})
        distribution = PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(bundle, {"gate-a": registry})
        audit = audit_policy_bundles(
            {"fleet-a": bundle},
            trusted_authorities={authority.kid},
        )
        revocations = RevocationList()
        revocations.revoke(
            "kinegrant:cap:" + "d" * 64,
            reason="fleet maintenance",
        )
        revocation_key = Ed25519KeyPair.generate()
        revocation_bundle = sign_revocation_bundle(
            build_revocation_bundle(
                revocations,
                issuer=revocation_key.kid,
            ),
            revocation_key,
        )
        revocation_gate = RevocationList()
        revocation = RevocationDistributor(
            trusted_authorities={revocation_key.kid}
        ).distribute(revocation_bundle, {"gate-a": revocation_gate})
        report = {
            "type": "kinegrant:FullLifecycleReport",
            "schema_version": "0.1",
            "policy_id": policy_id,
            "bundle_id": bundle["payload"]["bundle_id"],
            "bundle_version": 1,
            "generated_at": "2026-08-15T01:00:00Z",
            "overall_result": "PASS",
            "summary": {"phases_total": 4, "passed": 4, "failed": 0},
            "policy_distribution": distribution,
            "audit_summary": audit,
            "revocation_distribution": revocation,
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            report_path = base / "lifecycle.json"
            policy_path = base / "policy.json"
            revocation_path = base / "revocation.json"
            authorities_path = base / "authorities.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            policy_path.write_text(json.dumps(bundle), encoding="utf-8")
            revocation_path.write_text(
                json.dumps(revocation_bundle),
                encoding="utf-8",
            )
            authorities_path.write_text(
                json.dumps([authority.kid, revocation_key.kid]),
                encoding="utf-8",
            )
            verified = self._run(
                "full-lifecycle",
                str(report_path),
                str(policy_path),
                str(revocation_path),
                str(authorities_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("FULL LIFECYCLE REPORT VALID", verified.stdout)
            tampered = dict(report)
            tampered["audit_summary"] = dict(audit)
            tampered["audit_summary"]["bundles"] = [
                dict(entry) for entry in audit["bundles"]
            ]
            tampered["audit_summary"]["bundles"][0]["policy_id"] = "other"
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run(
                "full-lifecycle",
                str(tampered_path),
                str(policy_path),
                str(revocation_path),
                str(authorities_path),
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_evidence_export_packet(self) -> None:
        import hashlib

        def digest_bytes(payload: bytes) -> str:
            return "sha256:" + hashlib.sha256(payload).hexdigest()

        packet = {
            "type": "kinegrant:EvidenceExportPacket",
            "schema_version": "0.1",
            "generated_at": "2026-08-15T01:00:00Z",
            "overall_result": "PASS",
            "artifacts": [
                {
                    "kind": "mpt_evidence",
                    "name": "machine-permission-test.evidence.json",
                    "sha256": digest_bytes(b"mpt-evidence"),
                },
                {
                    "kind": "conformance_report",
                    "name": "conformance-report.json",
                    "sha256": digest_bytes(b"conformance"),
                },
            ],
            "summary": {"artifacts_total": 2, "unique_kinds": 2, "digest_verified": True},
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "export.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("evidence-export", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("EVIDENCE EXPORT PACKET VALID", verified.stdout)
            tampered = dict(packet)
            tampered["artifacts"] = [dict(artifact) for artifact in packet["artifacts"]]
            tampered["artifacts"][0]["sha256"] = "sha256:" + "0" * 63
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("evidence-export", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_device_to_policy_export_packet(
        self,
    ) -> None:
        from datetime import timedelta

        from kinegrant.sensor_evidence import evidence_hash_for_commitment

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        issuer = CapabilityIssuer(key)
        executor = Ed25519KeyPair.generate()
        sensor_key = Ed25519KeyPair.generate()
        notary_key = Ed25519KeyPair.generate()
        device_key = Ed25519KeyPair.generate()
        device_id = "device:esp32c3:paper-barrier:unit-1"
        request = ActionRequest(
            "urn:kinegrant:browser:request:device-to-policy",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "open",
            "delivery",
        )
        rule = PolicyRule(
            "device-to-policy-rule-1",
            key.kid,
            "urn:space:browser:*",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
        bundle = authority.publish(
            "device-to-policy-rule-1",
            [rule],
            ttl_seconds=3600,
        )
        decision = PolicyEngine(
            [rule],
            trusted_policy_issuers={key.kid},
        ).evaluate(request)
        capability = issuer.issue(request, decision, ttl_seconds=300)
        reading = SensorReading(
            kind="force",
            value={"newtons": 1.5},
            source_id=device_id,
            confidence=0.9,
            observed_at="2026-08-15T00:00:00Z",
        )
        commitment = build_sensor_commitment(
            [reading],
            sensor_kid=sensor_key.kid,
            key_pair=sensor_key,
            committed_at="2026-08-15T00:00:00Z",
        )
        evidence_hash = evidence_hash_for_commitment(commitment)
        log = ReceiptLog(executor)
        gate = ActionGate(
            trusted_issuers={key.kid},
            replay_store=InMemoryReplayStore(),
        )
        started = utc_now()
        verified = gate.authorize(capability, request, now=started)
        receipt = log.append(
            verified,
            result="succeeded",
            evidence_hash=evidence_hash,
            started_at=started,
            finished_at=started + timedelta(seconds=1),
            request=request,
        )
        checkpoint = build_receipt_checkpoint(
            digest([receipt]),
            notary_kid=notary_key.kid,
            key_pair=notary_key,
            period="daily",
            issued_at="2026-08-15T00:00:00Z",
        )
        attestation = build_device_attestation(
            device_id=device_id,
            firmware_digest="sha256:" + "c" * 64,
            boot_counter=3,
            device_key=device_key,
            measured_boot=[
                {"stage": "bootloader", "digest": "sha256:" + "d" * 64}
            ],
            issued_at="2026-08-15T00:00:00Z",
        )
        cap_payload = capability["payload"]
        packet = {
            "type": "kinegrant:DeviceToPolicyExportPacket",
            "schema_version": "0.1",
            "device_id": device_id,
            "generated_at": isoformat(started + timedelta(minutes=1)),
            "overall_result": "PASS",
            "trusted_policy_issuers": [key.kid],
            "policy_bundle": bundle,
            "capability": capability,
            "request": request.to_dict(),
            "gate_decision": {
                "allowed": True,
                "reason": "allow",
                "checked_at": isoformat(started),
                "capability_id": cap_payload["capability_id"],
                "policy_digest": cap_payload["policy_digest"],
            },
            "receipt": receipt,
            "sensor_commitment": commitment,
            "receipt_checkpoint": checkpoint,
            "device_attestation": attestation,
            "summary": {
                "artifacts_total": 9,
                "policy_verified": True,
                "capability_verified": True,
                "decision_consistent": True,
                "receipt_bound": True,
                "sensor_bound": True,
                "checkpoint_bound": True,
                "attestation_bound": True,
                "cross_references_ok": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "device-to-policy.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("device-to-policy", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("DEVICE-TO-POLICY EXPORT VALID", verified.stdout)
            tampered = dict(packet)
            tampered["summary"] = dict(packet["summary"])
            tampered["summary"]["sensor_bound"] = False
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("device-to-policy", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def _build_device_to_policy_packet(
        self,
        *,
        authority_key: Ed25519KeyPair,
        rule: PolicyRule,
        bundle: dict,
        device_id: str,
        request_id: str,
    ) -> dict:
        from datetime import timedelta

        from kinegrant.sensor_evidence import evidence_hash_for_commitment

        issuer = CapabilityIssuer(authority_key)
        executor = Ed25519KeyPair.generate()
        sensor_key = Ed25519KeyPair.generate()
        notary_key = Ed25519KeyPair.generate()
        device_key = Ed25519KeyPair.generate()
        request = ActionRequest(
            request_id,
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "open",
            "delivery",
        )
        decision = PolicyEngine(
            [rule],
            trusted_policy_issuers={authority_key.kid},
        ).evaluate(request)
        capability = issuer.issue(request, decision, ttl_seconds=300)
        reading = SensorReading(
            kind="force",
            value={"newtons": 1.5},
            source_id=device_id,
            confidence=0.9,
            observed_at="2026-08-15T00:00:00Z",
        )
        commitment = build_sensor_commitment(
            [reading],
            sensor_kid=sensor_key.kid,
            key_pair=sensor_key,
            committed_at="2026-08-15T00:00:00Z",
        )
        evidence_hash = evidence_hash_for_commitment(commitment)
        log = ReceiptLog(executor)
        gate = ActionGate(
            trusted_issuers={authority_key.kid},
            replay_store=InMemoryReplayStore(),
        )
        started = utc_now()
        verified = gate.authorize(capability, request, now=started)
        receipt = log.append(
            verified,
            result="succeeded",
            evidence_hash=evidence_hash,
            started_at=started,
            finished_at=started + timedelta(seconds=1),
            request=request,
        )
        checkpoint = build_receipt_checkpoint(
            digest([receipt]),
            notary_kid=notary_key.kid,
            key_pair=notary_key,
            period="daily",
            issued_at="2026-08-15T00:00:00Z",
        )
        attestation = build_device_attestation(
            device_id=device_id,
            firmware_digest="sha256:" + "c" * 64,
            boot_counter=3,
            device_key=device_key,
            measured_boot=[
                {"stage": "bootloader", "digest": "sha256:" + "d" * 64}
            ],
            issued_at="2026-08-15T00:00:00Z",
        )
        cap_payload = capability["payload"]
        return {
            "type": "kinegrant:DeviceToPolicyExportPacket",
            "schema_version": "0.1",
            "device_id": device_id,
            "generated_at": isoformat(started + timedelta(minutes=1)),
            "overall_result": "PASS",
            "trusted_policy_issuers": [authority_key.kid],
            "policy_bundle": bundle,
            "capability": capability,
            "request": request.to_dict(),
            "gate_decision": {
                "allowed": True,
                "reason": "allow",
                "checked_at": isoformat(started),
                "capability_id": cap_payload["capability_id"],
                "policy_digest": cap_payload["policy_digest"],
            },
            "receipt": receipt,
            "sensor_commitment": commitment,
            "receipt_checkpoint": checkpoint,
            "device_attestation": attestation,
            "summary": {
                "artifacts_total": 9,
                "policy_verified": True,
                "capability_verified": True,
                "decision_consistent": True,
                "receipt_bound": True,
                "sensor_bound": True,
                "checkpoint_bound": True,
                "attestation_bound": True,
                "cross_references_ok": True,
            },
        }

    def test_browser_verifier_verifies_python_fleet_device_export_packet(
        self,
    ) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        rule = PolicyRule(
            "device-to-policy-rule-1",
            key.kid,
            "urn:space:browser:*",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
        bundle = authority.publish(
            "device-to-policy-rule-1",
            [rule],
            ttl_seconds=3600,
        )
        packet_1 = self._build_device_to_policy_packet(
            authority_key=key,
            rule=rule,
            bundle=bundle,
            device_id="device:esp32c3:paper-barrier:unit-1",
            request_id="urn:kinegrant:browser:request:fleet-1",
        )
        packet_2 = self._build_device_to_policy_packet(
            authority_key=key,
            rule=rule,
            bundle=bundle,
            device_id="device:esp32c3:paper-barrier:unit-2",
            request_id="urn:kinegrant:browser:request:fleet-2",
        )
        fleet = {
            "type": "kinegrant:FleetDeviceExportPacket",
            "schema_version": "0.1",
            "generated_at": isoformat(utc_now() + timedelta(minutes=2)),
            "overall_result": "PASS",
            "trusted_policy_issuers": [key.kid],
            "policy_bundle": bundle,
            "devices": [packet_1, packet_2],
            "summary": {
                "devices_total": 2,
                "policy_shared": True,
                "devices_verified": 2,
                "device_ids_unique": True,
                "cross_references_ok": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fleet_path = base / "fleet.json"
            fleet_path.write_text(json.dumps(fleet), encoding="utf-8")
            verified = self._run("fleet-device-export", str(fleet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("FLEET DEVICE EXPORT VALID", verified.stdout)
            tampered = dict(fleet)
            tampered["summary"] = dict(fleet["summary"])
            tampered["summary"]["devices_verified"] = 1
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("fleet-device-export", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_end_to_end_audit_export_packet(
        self,
    ) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        policy_id = "urn:kinegrant:policy:audit:1"
        rule = PolicyRule(
            "audit-rule-1",
            key.kid,
            "urn:space:browser:*",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
        bundle = authority.publish(
            policy_id,
            [rule],
            ttl_seconds=3600,
        )
        registry = PolicyRegistry(trusted_authorities={key.kid})
        distribution = PolicyDistributor(
            trusted_authorities={key.kid}
        ).distribute(bundle, {"gate-a": registry})
        audit = audit_policy_bundles(
            {"fleet-a": bundle},
            trusted_authorities={key.kid},
        )
        revocations = RevocationList()
        revocations.revoke(
            "kinegrant:cap:" + "d" * 64,
            reason="fleet maintenance",
        )
        revocation_key = Ed25519KeyPair.generate()
        revocation_bundle = sign_revocation_bundle(
            build_revocation_bundle(
                revocations,
                issuer=revocation_key.kid,
            ),
            revocation_key,
        )
        revocation_gate = RevocationList()
        revocation = RevocationDistributor(
            trusted_authorities={revocation_key.kid}
        ).distribute(revocation_bundle, {"gate-a": revocation_gate})
        lifecycle_report = {
            "type": "kinegrant:FullLifecycleReport",
            "schema_version": "0.1",
            "policy_id": policy_id,
            "bundle_id": bundle["payload"]["bundle_id"],
            "bundle_version": 1,
            "generated_at": "2026-08-15T01:00:00Z",
            "overall_result": "PASS",
            "summary": {"phases_total": 4, "passed": 4, "failed": 0},
            "policy_distribution": distribution,
            "audit_summary": audit,
            "revocation_distribution": revocation,
        }
        packet_1 = self._build_device_to_policy_packet(
            authority_key=key,
            rule=rule,
            bundle=bundle,
            device_id="device:esp32c3:paper-barrier:unit-1",
            request_id="urn:kinegrant:browser:request:audit-1",
        )
        packet_2 = self._build_device_to_policy_packet(
            authority_key=key,
            rule=rule,
            bundle=bundle,
            device_id="device:esp32c3:paper-barrier:unit-2",
            request_id="urn:kinegrant:browser:request:audit-2",
        )
        fleet_export = {
            "type": "kinegrant:FleetDeviceExportPacket",
            "schema_version": "0.1",
            "generated_at": isoformat(utc_now() + timedelta(minutes=2)),
            "overall_result": "PASS",
            "trusted_policy_issuers": [key.kid],
            "policy_bundle": bundle,
            "devices": [packet_1, packet_2],
            "summary": {
                "devices_total": 2,
                "policy_shared": True,
                "devices_verified": 2,
                "device_ids_unique": True,
                "cross_references_ok": True,
            },
        }
        packet = {
            "type": "kinegrant:EndToEndAuditExportPacket",
            "schema_version": "0.1",
            "generated_at": isoformat(utc_now() + timedelta(minutes=3)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid, revocation_key.kid],
            "policy_bundle": bundle,
            "revocation_bundle": revocation_bundle,
            "lifecycle_report": lifecycle_report,
            "fleet_export": fleet_export,
            "summary": {
                "artifacts_total": 7,
                "phases_total": 4,
                "devices_total": 2,
                "policy_shared": True,
                "lifecycle_verified": True,
                "fleet_verified": True,
                "cross_references_ok": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "audit-export.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("end-to-end-audit", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("END-TO-END AUDIT EXPORT VALID", verified.stdout)
            tampered = dict(packet)
            tampered["summary"] = dict(packet["summary"])
            tampered["summary"]["devices_total"] = 1
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("end-to-end-audit", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_revocation_reissue_closure_packet(
        self,
    ) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        issuer = CapabilityIssuer(key)
        rule = PolicyRule(
            "revoke-reissue-rule-1",
            key.kid,
            "urn:space:browser:*",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
        bundle = authority.publish(
            "revoke-reissue-rule-1",
            [rule],
            ttl_seconds=3600,
        )
        request = ActionRequest(
            "urn:kinegrant:browser:request:revoke-reissue",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "open",
            "delivery",
        )
        decision = PolicyEngine(
            [rule],
            trusted_policy_issuers={key.kid},
        ).evaluate(request)
        revoked_capability = issuer.issue(request, decision, ttl_seconds=300)
        revoked_id = revoked_capability["payload"]["capability_id"]
        revocations = RevocationList()
        revocations.revoke(revoked_id, reason="operator decision")
        revocation_key = Ed25519KeyPair.generate()
        revocation_bundle = sign_revocation_bundle(
            build_revocation_bundle(
                revocations,
                issuer=revocation_key.kid,
            ),
            revocation_key,
        )
        reissued_capability = issuer.issue(request, decision, ttl_seconds=300)
        reissued_id = reissued_capability["payload"]["capability_id"]
        self.assertNotEqual(revoked_id, reissued_id)
        started = utc_now()
        denied_at = isoformat(started - timedelta(minutes=5))
        allowed_at = isoformat(started - timedelta(minutes=4))
        gate = ActionGate(
            trusted_issuers={key.kid},
            replay_store=InMemoryReplayStore(),
            revocation_list=revocations,
        )
        with self.assertRaises(PermissionError):
            gate.authorize(revoked_capability, request, now=started)
        verified = gate.authorize(reissued_capability, request, now=started)
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        receipt = log.append(
            verified,
            result="succeeded",
            evidence_hash="sha256:" + "a" * 64,
            started_at=started,
            finished_at=started + timedelta(seconds=1),
            request=request,
        )
        cap_payload = reissued_capability["payload"]
        packet = {
            "type": "kinegrant:RevocationReissueClosurePacket",
            "schema_version": "0.1",
            "generated_at": isoformat(started + timedelta(minutes=1)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid, revocation_key.kid],
            "trusted_policy_issuers": [key.kid],
            "policy_bundle": bundle,
            "revocation_bundle": revocation_bundle,
            "revoked_capability_id": revoked_id,
            "request": request.to_dict(),
            "reissued_capability": reissued_capability,
            "gate_log": {
                "revoked_denied": {
                    "allowed": False,
                    "reason": "revoked",
                    "checked_at": denied_at,
                    "capability_id": revoked_id,
                    "policy_digest": cap_payload["policy_digest"],
                },
                "reissued_allowed": {
                    "allowed": True,
                    "reason": "allow",
                    "checked_at": allowed_at,
                    "capability_id": reissued_id,
                    "policy_digest": cap_payload["policy_digest"],
                },
            },
            "receipt": receipt,
            "summary": {
                "artifacts_total": 8,
                "policy_verified": True,
                "revocation_verified": True,
                "revoked_capability_revoked": True,
                "deny_recorded": True,
                "reissue_verified": True,
                "allow_recorded": True,
                "receipt_bound": True,
                "closure_complete": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "revocation-reissue.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("revocation-reissue", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("REVOCATION-REISSUE CLOSURE VALID", verified.stdout)
            tampered = dict(packet)
            tampered["summary"] = dict(packet["summary"])
            tampered["summary"]["closure_complete"] = False
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("revocation-reissue", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_unified_audit_export_packet(
        self,
    ) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        issuer = CapabilityIssuer(key)
        policy_id = "urn:kinegrant:policy:unified:1"
        rule = PolicyRule(
            "unified-rule-1",
            key.kid,
            "urn:space:browser:*",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
        bundle = authority.publish(
            policy_id,
            [rule],
            ttl_seconds=3600,
        )
        request = ActionRequest(
            "urn:kinegrant:browser:request:unified",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "open",
            "delivery",
        )
        decision = PolicyEngine(
            [rule],
            trusted_policy_issuers={key.kid},
        ).evaluate(request)
        revoked_capability = issuer.issue(request, decision, ttl_seconds=300)
        revoked_id = revoked_capability["payload"]["capability_id"]
        revocations = RevocationList()
        revocations.revoke(revoked_id, reason="operator decision")
        revocation_key = Ed25519KeyPair.generate()
        revocation_bundle = sign_revocation_bundle(
            build_revocation_bundle(
                revocations,
                issuer=revocation_key.kid,
            ),
            revocation_key,
        )
        reissued_capability = issuer.issue(request, decision, ttl_seconds=300)
        reissued_id = reissued_capability["payload"]["capability_id"]
        started = utc_now()
        denied_at = isoformat(started - timedelta(minutes=5))
        allowed_at = isoformat(started - timedelta(minutes=4))
        gate = ActionGate(
            trusted_issuers={key.kid},
            replay_store=InMemoryReplayStore(),
            revocation_list=revocations,
        )
        with self.assertRaises(PermissionError):
            gate.authorize(revoked_capability, request, now=started)
        verified = gate.authorize(reissued_capability, request, now=started)
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        closure_receipt = log.append(
            verified,
            result="succeeded",
            evidence_hash="sha256:" + "a" * 64,
            started_at=started,
            finished_at=started + timedelta(seconds=1),
            request=request,
        )
        cap_payload = reissued_capability["payload"]
        closure = {
            "type": "kinegrant:RevocationReissueClosurePacket",
            "schema_version": "0.1",
            "generated_at": isoformat(started + timedelta(minutes=1)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid, revocation_key.kid],
            "trusted_policy_issuers": [key.kid],
            "policy_bundle": bundle,
            "revocation_bundle": revocation_bundle,
            "revoked_capability_id": revoked_id,
            "request": request.to_dict(),
            "reissued_capability": reissued_capability,
            "gate_log": {
                "revoked_denied": {
                    "allowed": False,
                    "reason": "revoked",
                    "checked_at": denied_at,
                    "capability_id": revoked_id,
                    "policy_digest": cap_payload["policy_digest"],
                },
                "reissued_allowed": {
                    "allowed": True,
                    "reason": "allow",
                    "checked_at": allowed_at,
                    "capability_id": reissued_id,
                    "policy_digest": cap_payload["policy_digest"],
                },
            },
            "receipt": closure_receipt,
            "summary": {
                "artifacts_total": 8,
                "policy_verified": True,
                "revocation_verified": True,
                "revoked_capability_revoked": True,
                "deny_recorded": True,
                "reissue_verified": True,
                "allow_recorded": True,
                "receipt_bound": True,
                "closure_complete": True,
            },
        }
        registry = PolicyRegistry(trusted_authorities={key.kid})
        distribution = PolicyDistributor(
            trusted_authorities={key.kid}
        ).distribute(bundle, {"gate-a": registry})
        audit = audit_policy_bundles(
            {"fleet-a": bundle},
            trusted_authorities={key.kid},
        )
        revocation_gate = RevocationList()
        revocation = RevocationDistributor(
            trusted_authorities={revocation_key.kid}
        ).distribute(revocation_bundle, {"gate-a": revocation_gate})
        lifecycle_report = {
            "type": "kinegrant:FullLifecycleReport",
            "schema_version": "0.1",
            "policy_id": policy_id,
            "bundle_id": bundle["payload"]["bundle_id"],
            "bundle_version": 1,
            "generated_at": "2026-08-15T01:00:00Z",
            "overall_result": "PASS",
            "summary": {"phases_total": 4, "passed": 4, "failed": 0},
            "policy_distribution": distribution,
            "audit_summary": audit,
            "revocation_distribution": revocation,
        }
        packet_1 = self._build_device_to_policy_packet(
            authority_key=key,
            rule=rule,
            bundle=bundle,
            device_id="device:esp32c3:paper-barrier:unit-1",
            request_id="urn:kinegrant:browser:request:unified-1",
        )
        packet_2 = self._build_device_to_policy_packet(
            authority_key=key,
            rule=rule,
            bundle=bundle,
            device_id="device:esp32c3:paper-barrier:unit-2",
            request_id="urn:kinegrant:browser:request:unified-2",
        )
        fleet_export = {
            "type": "kinegrant:FleetDeviceExportPacket",
            "schema_version": "0.1",
            "generated_at": isoformat(started + timedelta(minutes=2)),
            "overall_result": "PASS",
            "trusted_policy_issuers": [key.kid],
            "policy_bundle": bundle,
            "devices": [packet_1, packet_2],
            "summary": {
                "devices_total": 2,
                "policy_shared": True,
                "devices_verified": 2,
                "device_ids_unique": True,
                "cross_references_ok": True,
            },
        }
        packet = {
            "type": "kinegrant:UnifiedAuditExportPacket",
            "schema_version": "0.1",
            "generated_at": isoformat(started + timedelta(minutes=3)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid, revocation_key.kid],
            "policy_bundle": bundle,
            "revocation_bundle": revocation_bundle,
            "lifecycle_report": lifecycle_report,
            "fleet_export": fleet_export,
            "closure": closure,
            "summary": {
                "artifacts_total": 8,
                "phases_total": 4,
                "devices_total": 2,
                "policy_shared": True,
                "lifecycle_verified": True,
                "fleet_verified": True,
                "closure_verified": True,
                "cross_references_ok": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "unified-audit.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("unified-audit", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("UNIFIED AUDIT EXPORT VALID", verified.stdout)
            tampered = dict(packet)
            tampered["summary"] = dict(packet["summary"])
            tampered["summary"]["closure_verified"] = False
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("unified-audit", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_policy_migration_audit_packet(
        self,
    ) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        issuer = CapabilityIssuer(key)
        policy_id = "urn:kinegrant:policy:migration:1"
        old_rule = PolicyRule(
            "migration-rule-1",
            key.kid,
            "urn:space:browser:*",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
        deny_rule = PolicyRule(
            "migration-rule-2",
            key.kid,
            "urn:space:browser:door-2",
            "deny",
            ("close",),
            purposes=("maintenance",),
        )
        old_bundle = authority.publish(policy_id, [old_rule], ttl_seconds=3600)
        new_bundle = authority.publish(
            policy_id,
            [old_rule, deny_rule],
            ttl_seconds=3600,
        )
        request = ActionRequest(
            "urn:kinegrant:browser:request:migration",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "open",
            "delivery",
        )
        old_decision = PolicyEngine(
            [old_rule],
            trusted_policy_issuers={key.kid},
        ).evaluate(request)
        new_decision = PolicyEngine(
            [old_rule, deny_rule],
            trusted_policy_issuers={key.kid},
        ).evaluate(request)
        old_capability = issuer.issue(request, old_decision, ttl_seconds=300)
        old_id = old_capability["payload"]["capability_id"]
        new_capability = issuer.issue(request, new_decision, ttl_seconds=300)
        new_id = new_capability["payload"]["capability_id"]
        self.assertNotEqual(old_id, new_id)
        registry = PolicyRegistry(trusted_authorities={key.kid})
        distribution = PolicyDistributor(
            trusted_authorities={key.kid}
        ).distribute(new_bundle, {"gate-a": registry})
        started = utc_now()
        denied_at = isoformat(started - timedelta(minutes=5))
        allowed_at = isoformat(started - timedelta(minutes=4))
        gate = ActionGate(
            trusted_issuers={key.kid},
            replay_store=InMemoryReplayStore(),
        )
        verified = gate.authorize(new_capability, request, now=started)
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        receipt = log.append(
            verified,
            result="succeeded",
            evidence_hash="sha256:" + "a" * 64,
            started_at=started,
            finished_at=started + timedelta(seconds=1),
            request=request,
        )
        old_payload = old_capability["payload"]
        new_payload = new_capability["payload"]
        packet = {
            "type": "kinegrant:PolicyMigrationAuditPacket",
            "schema_version": "0.1",
            "generated_at": isoformat(started + timedelta(minutes=1)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid],
            "old_policy_bundle": old_bundle,
            "new_policy_bundle": new_bundle,
            "distribution_report": distribution,
            "old_capability_id": old_id,
            "request": request.to_dict(),
            "old_capability": old_capability,
            "new_capability": new_capability,
            "migration": {
                "gate_log": {
                    "old_denied": {
                        "allowed": False,
                        "reason": "policy_migrated",
                        "checked_at": denied_at,
                        "capability_id": old_id,
                        "policy_digest": old_payload["policy_digest"],
                    },
                    "new_allowed": {
                        "allowed": True,
                        "reason": "allow",
                        "checked_at": allowed_at,
                        "capability_id": new_id,
                        "policy_digest": new_payload["policy_digest"],
                    },
                }
            },
            "receipt": receipt,
            "summary": {
                "artifacts_total": 10,
                "old_policy_verified": True,
                "new_policy_verified": True,
                "version_chain": True,
                "distribution_verified": True,
                "migration_verified": True,
                "gate_order_ok": True,
                "receipt_bound": True,
                "closure_complete": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "migration-audit.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("migration-audit", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY MIGRATION AUDIT VALID", verified.stdout)
            tampered = dict(packet)
            tampered["summary"] = dict(packet["summary"])
            tampered["summary"]["version_chain"] = False
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("migration-audit", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_compliance_timeline(self) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        issuer = CapabilityIssuer(key)
        rule = PolicyRule(
            "timeline-rule-1",
            key.kid,
            "urn:space:browser:*",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
        bundle = authority.publish(
            "timeline-rule-1",
            [rule],
            ttl_seconds=3600,
        )
        request = ActionRequest(
            "urn:kinegrant:browser:request:timeline",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "open",
            "delivery",
        )
        decision = PolicyEngine(
            [rule],
            trusted_policy_issuers={key.kid},
        ).evaluate(request)
        capability_a = issuer.issue(request, decision, ttl_seconds=300)
        cap_id_a = capability_a["payload"]["capability_id"]
        capability_b = issuer.issue(request, decision, ttl_seconds=300)
        cap_id_b = capability_b["payload"]["capability_id"]
        self.assertNotEqual(cap_id_a, cap_id_b)
        policy_digest = capability_a["payload"]["policy_digest"]
        started = utc_now()
        issued_at = isoformat(started - timedelta(minutes=5))
        allowed_at = isoformat(started - timedelta(minutes=4))
        receipt_at = isoformat(started)
        revoked_at = isoformat(started - timedelta(minutes=2))
        denied_at = isoformat(started - timedelta(minutes=1))
        reissued_at = isoformat(started + timedelta(minutes=1))
        gate = ActionGate(
            trusted_issuers={key.kid},
            replay_store=InMemoryReplayStore(),
        )
        verified = gate.authorize(capability_a, request, now=started)
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        receipt = log.append(
            verified,
            result="succeeded",
            evidence_hash="sha256:" + "a" * 64,
            started_at=started,
            finished_at=started + timedelta(seconds=1),
            request=request,
        )
        revocations = RevocationList()
        revocations.revoke(cap_id_a, reason="operator decision")
        revoked_gate = ActionGate(
            trusted_issuers={key.kid},
            replay_store=InMemoryReplayStore(),
            revocation_list=revocations,
        )
        with self.assertRaises(PermissionError):
            revoked_gate.authorize(capability_a, request, now=started)
        events = [
            {
                "kind": "capability_issued",
                "at": issued_at,
                "capability_id": cap_id_a,
                "request_digest": capability_a["payload"]["request_digest"],
                "policy_digest": policy_digest,
                "actor": "urn:robot:browser:1",
            },
            {
                "kind": "gate_allowed",
                "at": allowed_at,
                "capability_id": cap_id_a,
                "policy_digest": policy_digest,
                "reason": "allow",
            },
            {
                "kind": "capability_revoked",
                "at": revoked_at,
                "capability_id": cap_id_a,
                "reason": "operator decision",
            },
            {
                "kind": "gate_denied",
                "at": denied_at,
                "capability_id": cap_id_a,
                "policy_digest": policy_digest,
                "reason": "revoked",
            },
            {
                "kind": "receipt_signed",
                "at": receipt_at,
                "capability_id": cap_id_a,
                "receipt_id": receipt["payload"]["receipt_id"],
                "evidence_hash": "sha256:" + "a" * 64,
            },
            {
                "kind": "capability_reissued",
                "at": reissued_at,
                "old_capability_id": cap_id_a,
                "new_capability_id": cap_id_b,
                "policy_digest": policy_digest,
            },
        ]
        packet = {
            "type": "kinegrant:ComplianceTimelinePacket",
            "schema_version": "0.1",
            "device_id": "device:esp32c3:paper-barrier:unit-1",
            "generated_at": isoformat(started + timedelta(minutes=2)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid],
            "policy_bundle": bundle,
            "events": events,
            "summary": {
                "events_total": 6,
                "kinds_unique": 6,
                "monotonic": True,
                "policy_bound": True,
                "device_bound": True,
                "references_ok": True,
                "timeline_complete": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "timeline.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("timeline", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("COMPLIANCE TIMELINE VALID", verified.stdout)
            tampered = dict(packet)
            tampered["events"] = [
                dict(event) for event in packet["events"]
            ]
            tampered["events"][1], tampered["events"][4] = (
                tampered["events"][4],
                tampered["events"][1],
            )
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("timeline", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_obligation_fulfillment(self) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        issuer = CapabilityIssuer(key)
        rule = PolicyRule(
            "obligation-rule-1",
            key.kid,
            "urn:space:browser:*",
            "allow",
            ("open",),
            purposes=("delivery",),
            obligations=("emitActionReceipt", "logAuditEvent"),
        )
        bundle = authority.publish(
            "obligation-rule-1",
            [rule],
            ttl_seconds=3600,
        )
        request = ActionRequest(
            "urn:kinegrant:browser:request:obligation",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "open",
            "delivery",
        )
        decision = PolicyEngine(
            [rule],
            trusted_policy_issuers={key.kid},
        ).evaluate(request)
        capability = issuer.issue(request, decision, ttl_seconds=300)
        gate = ActionGate(
            trusted_issuers={key.kid},
            replay_store=InMemoryReplayStore(),
        )
        started = utc_now()
        verified = gate.authorize(capability, request, now=started)
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        receipt = log.append(
            verified,
            result="succeeded",
            evidence_hash="sha256:" + "a" * 64,
            started_at=started,
            finished_at=started + timedelta(seconds=1),
            request=request,
            obligation_results=[
                {"obligation": "emitActionReceipt", "status": "satisfied"},
                {"obligation": "logAuditEvent", "status": "satisfied"},
            ],
        )
        packet = {
            "type": "kinegrant:ObligationFulfillmentPacket",
            "schema_version": "0.1",
            "device_id": "device:esp32c3:paper-barrier:unit-1",
            "generated_at": isoformat(started + timedelta(minutes=1)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid],
            "policy_bundle": bundle,
            "request": request.to_dict(),
            "capability": capability,
            "receipts": [receipt],
            "summary": {
                "artifacts_total": 6,
                "capabilities": 1,
                "receipts_total": 1,
                "obligations_required": 2,
                "obligations_covered": 2,
                "references_ok": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "obligation.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("obligation-fulfillment", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("OBLIGATION FULFILLMENT VALID", verified.stdout)
            tampered = dict(packet)
            tampered["receipts"] = [dict(receipt)]
            tampered["receipts"][0]["payload"] = dict(receipt["payload"])
            tampered["receipts"][0]["payload"]["obligation_results"] = [
                {"obligation": "emitActionReceipt", "status": "satisfied"}
            ]
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("obligation-fulfillment", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_selective_disclosure(self) -> None:
        from datetime import timedelta

        from kinegrant.merkle import merkle_redact

        document = {
            "action": "open",
            "agent": "urn:robot:browser:1",
            "purpose": "delivery",
            "target": "urn:space:browser:door-1",
        }
        redaction = merkle_redact(document, ["action", "purpose"])
        packet = {
            "type": "kinegrant:SelectiveDisclosurePacket",
            "schema_version": "0.1",
            "document_id": "receipt-1",
            "generated_at": isoformat(utc_now() + timedelta(minutes=1)),
            "overall_result": "PASS",
            "root": redaction["root"],
            "visible": redaction["visible"],
            "summary": {
                "artifacts_total": 3,
                "fields_total": 2,
                "proofs_verified": 2,
                "root_bound": True,
                "document_bound": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "disclosure.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("selective-disclosure", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("SELECTIVE DISCLOSURE VALID", verified.stdout)
            tampered = dict(packet)
            tampered["visible"] = [
                dict(entry) for entry in packet["visible"]
            ]
            tampered["visible"][0]["value"] = "close"
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("selective-disclosure", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_identifier_rotation(self) -> None:
        from datetime import timedelta

        from kinegrant.privacy import RotatingIdentifierRegistry

        started = utc_now()
        registry = RotatingIdentifierRegistry(lifetime_seconds=300)
        first = registry.issue(
            "robot-a",
            "robot-1",
            now=started - timedelta(minutes=5),
        )
        second = registry.rotate(
            "robot-a",
            "robot-1",
            now=started - timedelta(minutes=4),
        )
        packet = {
            "type": "kinegrant:IdentifierRotationPacket",
            "schema_version": "0.1",
            "namespace": "robot-a",
            "static_id": "robot-1",
            "generated_at": isoformat(started),
            "overall_result": "PASS",
            "rotations": [
                {
                    "ephemeral_id": first,
                    "issued_at": isoformat(started - timedelta(minutes=5)),
                    "status": "revoked",
                    "revoked_at": isoformat(started - timedelta(minutes=4)),
                },
                {
                    "ephemeral_id": second,
                    "issued_at": isoformat(started - timedelta(minutes=4)),
                    "status": "active",
                    "revoked_at": None,
                },
            ],
            "summary": {
                "artifacts_total": 3,
                "rotations_total": 2,
                "active_total": 1,
                "revoked_total": 1,
                "statuses_ok": True,
                "chain_complete": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "rotation.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("identifier-rotation", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("IDENTIFIER ROTATION VALID", verified.stdout)
            tampered = dict(packet)
            tampered["rotations"] = [
                dict(entry) for entry in packet["rotations"]
            ]
            tampered["rotations"][0]["status"] = "active"
            tampered["rotations"][0]["revoked_at"] = None
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("identifier-rotation", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_minimal_disclosure(self) -> None:
        from datetime import timedelta

        from kinegrant.merkle import merkle_redact

        document = {
            "action": "open",
            "agent": "urn:robot:browser:1",
            "purpose": "delivery",
            "target": "urn:space:browser:door-1",
        }
        redaction = merkle_redact(document, ["action", "purpose"])
        packet = {
            "type": "kinegrant:MinimalDisclosureAuditPacket",
            "schema_version": "0.1",
            "document_id": "receipt-1",
            "generated_at": isoformat(utc_now() + timedelta(minutes=1)),
            "overall_result": "PASS",
            "root": redaction["root"],
            "required_fields": ["action", "purpose"],
            "visible": redaction["visible"],
            "summary": {
                "artifacts_total": 4,
                "fields_total": 2,
                "proofs_verified": 2,
                "required_covered": True,
                "no_extra_fields": True,
                "root_bound": True,
                "document_bound": True,
                "minimal_disclosure": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "minimal-disclosure.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("minimal-disclosure", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("MINIMAL DISCLOSURE VALID", verified.stdout)
            tampered = dict(packet)
            tampered["visible"] = [
                dict(entry) for entry in packet["visible"]
            ]
            tampered["visible"][0]["field"] = "agent"
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("minimal-disclosure", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_least_privilege_audit(self) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        issuer = CapabilityIssuer(key)
        rule = PolicyRule(
            "least-privilege-rule-1",
            key.kid,
            "urn:space:browser:door-1",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
        bundle = authority.publish(
            "least-privilege-rule-1",
            [rule],
            ttl_seconds=3600,
        )
        request = ActionRequest(
            "urn:kinegrant:browser:request:least-privilege",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "open",
            "delivery",
        )
        decision = PolicyEngine(
            [rule],
            trusted_policy_issuers={key.kid},
        ).evaluate(request)
        capability = issuer.issue_scoped(
            request,
            decision,
            ttl_seconds=300,
            actions=("open",),
            purposes=("delivery",),
            target=request.target,
            wire_version="1.0",
        )
        gate = ActionGate(
            trusted_issuers={key.kid},
            replay_store=InMemoryReplayStore(),
        )
        started = utc_now()
        verified = gate.authorize(capability, request, now=started)
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        receipt = log.append(
            verified,
            result="succeeded",
            evidence_hash="sha256:" + "a" * 64,
            started_at=started,
            finished_at=started + timedelta(seconds=1),
            request=request,
        )
        packet = {
            "type": "kinegrant:LeastPrivilegeAuditPacket",
            "schema_version": "0.1",
            "device_id": "device:esp32c3:paper-barrier:unit-1",
            "generated_at": isoformat(started + timedelta(minutes=1)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid],
            "policy_bundle": bundle,
            "request": request.to_dict(),
            "capability": capability,
            "receipt": receipt,
            "summary": {
                "artifacts_total": 5,
                "capability_verified": True,
                "policy_bound": True,
                "request_bound": True,
                "actions_minimal": True,
                "purposes_minimal": True,
                "targets_minimal": True,
                "scope_minimal": True,
                "receipt_bound": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "least-privilege.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("least-privilege", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("LEAST PRIVILEGE AUDIT VALID", verified.stdout)
            wide = issuer.issue_scoped(
                request,
                decision,
                ttl_seconds=300,
                actions=("open", "close"),
                purposes=("delivery",),
                target=request.target,
                wire_version="1.0",
            )
            tampered = dict(packet)
            tampered["capability"] = wide
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("least-privilege", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_denial_explainability(self) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        deny_rule = PolicyRule(
            "deny-rule-1",
            key.kid,
            "urn:space:browser:door-1",
            "deny",
            ("kg.action.open",),
            purposes=("delivery",),
        )
        bundle = authority.publish(
            "deny-rule-1",
            [deny_rule],
            ttl_seconds=3600,
        )
        engine = PolicyEngine(
            [deny_rule],
            trusted_policy_issuers={key.kid},
            require_known_actions=True,
        )
        started = utc_now()
        denied_request = ActionRequest(
            "urn:kinegrant:browser:request:deny-1",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "kg.action.open",
            "delivery",
        )
        denied_decision = engine.evaluate(denied_request, now=started)
        self.assertFalse(denied_decision.allowed)
        unknown_request = ActionRequest(
            "urn:kinegrant:browser:request:deny-2",
            "urn:robot:browser:1",
            "urn:space:browser:door-1",
            "kg.action.teleport",
            "delivery",
        )
        unknown_decision = engine.evaluate(unknown_request, now=started)
        self.assertFalse(unknown_decision.allowed)
        policy_digest = denied_decision.policy_digest
        packet = {
            "type": "kinegrant:DenialExplainabilityPacket",
            "schema_version": "0.1",
            "device_id": "device:esp32c3:paper-barrier:unit-1",
            "generated_at": isoformat(started + timedelta(minutes=1)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid],
            "policy_bundle": bundle,
            "denials": [
                {
                    "denial_id": "denial-1",
                    "denied_at": isoformat(started - timedelta(minutes=5)),
                    "request_digest": denied_request.digest,
                    "policy_digest": policy_digest,
                    "rule_id": denied_decision.matched_policy_ids[0],
                    "reason": denied_decision.reason,
                    "explanation": "the request matched an explicit deny rule",
                },
                {
                    "denial_id": "denial-2",
                    "denied_at": isoformat(started - timedelta(minutes=4)),
                    "request_digest": unknown_request.digest,
                    "policy_digest": policy_digest,
                    "rule_id": None,
                    "reason": unknown_decision.reason,
                    "explanation": "the requested action is not in the known action vocabulary",
                },
            ],
            "summary": {
                "artifacts_total": 3,
                "denials_total": 2,
                "reasons_explained": 2,
                "explanations_complete": 2,
                "rules_referenced": 1,
                "policy_bound": True,
                "request_bound": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "denial-explainability.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("denial-explainability", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("DENIAL EXPLAINABILITY VALID", verified.stdout)
            tampered = dict(packet)
            tampered["denials"] = [
                dict(entry) for entry in packet["denials"]
            ]
            tampered["denials"][0]["explanation"] = ""
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("denial-explainability", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_policy_diff_audit(self) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        rule_a_v1 = PolicyRule(
            "diff-rule-a",
            key.kid,
            "urn:space:browser:door-1",
            "allow",
            ("kg.action.open",),
            purposes=("delivery",),
            obligations=("emitActionReceipt",),
        )
        rule_a_v2 = PolicyRule(
            "diff-rule-a",
            key.kid,
            "urn:space:browser:door-1",
            "allow",
            ("kg.action.open",),
            purposes=("delivery",),
            obligations=("emitActionReceipt", "logAuditEvent"),
        )
        rule_b = PolicyRule(
            "diff-rule-b",
            key.kid,
            "urn:space:browser:door-2",
            "deny",
            ("kg.action.close",),
            purposes=("maintenance",),
        )
        old_bundle = authority.publish(
            "urn:kinegrant:policy:diff:1",
            [rule_a_v1],
            ttl_seconds=3600,
        )
        new_bundle = authority.publish(
            "urn:kinegrant:policy:diff:1",
            [rule_a_v2, rule_b],
            ttl_seconds=3600,
        )

        def rule_map(bundle: dict) -> dict[str, dict]:
            return {
                rule["policy_id"]: rule
                for rule in bundle["payload"]["rules"]
            }

        old_rules = rule_map(old_bundle)
        new_rules = rule_map(new_bundle)
        added = sorted(set(new_rules) - set(old_rules))
        removed = sorted(set(old_rules) - set(new_rules))
        unchanged = sorted(
            rule_id
            for rule_id in set(old_rules) & set(new_rules)
            if digest(old_rules[rule_id]) == digest(new_rules[rule_id])
        )
        changed = sorted(
            rule_id
            for rule_id in set(old_rules) & set(new_rules)
            if digest(old_rules[rule_id]) != digest(new_rules[rule_id])
        )
        packet = {
            "type": "kinegrant:PolicyDiffAuditPacket",
            "schema_version": "0.1",
            "generated_at": isoformat(utc_now() + timedelta(minutes=1)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid],
            "old_policy_bundle": old_bundle,
            "new_policy_bundle": new_bundle,
            "diff": {
                "added_rule_ids": added,
                "removed_rule_ids": removed,
                "unchanged_rule_ids": unchanged,
                "changed_rule_ids": changed,
            },
            "summary": {
                "artifacts_total": 4,
                "rules_total": len(new_rules),
                "rules_added": len(added),
                "rules_removed": len(removed),
                "rules_unchanged": len(unchanged),
                "rules_changed": len(changed),
                "version_chain": True,
                "diff_complete": True,
                "policy_bound": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "policy-diff.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("policy-diff", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY DIFF AUDIT VALID", verified.stdout)
            tampered = dict(packet)
            tampered["summary"] = dict(packet["summary"])
            tampered["summary"]["rules_added"] += 1
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("policy-diff", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)

    def test_browser_verifier_verifies_python_policy_impact_audit(self) -> None:
        from datetime import timedelta

        key = Ed25519KeyPair.generate()
        authority = PolicyAuthority(key)
        rule_a_v1 = PolicyRule(
            "impact-rule-a",
            key.kid,
            "urn:space:browser:door-1",
            "allow",
            ("kg.action.open",),
            purposes=("delivery",),
            obligations=("emitActionReceipt",),
        )
        rule_a_v2 = PolicyRule(
            "impact-rule-a",
            key.kid,
            "urn:space:browser:door-1",
            "allow",
            ("kg.action.open",),
            purposes=("delivery",),
            obligations=("emitActionReceipt", "logAuditEvent"),
        )
        rule_b = PolicyRule(
            "impact-rule-b",
            key.kid,
            "urn:space:browser:door-2",
            "deny",
            ("kg.action.close",),
            purposes=("maintenance",),
        )
        old_bundle = authority.publish(
            "urn:kinegrant:policy:impact:1",
            [rule_a_v1],
            ttl_seconds=3600,
        )
        new_bundle = authority.publish(
            "urn:kinegrant:policy:impact:1",
            [rule_a_v2, rule_b],
            ttl_seconds=3600,
        )

        def rule_map(bundle: dict) -> dict[str, dict]:
            return {
                rule["policy_id"]: rule
                for rule in bundle["payload"]["rules"]
            }

        old_rules = rule_map(old_bundle)
        new_rules = rule_map(new_bundle)
        added = sorted(set(new_rules) - set(old_rules))
        removed = sorted(set(old_rules) - set(new_rules))
        unchanged = sorted(
            rule_id
            for rule_id in set(old_rules) & set(new_rules)
            if digest(old_rules[rule_id]) == digest(new_rules[rule_id])
        )
        changed = sorted(
            rule_id
            for rule_id in set(old_rules) & set(new_rules)
            if digest(old_rules[rule_id]) != digest(new_rules[rule_id])
        )
        affected_rule_ids = sorted(set(added) | set(changed))
        affected_rules = [new_rules[rule_id] for rule_id in affected_rule_ids]
        affected_targets = sorted(
            {rule["target"] for rule in affected_rules}
        )
        affected_actions = sorted(
            {
                action
                for rule in affected_rules
                for action in rule.get("actions", [])
            }
        )
        affected_purposes = sorted(
            {
                purpose
                for rule in affected_rules
                for purpose in rule.get("purposes", [])
            }
        )
        packet = {
            "type": "kinegrant:PolicyImpactAuditPacket",
            "schema_version": "0.1",
            "generated_at": isoformat(utc_now() + timedelta(minutes=1)),
            "overall_result": "PASS",
            "trusted_authorities": [key.kid],
            "old_policy_bundle": old_bundle,
            "new_policy_bundle": new_bundle,
            "diff": {
                "added_rule_ids": added,
                "removed_rule_ids": removed,
                "unchanged_rule_ids": unchanged,
                "changed_rule_ids": changed,
            },
            "impact": {
                "affected_rule_ids": affected_rule_ids,
                "affected_targets": affected_targets,
                "affected_actions": affected_actions,
                "affected_purposes": affected_purposes,
            },
            "summary": {
                "artifacts_total": 5,
                "affected_rule_ids_total": len(affected_rule_ids),
                "affected_targets_total": len(affected_targets),
                "affected_actions_total": len(affected_actions),
                "affected_purposes_total": len(affected_purposes),
                "version_chain": True,
                "diff_matches": True,
                "impact_complete": True,
                "policy_bound": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            packet_path = base / "policy-impact.json"
            packet_path.write_text(json.dumps(packet), encoding="utf-8")
            verified = self._run("policy-impact", str(packet_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("POLICY IMPACT AUDIT VALID", verified.stdout)
            tampered = dict(packet)
            tampered["summary"] = dict(packet["summary"])
            tampered["summary"]["affected_actions_total"] += 1
            tampered_path = base / "tampered.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            rejected = self._run("policy-impact", str(tampered_path))
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("INVALID", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
