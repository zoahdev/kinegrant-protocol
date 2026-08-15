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


if __name__ == "__main__":
    unittest.main()
