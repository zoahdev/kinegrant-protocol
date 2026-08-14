from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from kinegrant.adapters.odrl import odrl_to_rules
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.models import PolicyRule, utc_now
from kinegrant.policy import PolicyEngine
from kinegrant.policy_bundle import (
    PolicyAuthority,
    PolicyDistributor,
    PolicyRegistry,
    analyze_policy_bundle,
    build_policy_bundle,
    bundle_to_odrl,
    main,
    policy_bundle_coverage,
    rules_from_bundle,
    sign_policy_bundle,
    verify_policy_distribution_report,
    verify_policy_bundle,
)


def make_rules(authority_kid: str, policy_id: str = "urn:kinegrant:policy:test:door") -> list[PolicyRule]:
    return [
        PolicyRule(
            policy_id,
            authority_kid,
            "urn:space:test:door-1",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
    ]


class PolicyBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = PolicyAuthority(Ed25519KeyPair.generate())
        self.policy_id = "urn:kinegrant:policy:test:door"
        self.bundle = self.authority.publish(
            self.policy_id,
            make_rules(self.authority.kid),
            ttl_seconds=3600,
        )

    def test_verify_roundtrip(self) -> None:
        payload = verify_policy_bundle(
            self.bundle,
            trusted_authorities={self.authority.kid},
            expected_policy_id=self.policy_id,
        )
        self.assertEqual(payload["policy_id"], self.policy_id)
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["issuer"], self.authority.kid)

    def test_rules_from_bundle_feed_policy_engine(self) -> None:
        rules = rules_from_bundle(
            self.bundle,
            trusted_authorities={self.authority.kid},
        )
        engine = PolicyEngine(
            rules,
            trusted_policy_issuers={self.authority.kid},
        )
        from kinegrant.models import ActionRequest

        request = ActionRequest(
            "req-1",
            "urn:robot:test-1",
            "urn:space:test:door-1",
            "open",
            "delivery",
        )
        decision = engine.evaluate(request)
        self.assertTrue(decision.allowed)

    def test_tampered_rules_rejected(self) -> None:
        tampered = dict(self.bundle)
        tampered["payload"] = dict(self.bundle["payload"])
        tampered["payload"]["rules"] = []
        with self.assertRaises(ValueError):
            verify_policy_bundle(
                tampered,
                trusted_authorities={self.authority.kid},
            )

    def test_digest_mismatch_rejected(self) -> None:
        tampered = dict(self.bundle)
        tampered["payload"] = dict(self.bundle["payload"])
        tampered["payload"]["policy_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            verify_policy_bundle(
                tampered,
                trusted_authorities={self.authority.kid},
            )

    def test_untrusted_authority_rejected(self) -> None:
        outsider = PolicyAuthority(Ed25519KeyPair.generate())
        with self.assertRaises(ValueError):
            verify_policy_bundle(
                self.bundle,
                trusted_authorities={outsider.kid},
            )

    def test_expected_policy_id_rejected(self) -> None:
        with self.assertRaises(ValueError):
            verify_policy_bundle(
                self.bundle,
                trusted_authorities={self.authority.kid},
                expected_policy_id="urn:kinegrant:policy:test:other",
            )

    def test_expired_bundle_rejected(self) -> None:
        with self.assertRaises(ValueError):
            verify_policy_bundle(
                self.bundle,
                trusted_authorities={self.authority.kid},
                now=utc_now() + timedelta(hours=2),
            )

    def test_future_bundle_rejected(self) -> None:
        future = self.authority.publish(
            self.policy_id,
            make_rules(self.authority.kid),
            not_before=utc_now() + timedelta(hours=1),
            ttl_seconds=3600,
        )
        with self.assertRaises(ValueError):
            verify_policy_bundle(
                future,
                trusted_authorities={self.authority.kid},
            )

    def test_registry_selects_latest_and_rolls_back_on_revoke(self) -> None:
        registry = PolicyRegistry(trusted_authorities={self.authority.kid})
        registry.activate(self.bundle)
        rules_v2 = make_rules(self.authority.kid)
        rules_v2[0] = PolicyRule(
            self.policy_id,
            self.authority.kid,
            "urn:space:test:door-1",
            "allow",
            ("open",),
            purposes=("delivery", "maintenance"),
        )
        v2 = self.authority.publish(self.policy_id, rules_v2, ttl_seconds=3600)
        registry.activate(v2)
        self.assertEqual(registry.current(self.policy_id)["version"], 2)
        self.assertEqual(registry.versions(self.policy_id), (1, 2))
        registry.revoke(self.policy_id, 2, reason="emergency rollback")
        self.assertTrue(registry.is_revoked(self.policy_id, 2))
        self.assertEqual(registry.current(self.policy_id)["version"], 1)
        registry.revoke(self.policy_id, 1)
        self.assertIsNone(registry.current(self.policy_id))

    def test_registry_rejects_duplicate_version_with_different_rules(self) -> None:
        registry = PolicyRegistry(trusted_authorities={self.authority.kid})
        registry.activate(self.bundle)
        conflicting_rules = [
            PolicyRule(
                self.policy_id,
                self.authority.kid,
                "urn:space:test:door-1",
                "allow",
                ("open",),
                purposes=("delivery", "maintenance"),
            )
        ]
        forged = build_policy_bundle(
            self.policy_id,
            conflicting_rules,
            issuer=self.authority.kid,
            version=1,
            not_after=utc_now() + timedelta(hours=1),
        )
        signed = sign_policy_bundle(forged, self.authority.key_pair)
        with self.assertRaises(ValueError):
            registry.activate(signed)

    def test_previous_version_digest_chain(self) -> None:
        v1 = self.authority.publish(
            self.policy_id,
            make_rules(self.authority.kid),
            ttl_seconds=3600,
        )
        v2 = self.authority.publish(
            self.policy_id,
            make_rules(self.authority.kid),
            ttl_seconds=3600,
        )
        self.assertEqual(
            v2["payload"]["previous_version_digest"],
            v1["payload"]["policy_digest"],
        )

    def test_registry_state_roundtrip(self) -> None:
        registry = PolicyRegistry(trusted_authorities={self.authority.kid})
        registry.activate(self.bundle)
        registry.revoke(self.policy_id, 9, reason="pre-emptive")
        restored = PolicyRegistry.from_dict(
            registry.to_dict(),
            trusted_authorities={self.authority.kid},
        )
        self.assertEqual(restored.trusted_authorities, {self.authority.kid})
        self.assertEqual(restored.current(self.policy_id)["version"], 1)
        self.assertTrue(restored.is_revoked(self.policy_id, 9))

    def test_self_test_passes(self) -> None:
        self.assertEqual(main(["--self-test"]), 0)

    def test_cli_verify_with_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle_path = root / "bundle.json"
            authorities_path = root / "authorities.json"
            bundle_path.write_text(
                json.dumps(self.bundle),
                encoding="utf-8",
            )
            authorities_path.write_text(
                json.dumps([self.authority.kid]),
                encoding="utf-8",
            )
            exit_code = main(
                [
                    "--verify",
                    str(bundle_path),
                    "--authorities",
                    str(authorities_path),
                    "--policy-id",
                    self.policy_id,
                ]
            )
            self.assertEqual(exit_code, 0)

    def test_distributor_upgrades_fleet_and_reports_acks(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:fleet"
        v1 = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        v2 = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        gate_a = PolicyRegistry(trusted_authorities={authority.kid})
        gate_b = PolicyRegistry(trusted_authorities={authority.kid})
        report = PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(
            v1,
            {"gate-a": gate_a, "gate-b": gate_b},
        )
        self.assertEqual(report["overall_result"], "PASS")
        self.assertEqual(report["summary"]["applied_total"], 2)
        self.assertEqual(gate_a.current(policy_id)["version"], 1)
        upgrade = PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(
            v2,
            {"gate-a": gate_a, "gate-b": gate_b},
        )
        self.assertEqual(upgrade["summary"]["applied_total"], 2)
        self.assertEqual(gate_a.current(policy_id)["version"], 2)

    def test_distributor_does_not_downgrade(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:fleet"
        v1 = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        v2 = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        gate = PolicyRegistry(trusted_authorities={authority.kid})
        PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(v1, {"gate": gate})
        report = PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(v1, {"gate": gate})
        self.assertEqual(report["summary"]["already_present_total"], 1)
        self.assertEqual(gate.current(policy_id)["version"], 1)
        PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(v2, {"gate": gate})
        older = PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(v1, {"gate": gate})
        self.assertEqual(older["summary"]["already_present_total"], 1)
        self.assertEqual(gate.current(policy_id)["version"], 2)

    def test_distributor_rejects_tampered_bundle_without_touching_gates(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:fleet"
        bundle = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        tampered = dict(bundle)
        tampered["payload"] = dict(bundle["payload"])
        tampered["payload"]["rules"] = []
        gate = PolicyRegistry(trusted_authorities={authority.kid})
        with self.assertRaises(ValueError):
            PolicyDistributor(
                trusted_authorities={authority.kid}
            ).distribute(tampered, {"gate": gate})
        self.assertIsNone(gate.current(policy_id))

    def test_distribution_report_verification(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:fleet"
        v1 = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        gate = PolicyRegistry(trusted_authorities={authority.kid})
        report = PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(v1, {"gate-a": gate})
        verified = verify_policy_distribution_report(
            report,
            v1,
            trusted_authorities={authority.kid},
        )
        self.assertEqual(verified["overall_result"], "PASS")

    def test_distribution_report_tampered_ack_rejected(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:fleet"
        v1 = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        gate = PolicyRegistry(trusted_authorities={authority.kid})
        report = PolicyDistributor(
            trusted_authorities={authority.kid}
        ).distribute(v1, {"gate-a": gate})
        report["acks"][0]["applied"] = not report["acks"][0]["applied"]
        with self.assertRaises(ValueError):
            verify_policy_distribution_report(
                report,
                v1,
                trusted_authorities={authority.kid},
            )

    def test_cli_distribute_roundtrip(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:fleet"
        bundle = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle_path = root / "bundle.json"
            authorities_path = root / "authorities.json"
            registries_path = root / "registries.json"
            out_path = root / "registries-out.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([authority.kid]),
                encoding="utf-8",
            )
            registries_path.write_text(
                json.dumps({"gate-a": PolicyRegistry().to_dict()}),
                encoding="utf-8",
            )
            exit_code = main(
                [
                    "--distribute",
                    str(bundle_path),
                    "--authorities",
                    str(authorities_path),
                    "--registries",
                    str(registries_path),
                    "--out",
                    str(out_path),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertTrue(out_path.exists())
            restored = PolicyRegistry.from_dict(
                json.loads(out_path.read_text(encoding="utf-8"))["gate-a"],
                trusted_authorities={authority.kid},
            )
            self.assertEqual(restored.current(policy_id)["version"], 1)

    def test_bundle_to_odrl_roundtrip(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:odrl"
        rules = [
            PolicyRule(
                policy_id,
                authority.kid,
                "urn:space:test:door-1",
                "allow",
                ("open",),
                purposes=("delivery",),
                obligations=("emitActionReceipt",),
            )
        ]
        bundle = authority.publish(policy_id, rules, ttl_seconds=3600)
        odrl_document = bundle_to_odrl(
            bundle,
            trusted_authorities={authority.kid},
            expected_policy_id=policy_id,
        )
        self.assertEqual(odrl_document["uid"], policy_id)
        round_trip = odrl_to_rules(odrl_document)
        engine = PolicyEngine(
            round_trip,
            trusted_policy_issuers={authority.kid},
        )
        from kinegrant.models import ActionRequest

        request = ActionRequest(
            "req-odrl-1",
            "urn:robot:test-1",
            "urn:space:test:door-1",
            "open",
            "delivery",
        )
        decision = engine.evaluate(request)
        self.assertTrue(decision.allowed)
        self.assertTrue(
            any(
                matched.startswith(policy_id)
                for matched in decision.matched_policy_ids
            )
        )

    def test_bundle_to_odrl_rejects_tampered(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        bundle = authority.publish(
            "urn:kinegrant:policy:odrl",
            make_rules(authority.kid, "urn:kinegrant:policy:odrl"),
            ttl_seconds=3600,
        )
        tampered = dict(bundle)
        tampered["payload"] = dict(bundle["payload"])
        tampered["payload"]["rules"] = []
        with self.assertRaises(ValueError):
            bundle_to_odrl(
                tampered,
                trusted_authorities={authority.kid},
            )

    def test_analyze_clean_bundle_passes(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:analyze"
        bundle = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        report = analyze_policy_bundle(
            bundle,
            trusted_authorities={authority.kid},
        )
        self.assertEqual(report["overall_result"], "PASS")
        self.assertEqual(report["summary"]["errors"], 0)

    def test_analyze_detects_allow_deny_conflict(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:analyze-conflict"
        rules = [
            PolicyRule(
                policy_id,
                authority.kid,
                "urn:space:test:door-1",
                "allow",
                ("open",),
                purposes=("delivery",),
            ),
            PolicyRule(
                policy_id + "-deny",
                authority.kid,
                "urn:space:test:door-1",
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
        self.assertTrue(
            any(
                finding["code"] == "conflicting_effect"
                for finding in report["findings"]
            )
        )

    def test_analyze_detects_duplicate_rule_warning(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:analyze-duplicate"
        rule = PolicyRule(
            policy_id,
            authority.kid,
            "urn:space:test:door-1",
            "allow",
            ("open",),
            purposes=("delivery",),
        )
        bundle = authority.publish(policy_id, [rule, rule], ttl_seconds=3600)
        report = analyze_policy_bundle(
            bundle,
            trusted_authorities={authority.kid},
        )
        self.assertTrue(
            any(
                finding["code"] == "duplicate_rule"
                for finding in report["findings"]
            )
        )

    def test_analyze_detects_broad_allow_warning(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:analyze-broad"
        rule = PolicyRule(
            policy_id,
            authority.kid,
            "*",
            "allow",
            ("*",),
            purposes=("*",),
        )
        bundle = authority.publish(policy_id, [rule], ttl_seconds=3600)
        report = analyze_policy_bundle(
            bundle,
            trusted_authorities={authority.kid},
        )
        self.assertTrue(
            any(
                finding["code"] == "broad_allow"
                for finding in report["findings"]
            )
        )

    def test_analyze_rejects_tampered(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        bundle = authority.publish(
            "urn:kinegrant:policy:analyze",
            make_rules(authority.kid, "urn:kinegrant:policy:analyze"),
            ttl_seconds=3600,
        )
        tampered = dict(bundle)
        tampered["payload"] = dict(bundle["payload"])
        tampered["payload"]["rules"] = []
        with self.assertRaises(ValueError):
            analyze_policy_bundle(
                tampered,
                trusted_authorities={authority.kid},
            )

    def test_cli_analyze_exit_codes(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:analyze-cli"
        clean = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        conflicting = authority.publish(
            policy_id,
            [
                PolicyRule(
                    policy_id,
                    authority.kid,
                    "urn:space:test:door-1",
                    "allow",
                    ("open",),
                ),
                PolicyRule(
                    policy_id + "-deny",
                    authority.kid,
                    "urn:space:test:door-1",
                    "deny",
                    ("open",),
                ),
            ],
            ttl_seconds=3600,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clean_path = root / "clean.json"
            conflict_path = root / "conflict.json"
            authorities_path = root / "authorities.json"
            clean_path.write_text(json.dumps(clean), encoding="utf-8")
            conflict_path.write_text(json.dumps(conflicting), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([authority.kid]),
                encoding="utf-8",
            )
            self.assertEqual(
                main(
                    [
                        "--analyze",
                        str(clean_path),
                        "--authorities",
                        str(authorities_path),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "--analyze",
                        str(conflict_path),
                        "--authorities",
                        str(authorities_path),
                    ]
                ),
                1,
            )

    def test_coverage_clean_bundle_passes(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:coverage"
        bundle = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        report = policy_bundle_coverage(
            bundle,
            trusted_authorities={authority.kid},
            targets=("urn:space:test:door-1",),
        )
        self.assertEqual(report["overall_result"], "PASS")
        self.assertEqual(report["summary"]["allowed"], 1)
        self.assertEqual(report["summary"]["denied"], 0)

    def test_coverage_reports_deny_default(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:coverage-deny-default"
        bundle = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        report = policy_bundle_coverage(
            bundle,
            trusted_authorities={authority.kid},
            actions=("open", "record"),
            targets=("urn:space:test:door-1",),
        )
        self.assertEqual(report["summary"]["allowed"], 1)
        self.assertEqual(report["summary"]["denied"], 1)

    def test_coverage_detects_shadowed_allow(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:coverage-shadow"
        bundle = authority.publish(
            policy_id,
            [
                PolicyRule(
                    policy_id + "-allow",
                    authority.kid,
                    "urn:space:test:door-1",
                    "allow",
                    ("open",),
                    purposes=("delivery",),
                ),
                PolicyRule(
                    policy_id + "-deny",
                    authority.kid,
                    "urn:space:test:door-1",
                    "deny",
                    ("open",),
                ),
            ],
            ttl_seconds=3600,
        )
        report = policy_bundle_coverage(
            bundle,
            trusted_authorities={authority.kid},
            targets=("urn:space:test:door-1",),
        )
        self.assertEqual(report["overall_result"], "FAIL")
        self.assertIn(policy_id + "-allow", report["shadowed_allows"])

    def test_coverage_rejects_tampered(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        bundle = authority.publish(
            "urn:kinegrant:policy:coverage",
            make_rules(authority.kid, "urn:kinegrant:policy:coverage"),
            ttl_seconds=3600,
        )
        tampered = dict(bundle)
        tampered["payload"] = dict(bundle["payload"])
        tampered["payload"]["rules"] = []
        with self.assertRaises(ValueError):
            policy_bundle_coverage(
                tampered,
                trusted_authorities={authority.kid},
            )

    def test_cli_coverage_exit_codes(self) -> None:
        authority = PolicyAuthority(Ed25519KeyPair.generate())
        policy_id = "urn:kinegrant:policy:coverage-cli"
        clean = authority.publish(
            policy_id,
            make_rules(authority.kid, policy_id),
            ttl_seconds=3600,
        )
        shadowed = authority.publish(
            policy_id,
            [
                PolicyRule(
                    policy_id + "-allow",
                    authority.kid,
                    "urn:space:test:door-1",
                    "allow",
                    ("open",),
                ),
                PolicyRule(
                    policy_id + "-deny",
                    authority.kid,
                    "urn:space:test:door-1",
                    "deny",
                    ("open",),
                ),
            ],
            ttl_seconds=3600,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clean_path = root / "clean.json"
            shadow_path = root / "shadow.json"
            authorities_path = root / "authorities.json"
            clean_path.write_text(json.dumps(clean), encoding="utf-8")
            shadow_path.write_text(json.dumps(shadowed), encoding="utf-8")
            authorities_path.write_text(
                json.dumps([authority.kid]),
                encoding="utf-8",
            )
            self.assertEqual(
                main(
                    [
                        "--coverage",
                        str(clean_path),
                        "--authorities",
                        str(authorities_path),
                        "--targets",
                        "urn:space:test:door-1",
                        "--max-requests",
                        "10",
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "--coverage",
                        str(shadow_path),
                        "--authorities",
                        str(authorities_path),
                        "--targets",
                        "urn:space:test:door-1",
                    ]
                ),
                1,
            )


if __name__ == "__main__":
    unittest.main()
