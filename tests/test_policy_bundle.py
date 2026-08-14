from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from kinegrant.crypto import Ed25519KeyPair
from kinegrant.models import PolicyRule, utc_now
from kinegrant.policy import PolicyEngine
from kinegrant.policy_bundle import (
    PolicyAuthority,
    PolicyRegistry,
    build_policy_bundle,
    main,
    rules_from_bundle,
    sign_policy_bundle,
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


if __name__ == "__main__":
    unittest.main()
