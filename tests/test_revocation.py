from __future__ import annotations

import unittest

from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.revocation import RevocationEntry, RevocationList
from kinegrant.revocation import (
    build_revocation_bundle,
    bundle_digest,
    sign_revocation_bundle,
    verify_revocation_bundle,
)


class RevocationListTests(unittest.TestCase):
    def test_revoke_and_check(self) -> None:
        rl = RevocationList()
        rl.revoke("kinegrant:cap:" + "a" * 64, reason="policy change")
        self.assertTrue(rl.is_revoked("kinegrant:cap:" + "a" * 64))
        self.assertFalse(rl.is_revoked("kinegrant:cap:" + "b" * 64))
        self.assertFalse(rl.is_revoked(None))
        self.assertEqual(rl.entries[0].reason, "policy change")

    def test_serialization_round_trip_and_digest(self) -> None:
        rl = RevocationList()
        rl.revoke("kinegrant:cap:" + "a" * 64, reason="compromise")
        restored = RevocationList.from_dict(rl.to_dict())
        self.assertTrue(restored.is_revoked("kinegrant:cap:" + "a" * 64))
        self.assertEqual(restored.digest(), rl.digest())
        self.assertTrue(rl.digest().startswith("sha256:"))

    def test_invalid_entries_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RevocationEntry("")
        with self.assertRaises(ValueError):
            RevocationList.from_dict({"type": "wrong", "schema_version": "0.1", "entries": []})
        with self.assertRaises(ValueError):
            RevocationList.from_dict(
                {"type": "kinegrant:RevocationList", "schema_version": "9.9", "entries": []}
            )


class GateRevocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = CapabilityIssuer(Ed25519KeyPair.generate())
        self.request = ActionRequest(
            request_id="req-revoke-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        rule = PolicyRule(
            policy_id="revoke-rule-1",
            issuer=self.issuer.key_pair.kid,
            target="door-*",
            effect="allow",
            actions=("open",),
            purposes=("delivery",),
        )
        decision = PolicyEngine(
            [rule], trusted_policy_issuers={self.issuer.key_pair.kid}
        ).evaluate(self.request)
        self.root = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
            target="door-*",
            actions=["open"],
            purposes=["delivery"],
            delegation_allowed=True,
            max_delegation_depth=1,
        )
        self.delegate = ActionRequest(
            request_id="req-revoke-delegate",
            agent="robot-2",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        self.child = self.issuer.issue_attenuated(
            self.root,
            target="door-7",
            delegate_agent="robot-2",
            delegate_request=self.delegate,
        )

    def gate(self, rl: RevocationList | None = None) -> ActionGate:
        return ActionGate(
            trusted_issuers={self.issuer.key_pair.kid},
            replay_store=InMemoryReplayStore(),
            revocation_list=rl,
        )

    def test_unrevoked_capability_passes(self) -> None:
        verified = self.gate().authorize(self.child, self.delegate)
        self.assertEqual(verified["root_capability_id"], self.root["payload"]["capability_id"])

    def test_revoked_child_id_is_rejected(self) -> None:
        rl = RevocationList()
        rl.revoke(self.child["payload"]["capability_id"])
        with self.assertRaises(PermissionError):
            self.gate(rl).authorize(self.child, self.delegate)

    def test_revoking_root_revokes_the_whole_chain(self) -> None:
        rl = RevocationList()
        rl.revoke(self.root["payload"]["capability_id"])
        with self.assertRaises(PermissionError):
            self.gate(rl).authorize(self.child, self.delegate)
        with self.assertRaises(PermissionError):
            self.gate(rl).authorize(self.root, self.request)

    def test_v01_capability_revocation(self) -> None:
        rule = PolicyRule(
            policy_id="revoke-rule-2",
            issuer=self.issuer.key_pair.kid,
            target="door-7",
            effect="allow",
            actions=("open",),
        )
        decision = PolicyEngine(
            [rule], trusted_policy_issuers={self.issuer.key_pair.kid}
        ).evaluate(self.request)
        v1 = self.issuer.issue(self.request, decision, ttl_seconds=30)
        rl = RevocationList()
        rl.revoke(v1["payload"]["capability_id"])
        with self.assertRaises(PermissionError):
            self.gate(rl).authorize(v1, self.request)


class RevocationBundleTests(unittest.TestCase):
    def test_sign_and_verify_round_trip(self) -> None:
        authority = Ed25519KeyPair.generate()
        rl = RevocationList()
        rl.revoke("kinegrant:cap:" + "a" * 64, reason="compromise")
        bundle = build_revocation_bundle(rl, issuer=authority.kid, version=1)
        envelope = sign_revocation_bundle(bundle, authority)
        restored = verify_revocation_bundle(
            envelope,
            trusted_authorities={authority.kid},
        )
        self.assertTrue(restored.is_revoked("kinegrant:cap:" + "a" * 64))

    def test_untrusted_authority_is_rejected(self) -> None:
        authority = Ed25519KeyPair.generate()
        other = Ed25519KeyPair.generate()
        bundle = build_revocation_bundle(RevocationList(), issuer=authority.kid)
        envelope = sign_revocation_bundle(bundle, authority)
        with self.assertRaises(ValueError):
            verify_revocation_bundle(
                envelope,
                trusted_authorities={other.kid},
            )

    def test_tampered_bundle_is_rejected(self) -> None:
        authority = Ed25519KeyPair.generate()
        rl = RevocationList()
        rl.revoke("kinegrant:cap:" + "a" * 64)
        bundle = build_revocation_bundle(rl, issuer=authority.kid)
        envelope = sign_revocation_bundle(bundle, authority)
        envelope["payload"]["revocations"][0]["capability_id"] = (
            "kinegrant:cap:" + "b" * 64
        )
        with self.assertRaises(ValueError):
            verify_revocation_bundle(envelope)

    def test_previous_digest_chain_is_enforced(self) -> None:
        authority = Ed25519KeyPair.generate()
        first = build_revocation_bundle(
            RevocationList(),
            issuer=authority.kid,
            version=1,
        )
        first_envelope = sign_revocation_bundle(first, authority)
        verify_revocation_bundle(first_envelope)
        second = build_revocation_bundle(
            RevocationList(),
            issuer=authority.kid,
            version=2,
            previous_bundle_digest=bundle_digest(first),
        )
        second_envelope = sign_revocation_bundle(second, authority)
        verify_revocation_bundle(
            second_envelope,
            expected_previous_digest=bundle_digest(first),
        )
        with self.assertRaises(ValueError):
            verify_revocation_bundle(
                second_envelope,
                expected_previous_digest="sha256:" + "0" * 64,
            )

    def test_invalid_bundle_shapes_are_rejected(self) -> None:
        authority = Ed25519KeyPair.generate()
        with self.assertRaises(ValueError):
            build_revocation_bundle(
                RevocationList(),
                issuer=authority.kid,
                version=0,
            )
        with self.assertRaises(ValueError):
            build_revocation_bundle(
                RevocationList(),
                issuer=authority.kid,
                previous_bundle_digest="not-a-digest",
            )

    def test_bundle_feeds_the_gate(self) -> None:
        authority = Ed25519KeyPair.generate()
        issuer = CapabilityIssuer(authority)
        request = ActionRequest(
            request_id="req-bundle-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        rule = PolicyRule(
            policy_id="bundle-rule-1",
            issuer=authority.kid,
            target="door-7",
            effect="allow",
            actions=("open",),
        )
        decision = PolicyEngine(
            [rule], trusted_policy_issuers={authority.kid}
        ).evaluate(request)
        capability = issuer.issue(request, decision, ttl_seconds=30)
        rl = RevocationList()
        rl.revoke(capability["payload"]["capability_id"])
        bundle = build_revocation_bundle(rl, issuer=authority.kid)
        envelope = sign_revocation_bundle(bundle, authority)
        loaded = verify_revocation_bundle(envelope, trusted_authorities={authority.kid})
        gate = ActionGate(
            trusted_issuers={authority.kid},
            revocation_list=loaded,
        )
        with self.assertRaises(PermissionError):
            gate.authorize(capability, request)


if __name__ == "__main__":
    unittest.main()
