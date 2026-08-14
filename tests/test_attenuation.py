from __future__ import annotations

import json
import unittest
from pathlib import Path

import jsonschema

from kinegrant.attenuation import attenuate_capability, verify_attenuation
from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine


class AttenuationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issuer = CapabilityIssuer(Ed25519KeyPair.generate())
        self.gate = ActionGate(
            trusted_issuers={self.issuer.key_pair.kid},
            replay_store=InMemoryReplayStore(),
        )
        rule = PolicyRule(
            policy_id="scoped-1",
            issuer=self.issuer.key_pair.kid,
            target="door-*",
            effect="allow",
            actions=("open", "close"),
            purposes=("delivery", "maintenance"),
        )
        self.engine = PolicyEngine(
            [rule],
            trusted_policy_issuers={self.issuer.key_pair.kid},
        )
        self.request = ActionRequest(
            request_id="req-atten-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        self.decision = self.engine.evaluate(self.request)
        self.root = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=30,
            target="door-*",
            actions=["open", "close"],
            purposes=["delivery", "maintenance"],
            approval_tier=1,
        )
        self.root_payload = self.root["payload"]

    def delegate_request(self, agent: str = "robot-2") -> ActionRequest:
        return ActionRequest(
            request_id=f"req-delegate-{agent}",
            agent=agent,
            target="door-7",
            action="open",
            purpose="delivery",
        )

    def test_root_v02_capability_passes_gate(self) -> None:
        verified = self.gate.authorize(self.root, self.request)
        self.assertEqual(verified["version"], "0.2")
        self.assertEqual(verified["approval_tier"], 1)

    def test_attenuation_narrows_scope_and_passes_gate(self) -> None:
        child = self.issuer.issue_attenuated(
            self.root,
            target="door-7",
            actions=["open"],
            purposes=["delivery"],
            ttl_seconds=15,
        )
        self.assertTrue(verify_attenuation(child["payload"], self.root_payload))
        verified = self.gate.authorize(child, self.request)
        self.assertEqual(verified["target"], "door-7")
        self.assertEqual(verified["actions"], ["open"])

    def test_child_is_single_use(self) -> None:
        child = self.issuer.issue_attenuated(
            self.root,
            target="door-7",
            ttl_seconds=15,
        )
        self.gate.authorize(child, self.request)
        with self.assertRaises(PermissionError):
            self.gate.authorize(child, self.request)

    def test_target_outside_parent_scope_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.issuer.issue_attenuated(self.root, target="hall-*")

    def test_action_outside_parent_scope_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.issuer.issue_attenuated(self.root, actions=["open", "record"])

    def test_purpose_outside_parent_scope_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.issuer.issue_attenuated(self.root, purposes=["training"])

    def test_ttl_cannot_extend_parent_lifetime(self) -> None:
        with self.assertRaises(ValueError):
            self.issuer.issue_attenuated(self.root, ttl_seconds=301)

    def test_physical_limits_can_only_tighten(self) -> None:
        child = self.issuer.issue_attenuated(
            self.root,
            max_force_newtons=50,
            max_velocity_mps=1.5,
            allowed_zones=["dock-*"],
        )
        # An unrestricted parent may gain limits; the verifier must accept it.
        self.assertTrue(verify_attenuation(child["payload"], self.root_payload))
        with self.assertRaises(ValueError):
            self.issuer.issue_attenuated(
                child,
                max_force_newtons=80,
            )
        with self.assertRaises(ValueError):
            self.issuer.issue_attenuated(
                child,
                allowed_zones=["lobby"],
            )
        nested = self.issuer.issue_attenuated(
            child,
            max_force_newtons=20,
            allowed_zones=["dock-1"],
        )
        self.assertTrue(verify_attenuation(nested["payload"], child["payload"]))

    def test_gate_rejects_child_when_parent_mismatches(self) -> None:
        child = self.issuer.issue_attenuated(
            self.root,
            target="door-7",
            ttl_seconds=15,
        )
        other_root = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=30,
            target="hall-*",
            actions=["open"],
            purposes=["delivery"],
            approval_tier=1,
        )
        with self.assertRaises(PermissionError):
            self.gate.authorize(
                child,
                self.request,
                parent_capability=other_root,
            )
        self.gate.authorize(
            child,
            self.request,
            parent_capability=self.root,
        )

    def test_v01_parent_can_be_attenuated(self) -> None:
        v1 = self.issuer.issue(self.request, self.decision, ttl_seconds=30)
        child = self.issuer.issue_attenuated(v1, ttl_seconds=10)
        self.assertTrue(verify_attenuation(child["payload"], v1["payload"]))
        self.assertEqual(child["payload"]["actions"], ["open"])
        verified = self.gate.authorize(child, self.request)
        self.assertEqual(verified["version"], "0.2")

    def test_verify_attenuation_rejects_tampering(self) -> None:
        child = self.issuer.issue_attenuated(
            self.root,
            target="door-7",
            actions=["open"],
            ttl_seconds=15,
        )
        tampered = json.loads(json.dumps(child["payload"]))
        tampered["approval_tier"] = 0
        self.assertFalse(verify_attenuation(tampered, self.root_payload))
        tampered2 = json.loads(json.dumps(child["payload"]))
        tampered2["actions"] = ["record"]
        self.assertFalse(verify_attenuation(tampered2, self.root_payload))

    def test_v02_envelope_matches_published_schema(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "spec"
            / "schemas"
            / "capability-v0.2.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(self.root, schema)
        child = self.issuer.issue_attenuated(
            self.root,
            target="door-7",
            ttl_seconds=15,
        )
        jsonschema.validate(child, schema)

    def test_cross_agent_delegation_with_opt_in(self) -> None:
        delegate_request = self.delegate_request()
        root = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=30,
            target="door-*",
            actions=["open"],
            purposes=["delivery"],
            approval_tier=1,
            delegation_allowed=True,
            max_delegation_depth=1,
        )
        child = self.issuer.issue_attenuated(
            root,
            target="door-7",
            delegate_agent="robot-2",
            delegate_request=delegate_request,
        )
        payload = child["payload"]
        self.assertEqual(payload["delegate_agent"], "robot-2")
        self.assertEqual(payload["delegation_depth"], 1)
        self.assertFalse(payload["delegation_allowed"])
        self.assertEqual(payload["max_delegation_depth"], 0)
        verified = self.gate.authorize(child, delegate_request)
        self.assertEqual(verified["agent"], "robot-1")
        self.assertEqual(verified["delegate_agent"], "robot-2")

    def test_delegation_without_opt_in_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.issuer.issue_attenuated(
                self.root,
                target="door-7",
                delegate_agent="robot-2",
            )

    def test_delegated_child_cannot_redelegate(self) -> None:
        root = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=30,
            target="door-*",
            actions=["open"],
            purposes=["delivery"],
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        child = self.issuer.issue_attenuated(
            root,
            target="door-7",
            delegate_agent="robot-2",
            delegate_request=self.delegate_request(),
        )
        with self.assertRaises(ValueError):
            self.issuer.issue_attenuated(
                child,
                delegate_agent="robot-3",
            )

    def test_delegated_capability_rejects_principal_agent(self) -> None:
        root = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=30,
            target="door-*",
            actions=["open"],
            purposes=["delivery"],
            delegation_allowed=True,
            max_delegation_depth=1,
        )
        child = self.issuer.issue_attenuated(
            root,
            target="door-7",
            delegate_agent="robot-2",
            delegate_request=self.delegate_request(),
        )
        with self.assertRaises(PermissionError):
            self.gate.authorize(child, self.request)

    def test_verify_attenuation_rejects_depth_tampering(self) -> None:
        root = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=30,
            target="door-*",
            actions=["open"],
            purposes=["delivery"],
            delegation_allowed=True,
            max_delegation_depth=1,
        )
        child = self.issuer.issue_attenuated(
            root,
            target="door-7",
            delegate_agent="robot-2",
            delegate_request=self.delegate_request(),
        )
        self.assertTrue(verify_attenuation(child["payload"], root["payload"]))
        tampered = json.loads(json.dumps(child["payload"]))
        tampered["delegation_depth"] = 2
        self.assertFalse(verify_attenuation(tampered, root["payload"]))

    def test_delegate_allowlist_restricts_delegation(self) -> None:
        root = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=30,
            target="door-*",
            actions=["open"],
            purposes=["delivery"],
            delegation_allowed=True,
            max_delegation_depth=1,
            delegate_allowlist=["robot-2"],
        )
        with self.assertRaises(ValueError):
            self.issuer.issue_attenuated(
                root,
                target="door-7",
                delegate_agent="robot-3",
                delegate_request=self.delegate_request("robot-3"),
            )
        child = self.issuer.issue_attenuated(
            root,
            target="door-7",
            delegate_agent="robot-2",
            delegate_request=self.delegate_request(),
        )
        self.assertTrue(verify_attenuation(child["payload"], root["payload"]))
        self.assertEqual(child["payload"]["delegate_allowlist"], ["robot-2"])

    def test_delegate_allowlist_glob_patterns(self) -> None:
        root = self.issuer.issue_scoped(
            self.request,
            self.decision,
            ttl_seconds=30,
            target="door-*",
            actions=["open"],
            purposes=["delivery"],
            delegation_allowed=True,
            max_delegation_depth=1,
            delegate_allowlist=["fleet-*"],
        )
        child = self.issuer.issue_attenuated(
            root,
            target="door-7",
            delegate_agent="fleet-robot-2",
            delegate_request=self.delegate_request("fleet-robot-2"),
        )
        self.assertTrue(verify_attenuation(child["payload"], root["payload"]))

    def test_root_capability_id_propagates_through_chain(self) -> None:
        child = self.issuer.issue_attenuated(
            self.root,
            target="door-7",
            ttl_seconds=15,
        )
        root_id = self.root_payload["capability_id"]
        self.assertEqual(child["payload"]["root_capability_id"], root_id)
        nested = self.issuer.issue_attenuated(
            child,
            target="door-7",
            ttl_seconds=5,
        )
        self.assertEqual(nested["payload"]["root_capability_id"], root_id)
        self.assertTrue(verify_attenuation(nested["payload"], child["payload"]))

    def test_verify_attenuation_rejects_root_id_tampering(self) -> None:
        child = self.issuer.issue_attenuated(
            self.root,
            target="door-7",
            ttl_seconds=15,
        )
        tampered = json.loads(json.dumps(child["payload"]))
        tampered["root_capability_id"] = "kinegrant:cap:" + "0" * 64
        self.assertFalse(verify_attenuation(tampered, self.root_payload))


if __name__ == "__main__":
    unittest.main()
