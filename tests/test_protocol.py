from __future__ import annotations

import copy
import unittest
from datetime import timedelta

from kinegrant.adapters import (
    matter_command_request,
    myterms_to_rules,
    odrl_to_rules,
    opcua_method_request,
    ros_action_request,
    wot_action_request,
)
from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.gate import ActionGate
from kinegrant.models import ActionRequest, PolicyRule, utc_now
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog, verify_receipt_chain


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = ActionRequest(
            request_id="req-1",
            agent="robot:1",
            target="room:1:door",
            action="open",
            purpose="delivery",
            context={"risk_tier": 1},
        )

    def test_default_deny(self) -> None:
        decision = PolicyEngine().evaluate(self.request)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "default_deny")

    def test_allow_and_obligation(self) -> None:
        rule = PolicyRule(
            policy_id="policy:allow",
            issuer="owner:1",
            target="room:1:*",
            effect="allow",
            actions=("open",),
            subjects=("robot:*",),
            purposes=("delivery",),
            obligations=("emitActionReceipt",),
        )
        decision = PolicyEngine([rule]).evaluate(self.request)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.obligations, ("emitActionReceipt",))

    def test_deny_overrides_allow(self) -> None:
        allow = PolicyRule("a", "owner", "room:1:*", "allow", ("open",))
        deny = PolicyRule("b", "safety", "room:1:door", "deny", ("open",))
        decision = PolicyEngine([allow, deny]).evaluate(self.request)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "explicit_deny")


class CapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = ActionRequest("req-2", "robot:2", "door:2", "open", "delivery")
        rule = PolicyRule("p", "owner", "door:2", "allow", ("open",), subjects=("robot:2",))
        self.decision = PolicyEngine([rule]).evaluate(self.request)
        self.authority = Ed25519KeyPair.generate()
        self.capability = CapabilityIssuer(self.authority).issue(self.request, self.decision)

    def test_gate_accepts_once_and_rejects_replay(self) -> None:
        gate = ActionGate(trusted_issuers={self.authority.kid})
        gate.authorize(self.capability, self.request)
        with self.assertRaises(PermissionError):
            gate.authorize(self.capability, self.request)

    def test_tampering_breaks_signature(self) -> None:
        tampered = copy.deepcopy(self.capability)
        tampered["payload"]["action"] = "unlock-everything"
        gate = ActionGate(trusted_issuers={self.authority.kid})
        with self.assertRaises(ValueError):
            gate.authorize(tampered, self.request)

    def test_expired_capability_is_rejected(self) -> None:
        gate = ActionGate(trusted_issuers={self.authority.kid})
        future = utc_now() + timedelta(minutes=10)
        with self.assertRaises(PermissionError):
            gate.authorize(self.capability, self.request, now=future)

    def test_empty_trust_store_denies(self) -> None:
        with self.assertRaises(PermissionError):
            ActionGate().authorize(self.capability, self.request)

    def test_capability_cannot_be_used_for_another_request(self) -> None:
        other = ActionRequest("req-3", "robot:2", "door:2", "open", "maintenance")
        gate = ActionGate(trusted_issuers={self.authority.kid})
        with self.assertRaises(PermissionError):
            gate.authorize(self.capability, other)

    def test_receipt_chain_detects_tampering(self) -> None:
        gate = ActionGate(trusted_issuers={self.authority.kid})
        claims = gate.authorize(self.capability, self.request)
        log = ReceiptLog(Ed25519KeyPair.generate())
        log.append(claims, result="succeeded")
        log.append(claims, result="aborted")
        self.assertTrue(verify_receipt_chain(log.entries))
        bad = [copy.deepcopy(item) for item in log.entries]
        bad[0]["payload"]["result"] = "failed"
        with self.assertRaises(ValueError):
            verify_receipt_chain(bad)


class AdapterTests(unittest.TestCase):
    def test_odrl_adapter(self) -> None:
        rules = odrl_to_rules(
            {
                "uid": "policy:1",
                "assigner": "owner:1",
                "permission": {
                    "target": "door:1",
                    "assignee": "robot:1",
                    "action": "open",
                    "constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "delivery"},
                },
            }
        )
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].purposes, ("delivery",))

    def test_myterms_adapter(self) -> None:
        rules = myterms_to_rules(
            {
                "id": "terms:alice",
                "subject": "person:alice",
                "target": "person:alice",
                "terms": [{"action": "record", "effect": "deny", "purposes": ["training"]}],
            }
        )
        self.assertEqual(rules[0].effect, "deny")
        self.assertEqual(rules[0].purposes, ("training",))

    def test_transport_adapters(self) -> None:
        wot = wot_action_request(
            {"id": "thing:door", "actions": {"open": {"safe": False}}},
            action_name="open",
            agent="robot:1",
            purpose="delivery",
            request_id="wot-1",
        )
        ros = ros_action_request(
            node_identity="robot:1", action_name="move", physical_target="box:1",
            purpose="sorting", request_id="ros-1"
        )
        opc = opcua_method_request(
            session_identity="operator:1", server_uri="urn:plant", node_id="ns=2;i=4",
            method="Start", purpose="production", request_id="opc-1"
        )
        matter = matter_command_request(
            fabric_identity="fabric:1", node_id="10", endpoint=1, cluster="DoorLock",
            command="UnlockDoor", purpose="entry", request_id="matter-1"
        )
        self.assertEqual(wot.context["transport"], "wot")
        self.assertEqual(ros.context["transport"], "ros2")
        self.assertEqual(opc.context["transport"], "opcua")
        self.assertEqual(matter.context["transport"], "matter")


if __name__ == "__main__":
    unittest.main()
