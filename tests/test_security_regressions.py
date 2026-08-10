from __future__ import annotations

import copy
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from kinegrant.adapters import matter_command_request, myterms_to_rules, odrl_to_rules
from kinegrant.canonical import content_id
from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair, verify_envelope
from kinegrant.gate import ActionGate, SQLiteReplayStore
from kinegrant.models import ActionRequest, PolicyRule, isoformat, utc_now
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog, verify_receipt_chain


def allowed_fixture() -> tuple[ActionRequest, Ed25519KeyPair, dict[str, object]]:
    request = ActionRequest("request:security", "robot:1", "door:1", "open", "delivery")
    rule = PolicyRule(
        "policy:trusted", "owner:trusted", "door:1", "allow", ("open",),
        subjects=("robot:1",), purposes=("delivery",), obligations=("emitActionReceipt",),
    )
    decision = PolicyEngine(
        [rule], trusted_policy_issuers={"owner:trusted"}
    ).evaluate(request)
    authority = Ed25519KeyPair.generate()
    return request, authority, CapabilityIssuer(authority).issue(request, decision)


class PolicyTrustTests(unittest.TestCase):
    def test_untrusted_policy_cannot_allow(self) -> None:
        request = ActionRequest("r", "robot", "door", "open", "delivery")
        rule = PolicyRule("p", "attacker", "door", "allow", ("open",))
        decision = PolicyEngine([rule]).evaluate(request)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "default_deny")

    def test_backdated_request_cannot_bypass_expired_policy(self) -> None:
        now = utc_now()
        request = ActionRequest(
            "r", "robot", "door", "open", "delivery", issued_at=now - timedelta(days=1)
        )
        rule = PolicyRule(
            "p", "owner", "door", "allow", ("open",),
            constraints={"not_after": isoformat(now - timedelta(hours=1))},
        )
        decision = PolicyEngine([rule], trusted_policy_issuers={"owner"}).evaluate(request, now=now)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "stale_request")

    def test_policy_digest_changes_with_policy_content(self) -> None:
        request = ActionRequest("r", "robot", "door", "open", "delivery")
        first = PolicyRule("p", "owner", "door", "allow", ("open",))
        second = PolicyRule(
            "p", "owner", "door", "allow", ("open",), constraints={"max_risk_tier": 1}
        )
        d1 = PolicyEngine([first], trusted_policy_issuers={"owner"}).evaluate(request)
        d2 = PolicyEngine([second], trusted_policy_issuers={"owner"}).evaluate(request)
        self.assertNotEqual(d1.policy_digest, d2.policy_digest)

    def test_duplicate_policy_ids_are_rejected(self) -> None:
        first = PolicyRule("same", "owner", "door:1", "allow", ("open",))
        second = PolicyRule("same", "owner", "door:2", "deny", ("open",))
        with self.assertRaises(ValueError):
            PolicyEngine([first, second], trusted_policy_issuers={"owner"})


class AdapterFailClosedTests(unittest.TestCase):
    def test_unknown_odrl_constraint_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            odrl_to_rules({
                "uid": "p", "assigner": "owner",
                "permission": {
                    "target": "door", "assignee": "robot", "action": "open",
                    "constraint": {"leftOperand": "mystery", "operator": "neq", "rightOperand": 1},
                },
            })

    def test_unknown_odrl_statement_field_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            odrl_to_rules({
                "permission": {
                    "target": "door", "assignee": "robot", "action": "open",
                    "unknownRestriction": {"must": "be-respected"},
                }
            })

    def test_missing_odrl_target_or_assignee_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            odrl_to_rules({"permission": {"assignee": "robot", "action": "open"}})
        with self.assertRaises(ValueError):
            odrl_to_rules({"permission": {"target": "door", "action": "open"}})

    def test_malformed_prohibition_is_not_silently_dropped(self) -> None:
        with self.assertRaises(ValueError):
            odrl_to_rules({"prohibition": ["not-an-object"]})

    def test_allowing_myterms_requires_explicit_scope(self) -> None:
        with self.assertRaises(ValueError):
            myterms_to_rules({"subject": "alice", "terms": [{"effect": "allow", "action": "observe"}]})

    def test_adapter_context_cannot_spoof_transport(self) -> None:
        with self.assertRaises(ValueError):
            matter_command_request(
                fabric_identity="f", node_id="1", endpoint=1, cluster="DoorLock",
                command="UnlockDoor", purpose="entry", request_id="r",
                context={"transport": "spoofed"},
            )


class CapabilityGateTests(unittest.TestCase):
    def test_bad_base64url_is_rejected(self) -> None:
        request, authority, capability = allowed_fixture()
        capability["signature"] = capability["signature"] + "!"
        with self.assertRaises(ValueError):
            ActionGate(trusted_issuers={authority.kid}).authorize(capability, request)

    def test_unknown_version_is_rejected(self) -> None:
        request, authority, capability = allowed_fixture()
        body = dict(capability["payload"])
        body["version"] = "9.9"
        body_without_id = dict(body)
        del body_without_id["capability_id"]
        body["capability_id"] = content_id("kinegrant:cap", body_without_id)
        resigned = authority.sign_envelope(body)
        with self.assertRaises(PermissionError):
            ActionGate(trusted_issuers={authority.kid}).authorize(resigned, request)

    def test_overlong_ttl_is_rejected_even_when_signed_by_trusted_issuer(self) -> None:
        request, authority, capability = allowed_fixture()
        body = dict(capability["payload"])
        body["expires_at"] = isoformat(datetime.now(timezone.utc) + timedelta(hours=1))
        body_without_id = dict(body)
        del body_without_id["capability_id"]
        body["capability_id"] = content_id("kinegrant:cap", body_without_id)
        resigned = authority.sign_envelope(body)
        with self.assertRaises(PermissionError):
            ActionGate(trusted_issuers={authority.kid}).authorize(resigned, request)

    def test_exact_expiry_is_rejected(self) -> None:
        request, authority, capability = allowed_fixture()
        expiry = datetime.fromisoformat(capability["payload"]["expires_at"].replace("Z", "+00:00"))
        with self.assertRaises(PermissionError):
            ActionGate(trusted_issuers={authority.kid}).authorize(capability, request, now=expiry)

    def test_concurrent_replay_has_exactly_one_winner(self) -> None:
        request, authority, capability = allowed_fixture()
        gate = ActionGate(trusted_issuers={authority.kid})

        def attempt(_: int) -> bool:
            try:
                gate.authorize(capability, request)
                return True
            except PermissionError:
                return False

        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(attempt, range(64)))
        self.assertEqual(sum(outcomes), 1)

    def test_sqlite_replay_state_survives_gate_restart(self) -> None:
        request, authority, capability = allowed_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/replay.sqlite3"
            first = ActionGate(
                trusted_issuers={authority.kid}, replay_store=SQLiteReplayStore(path)
            )
            first.authorize(capability, request)
            second = ActionGate(
                trusted_issuers={authority.kid}, replay_store=SQLiteReplayStore(path)
            )
            with self.assertRaises(PermissionError):
                second.authorize(capability, request)


class ReceiptTrustTests(unittest.TestCase):
    def test_untrusted_executor_is_rejected(self) -> None:
        request, authority, capability = allowed_fixture()
        claims = ActionGate(trusted_issuers={authority.kid}).authorize(capability, request)
        executor = Ed25519KeyPair.generate()
        log = ReceiptLog(executor)
        log.append(claims, result="succeeded")
        self.assertFalse(verify_receipt_chain(log.entries, trusted_executors=set()))
        self.assertTrue(verify_receipt_chain(log.entries, trusted_executors={executor.kid}))

    def test_duplicate_terminal_receipt_is_rejected(self) -> None:
        request, authority, capability = allowed_fixture()
        claims = ActionGate(trusted_issuers={authority.kid}).authorize(capability, request)
        log = ReceiptLog(Ed25519KeyPair.generate())
        log.append(claims, result="succeeded")
        with self.assertRaises(ValueError):
            log.append(claims, result="failed")

    def test_receipt_requires_gate_verified_claims(self) -> None:
        _, _, capability = allowed_fixture()
        with self.assertRaises(TypeError):
            ReceiptLog(Ed25519KeyPair.generate()).append(capability["payload"], result="succeeded")


if __name__ == "__main__":
    unittest.main()
