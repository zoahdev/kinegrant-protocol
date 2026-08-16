from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from kinegrant.server import DEFAULT_POLICY, build_service_from_dir


ALLOW = {
    "agent": "urn:robot:delivery-1",
    "target": "urn:space:demo:door-7",
    "action": "open",
    "purpose": "delivery",
    "context": {"risk_tier": 1},
}


def _deny_policy() -> dict:
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    policy["permission"][0]["assignee"] = "urn:robot:someone-else"
    return policy


class GateServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        (self.dir / "policy.json").write_text(
            json.dumps(DEFAULT_POLICY), encoding="utf-8"
        )
        (self.dir / "config.json").write_text(
            json.dumps(
                {
                    "host": "127.0.0.1",
                    "port": 18770,
                    "capability_ttl_seconds": 30,
                    "trusted_policy_issuers": ["urn:person:space-owner"],
                    "keys_dir": "keys",
                    "replay_db": "gate-replay.sqlite3",
                    "receipt_log": "receipt-log.json",
                }
            ),
            encoding="utf-8",
        )
        self.service = build_service_from_dir(self.dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_authorize_allow(self) -> None:
        result = self.service.authorize(ALLOW)
        self.assertTrue(result["decision"]["allowed"])
        self.assertIsNotNone(result["capability"])

    def test_authorize_deny(self) -> None:
        result = self.service.authorize({**ALLOW, "action": "record"})
        self.assertFalse(result["decision"]["allowed"])
        self.assertIsNone(result["capability"])

    def test_verify_and_replay(self) -> None:
        authorized = self.service.authorize(ALLOW)
        first = self.service.verify(
            authorized["request"],
            authorized["capability"],
        )
        self.assertTrue(first["allowed"])
        with self.assertRaises(PermissionError):
            self.service.verify(authorized["request"], authorized["capability"])

    def test_receipt_and_chain(self) -> None:
        authorized = self.service.authorize(ALLOW)
        result = self.service.receipt(
            authorized["request"],
            authorized["capability"],
            "succeeded",
            None,
        )
        self.assertTrue(result["receipt_chain_valid"])
        self.assertEqual(
            result["receipt"]["payload"]["result"],
            "succeeded",
        )

    def test_list_receipts(self) -> None:
        self.service.run(ALLOW)
        self.service.run(ALLOW)
        listing = self.service.list_receipts()
        self.assertEqual(listing["count"], 2)
        self.assertTrue(listing["chain_valid"])
        self.assertEqual(len(listing["receipts"]), 2)

    def test_health(self) -> None:
        health = self.service.health()
        self.assertEqual(health["status"], "ok")
        self.assertIn("receipts", health["endpoints"])
        self.assertIn("receipt_count", health)

    def test_hot_reload_policy(self) -> None:
        self.assertTrue(self.service.authorize(ALLOW)["decision"]["allowed"])
        (self.dir / "policy.json").write_text(
            json.dumps(_deny_policy()), encoding="utf-8"
        )
        self.assertFalse(self.service.authorize(ALLOW)["decision"]["allowed"])

    def test_malformed_policy_error(self) -> None:
        (self.dir / "policy.json").write_text("{bad json", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "policy.json"):
            self.service.authorize(ALLOW)

    def test_capability_must_be_object(self) -> None:
        with self.assertRaisesRegex(ValueError, "capability must be a JSON object"):
            self.service.verify(ALLOW, "not-an-object")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
