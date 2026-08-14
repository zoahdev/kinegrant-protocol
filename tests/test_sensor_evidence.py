from __future__ import annotations

import copy
import unittest

from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair, MLDSA65KeyPair
from kinegrant.gate import ActionGate, InMemoryReplayStore
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine
from kinegrant.receipt import ReceiptLog, verify_receipt_chain
from kinegrant.sensor_evidence import (
    SensorReading,
    build_sensor_commitment,
    evidence_hash_for_commitment,
    verify_sensor_commitment,
)


def reading(**overrides: object) -> SensorReading:
    defaults = {
        "kind": "door_position",
        "value": {"open": True, "degrees": 90},
        "source_id": "sensor:door-7:encoder",
        "confidence": 0.99,
        "observed_at": "2026-08-14T00:00:00Z",
    }
    defaults.update(overrides)
    return SensorReading(**defaults)  # type: ignore[arg-type]


class SensorEvidenceTests(unittest.TestCase):
    def test_unsigned_commitment_verifies(self) -> None:
        commitment = build_sensor_commitment([reading()])
        payload = verify_sensor_commitment(commitment)
        self.assertEqual(payload["type"], "kinegrant:SensorEvidenceCommitment")
        self.assertEqual(payload["readings"][0]["kind"], "door_position")

    def test_signed_commitment_round_trip(self) -> None:
        sensor = Ed25519KeyPair.generate()
        commitment = build_sensor_commitment(
            [reading()],
            sensor_kid=sensor.kid,
            key_pair=sensor,
        )
        payload = verify_sensor_commitment(
            commitment,
            trusted_sensors={sensor.kid},
        )
        self.assertEqual(payload["sensor"], sensor.kid)

    def test_mldsa_signed_commitment(self) -> None:
        sensor = MLDSA65KeyPair.generate()
        commitment = build_sensor_commitment(
            [reading()],
            sensor_kid=sensor.kid,
            key_pair=sensor,
        )
        verify_sensor_commitment(commitment, trusted_sensors={sensor.kid})

    def test_tampered_readings_are_rejected(self) -> None:
        commitment = build_sensor_commitment([reading()])
        tampered = copy.deepcopy(commitment)
        tampered["readings"][0]["value_hash"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            verify_sensor_commitment(tampered)

    def test_untrusted_sensor_is_rejected(self) -> None:
        sensor = Ed25519KeyPair.generate()
        commitment = build_sensor_commitment(
            [reading()],
            sensor_kid=sensor.kid,
            key_pair=sensor,
        )
        with self.assertRaises(ValueError):
            verify_sensor_commitment(commitment, trusted_sensors=set())

    def test_invalid_reading_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            reading(confidence=1.5)
        with self.assertRaises(ValueError):
            build_sensor_commitment([])

    def test_evidence_hash_binds_into_receipt(self) -> None:
        authority = Ed25519KeyPair.generate()
        request = ActionRequest(
            request_id="req-sensor-1",
            agent="robot-1",
            target="door-7",
            action="open",
            purpose="delivery",
        )
        rule = PolicyRule(
            policy_id="sensor-rule-1",
            issuer=authority.kid,
            target="door-7",
            effect="allow",
            actions=("open",),
        )
        decision = PolicyEngine(
            [rule], trusted_policy_issuers={authority.kid}
        ).evaluate(request)
        capability = CapabilityIssuer(authority).issue(
            request, decision, ttl_seconds=30
        )
        verified = ActionGate(
            trusted_issuers={authority.kid},
            replay_store=InMemoryReplayStore(),
        ).authorize(capability, request)
        commitment = build_sensor_commitment(
            [reading()],
            sensor_kid=authority.kid,
            key_pair=authority,
        )
        receipt = ReceiptLog(authority).append(
            verified,
            result="succeeded",
            evidence_hash=evidence_hash_for_commitment(commitment),
        )
        self.assertTrue(
            verify_receipt_chain(
                [receipt],
                trusted_executors={authority.kid},
                expected_capability_ids={verified["capability_id"]},
            )
        )


if __name__ == "__main__":
    unittest.main()
