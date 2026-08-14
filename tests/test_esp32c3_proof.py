from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator

from kinegrant.capability import CapabilityIssuer
from kinegrant.canonical import content_id
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.experimental.esp32c3 import (
    DeviceCommandIssuer,
    DeviceChallenge,
    SQLiteDeviceStateStore,
    SimulatedPaperBarrierDevice,
    verify_device_ack,
)
from kinegrant.gate import ActionGate, SQLiteReplayStore
from kinegrant.models import ActionRequest, PolicyRule, utc_now
from kinegrant.policy import PolicyEngine


class FakeMonotonic:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


class ESP32C3ProofProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.executor = Ed25519KeyPair.generate()
        self.device_key = Ed25519KeyPair.generate()
        self.device_id = "device:esp32c3:paper-barrier:1"
        self.request = ActionRequest(
            "proof:req:1",
            "agent:proof-host:1",
            self.device_id,
            "move_paper_barrier",
            "permission-proof",
            context={"device_parameters": {"position": "open"}},
        )
        rule = PolicyRule(
            "proof:policy:1",
            "owner:proof-lab",
            self.device_id,
            "allow",
            ("move_paper_barrier",),
            subjects=("agent:proof-host:1",),
            purposes=("permission-proof",),
        )
        decision = PolicyEngine(
            [rule], trusted_policy_issuers={"owner:proof-lab"}
        ).evaluate(self.request)
        self.capability = CapabilityIssuer(self.authority).issue(self.request, decision, ttl_seconds=10)

    def authorize(self):
        return ActionGate(trusted_issuers={self.authority.kid}).authorize(
            self.capability, self.request
        )

    def device(self, **kwargs):
        return SimulatedPaperBarrierDevice(
            device_id=self.device_id,
            device_key=self.device_key,
            trusted_executors={self.executor.kid},
            **kwargs,
        )

    def command(self, device, claims=None):
        challenge = device.challenge()
        return DeviceCommandIssuer(self.executor).issue(
            claims or self.authorize(), self.request, challenge
        )

    def test_no_gate_consumption_means_no_device_command(self) -> None:
        device = self.device()
        self.assertEqual(device.actuator_count, 0)

    def test_valid_capability_moves_exactly_once_and_ack_verifies(self) -> None:
        device = self.device()
        challenge = device.challenge()
        command = DeviceCommandIssuer(self.executor).issue(
            self.authorize(), self.request, DeviceChallenge.from_dict(challenge.to_dict())
        )
        ack = device.execute(command)
        self.assertTrue(
            verify_device_ack(
                ack,
                trusted_devices={self.device_key.kid},
                expected_command_ids={command["payload"]["command_id"]},
                expected_device_ids={self.device_id},
                expected_capability_ids={command["payload"]["capability_id"]},
            )
        )
        self.assertEqual(ack["payload"]["actuator_count"], 1)

        schema_dir = Path(__file__).parents[1] / "proof" / "esp32-c3" / "schemas"
        for filename, value in (
            ("device-challenge.schema.json", challenge.to_dict()),
            ("device-command.schema.json", command),
            ("device-ack.schema.json", ack),
        ):
            schema = json.loads((schema_dir / filename).read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(value)

    def test_device_command_replay_is_denied(self) -> None:
        device = self.device()
        command = self.command(device)
        device.execute(command)
        device.challenge()
        with self.assertRaises(PermissionError):
            device.execute(command)

    def test_verified_capability_can_issue_only_one_device_command(self) -> None:
        device = self.device()
        claims = self.authorize()
        issuer = DeviceCommandIssuer(self.executor)
        issuer.issue(claims, self.request, device.challenge())
        with self.assertRaises(PermissionError):
            issuer.issue(claims, self.request, device.challenge())

    def test_device_command_issuance_replay_state_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            issuance_store = SQLiteReplayStore(Path(temp_dir) / "issuance.sqlite3")
            device = self.device()
            claims = self.authorize()
            DeviceCommandIssuer(
                self.executor, issuance_store=issuance_store
            ).issue(claims, self.request, device.challenge())
            with self.assertRaises(PermissionError):
                DeviceCommandIssuer(
                    self.executor, issuance_store=issuance_store
                ).issue(claims, self.request, device.challenge())

    def test_concurrent_device_command_issuance_has_one_winner(self) -> None:
        device = self.device()
        claims = self.authorize()
        issuer = DeviceCommandIssuer(self.executor)
        challenge = device.challenge()

        def attempt() -> bool:
            try:
                issuer.issue(claims, self.request, challenge)
                return True
            except PermissionError:
                return False

        with ThreadPoolExecutor(max_workers=32) as executor:
            outcomes = list(executor.map(lambda _: attempt(), range(64)))
        self.assertEqual(sum(outcomes), 1)

    def test_expired_capability_cannot_produce_device_command(self) -> None:
        device = self.device()
        issuer = DeviceCommandIssuer(
            self.executor,
            now=lambda: utc_now() + timedelta(minutes=1),
        )
        with self.assertRaises(PermissionError):
            issuer.issue(self.authorize(), self.request, device.challenge())

    def test_binding_tampering_breaks_command_signature(self) -> None:
        for path, value in (
            (("device_id",), "device:esp32c3:paper-barrier:other"),
            (("action",), "spin_servo"),
            (("parameters", "position"), "closed"),
        ):
            with self.subTest(path=path):
                device = self.device()
                command = self.command(device)
                target = command["payload"]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(PermissionError):
                    device.execute(command)
                self.assertEqual(device.actuator_count, 0)

    def test_untrusted_executor_is_denied(self) -> None:
        device = self.device()
        claims = self.authorize()
        command = DeviceCommandIssuer(Ed25519KeyPair.generate()).issue(
            claims, self.request, device.challenge()
        )
        with self.assertRaises(PermissionError):
            device.execute(command)

    def test_exact_ten_second_challenge_expiry_is_denied(self) -> None:
        clock = FakeMonotonic()
        device = self.device(monotonic=clock)
        command = self.command(device)
        clock.value = 10.0
        with self.assertRaises(PermissionError):
            device.execute(command)

    def test_concurrent_replay_has_one_winner(self) -> None:
        device = self.device()
        command = self.command(device)

        def attempt() -> bool:
            try:
                device.execute(command)
                return True
            except PermissionError:
                return False

        with ThreadPoolExecutor(max_workers=32) as executor:
            outcomes = list(executor.map(lambda _: attempt(), range(64)))
        self.assertEqual(sum(outcomes), 1)
        self.assertEqual(device.actuator_count, 1)

    def test_old_command_is_denied_after_persistent_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = SQLiteDeviceStateStore(Path(temp_dir) / "device-state.sqlite3")
            first = self.device(state_store=store)
            command = self.command(first)
            first.execute(command)

            restarted = self.device(state_store=store)
            restarted.challenge()
            with self.assertRaises(PermissionError):
                restarted.execute(command)

    def test_ack_tampering_and_untrusted_device_are_denied(self) -> None:
        device = self.device()
        ack = device.execute(self.command(device))
        tampered = copy.deepcopy(ack)
        tampered["payload"]["actuator_count"] = 999
        self.assertFalse(verify_device_ack(tampered, trusted_devices={self.device_key.kid}))
        self.assertFalse(verify_device_ack(ack, trusted_devices={Ed25519KeyPair.generate().kid}))
        self.assertFalse(
            verify_device_ack(
                ack,
                trusted_devices={self.device_key.kid},
                expected_device_ids={"device:other"},
            )
        )

    def test_unknown_envelope_fields_and_boolean_sequence_are_denied(self) -> None:
        device = self.device()
        command = self.command(device)
        command["unprotected"] = "ignored-by-signature"
        with self.assertRaises(PermissionError):
            device.execute(command)

        device = self.device()
        challenge = device.challenge()
        claims = self.authorize()
        command = DeviceCommandIssuer(self.executor).issue(claims, self.request, challenge)
        payload = dict(command["payload"])
        payload["sequence"] = True
        payload_without_id = dict(payload)
        del payload_without_id["command_id"]
        payload["command_id"] = content_id("kinegrant:device-command", payload_without_id)
        command = self.executor.sign_envelope(payload)
        with self.assertRaises(PermissionError):
            device.execute(command)

    def test_signed_but_unsupported_parameters_are_denied(self) -> None:
        bad_request = ActionRequest(
            "proof:req:bad",
            self.request.agent,
            self.device_id,
            "move_paper_barrier",
            self.request.purpose,
            context={"device_parameters": {"pulse_us": 20_000}},
        )
        rule = PolicyRule(
            "proof:policy:bad",
            "owner:proof-lab",
            self.device_id,
            "allow",
            ("move_paper_barrier",),
            subjects=(self.request.agent,),
            purposes=(self.request.purpose,),
        )
        decision = PolicyEngine([rule], trusted_policy_issuers={"owner:proof-lab"}).evaluate(bad_request)
        capability = CapabilityIssuer(self.authority).issue(bad_request, decision)
        claims = ActionGate(trusted_issuers={self.authority.kid}).authorize(capability, bad_request)
        device = self.device()
        command = DeviceCommandIssuer(self.executor).issue(claims, bad_request, device.challenge())
        with self.assertRaises(PermissionError):
            device.execute(command)


if __name__ == "__main__":
    unittest.main()
