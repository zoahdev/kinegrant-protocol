from __future__ import annotations

from collections import deque
import unittest

from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.experimental.esp32c3 import DeviceCommandIssuer, SimulatedPaperBarrierDevice
from kinegrant.experimental.esp32c3_serial import (
    PaperBarrierSerialClient,
    read_device_challenge,
    read_serial_object,
)
from kinegrant.experimental.esp32c3_transport import decode_frame, encode_frame
from kinegrant.gate import ActionGate
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine


class FakeSerial:
    def __init__(self, reads=(), *, on_write=None, short_write=False) -> None:
        self.reads = deque(reads)
        self.on_write = on_write
        self.short_write = short_write
        self.writes = []
        self.flushed = False
        self.closed = False

    def read(self, size: int) -> bytes:
        return self.reads.popleft() if self.reads else b""

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        if self.on_write is not None:
            self.on_write(data, self)
        return len(data) - 1 if self.short_write else len(data)

    def flush(self) -> None:
        self.flushed = True

    def close(self) -> None:
        self.closed = True


class AdvancingClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        self.value += 0.05
        return self.value


class ESP32C3SerialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.executor = Ed25519KeyPair.generate()
        self.device_key = Ed25519KeyPair.generate()
        self.device_id = "device:esp32c3:paper-barrier:serial"
        self.request = ActionRequest(
            "serial:req:1",
            "agent:serial-host:1",
            self.device_id,
            "move_paper_barrier",
            "permission-proof",
            context={"device_parameters": {"position": "open"}},
        )
        rule = PolicyRule(
            "serial:policy:1",
            "owner:proof-lab",
            self.device_id,
            "allow",
            ("move_paper_barrier",),
            subjects=(self.request.agent,),
            purposes=(self.request.purpose,),
        )
        decision = PolicyEngine(
            [rule], trusted_policy_issuers={"owner:proof-lab"}
        ).evaluate(self.request)
        capability = CapabilityIssuer(self.authority).issue(self.request, decision)
        self.verified = ActionGate(trusted_issuers={self.authority.kid}).authorize(
            capability, self.request
        )

    def test_real_session_shape_round_trips_with_fragmented_reads(self) -> None:
        device = SimulatedPaperBarrierDevice(
            device_id=self.device_id,
            device_key=self.device_key,
            trusted_executors={self.executor.kid},
        )
        challenge_frame = encode_frame(device.challenge().to_dict())
        serial = FakeSerial([challenge_frame[:9], challenge_frame[9:]])

        def execute(data: bytes, peer: FakeSerial) -> None:
            acknowledgement = device.execute(decode_frame(data))
            frame = encode_frame(acknowledgement)
            peer.reads.extend((frame[:13], frame[13:]))

        serial.on_write = execute
        exchange = PaperBarrierSerialClient(
            serial,
            DeviceCommandIssuer(self.executor),
            trusted_devices={self.device_key.kid},
        ).execute_once(self.verified, self.request)
        self.assertEqual(device.actuator_count, 1)
        self.assertTrue(serial.flushed)
        self.assertEqual(exchange.challenge["device_id"], self.device_id)
        self.assertEqual(exchange.command_frame, serial.writes[0])

    def test_untrusted_ack_is_rejected_after_single_device_attempt(self) -> None:
        device = SimulatedPaperBarrierDevice(
            device_id=self.device_id,
            device_key=self.device_key,
            trusted_executors={self.executor.kid},
        )
        serial = FakeSerial([encode_frame(device.challenge().to_dict())])
        serial.on_write = lambda data, peer: peer.reads.append(
            encode_frame(device.execute(decode_frame(data)))
        )
        client = PaperBarrierSerialClient(
            serial,
            DeviceCommandIssuer(self.executor),
            trusted_devices={Ed25519KeyPair.generate().kid},
        )
        with self.assertRaisesRegex(PermissionError, "acknowledgement"):
            client.execute_once(self.verified, self.request)
        self.assertEqual(device.actuator_count, 1)

    def test_short_write_fails_before_acknowledgement_read(self) -> None:
        device = SimulatedPaperBarrierDevice(
            device_id=self.device_id,
            device_key=self.device_key,
            trusted_executors={self.executor.kid},
        )
        serial = FakeSerial(
            [encode_frame(device.challenge().to_dict())], short_write=True
        )
        client = PaperBarrierSerialClient(
            serial,
            DeviceCommandIssuer(self.executor),
            trusted_devices={self.device_key.kid},
        )
        with self.assertRaises(ConnectionError):
            client.execute_once(self.verified, self.request)
        self.assertFalse(serial.flushed)
        self.assertEqual(device.actuator_count, 0)

    def test_timeout_partial_and_surplus_frames_fail_closed(self) -> None:
        with self.assertRaises(TimeoutError):
            read_serial_object(
                FakeSerial([b'{"partial":']),
                timeout_seconds=0.2,
                monotonic=AdvancingClock(),
            )
        with self.assertRaisesRegex(PermissionError, "surplus"):
            read_serial_object(
                FakeSerial([b"{}\n{}\n"]),
                timeout_seconds=0.2,
                monotonic=AdvancingClock(),
            )

    def test_invalid_challenge_and_non_bytes_transport_are_rejected(self) -> None:
        with self.assertRaisesRegex(PermissionError, "invalid challenge"):
            read_device_challenge(
                FakeSerial([b"{}\n"]),
                timeout_seconds=0.2,
                monotonic=AdvancingClock(),
            )
        with self.assertRaises(TypeError):
            read_serial_object(
                FakeSerial(["not-bytes"]),
                timeout_seconds=0.2,
                monotonic=AdvancingClock(),
            )


if __name__ == "__main__":
    unittest.main()
