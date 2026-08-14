from __future__ import annotations

import unittest

from kinegrant.capability import CapabilityIssuer
from kinegrant.crypto import Ed25519KeyPair
from kinegrant.experimental.esp32c3 import DeviceCommandIssuer, SimulatedPaperBarrierDevice
from kinegrant.experimental.esp32c3_transport import (
    MAX_FRAME_BYTES,
    NDJSONStreamDecoder,
    decode_frame,
    encode_frame,
)
from kinegrant.gate import ActionGate
from kinegrant.models import ActionRequest, PolicyRule
from kinegrant.policy import PolicyEngine


class ESP32C3TransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.executor = Ed25519KeyPair.generate()
        self.device_key = Ed25519KeyPair.generate()
        self.device_id = "device:esp32c3:paper-barrier:transport"
        self.request = ActionRequest(
            "transport:req:1",
            "agent:transport-host:1",
            self.device_id,
            "move_paper_barrier",
            "permission-proof",
            context={"device_parameters": {"position": "open"}},
        )
        rule = PolicyRule(
            "transport:policy:1",
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
        self.claims = ActionGate(trusted_issuers={self.authority.kid}).authorize(
            capability, self.request
        )

    def device_and_command(self):
        device = SimulatedPaperBarrierDevice(
            device_id=self.device_id,
            device_key=self.device_key,
            trusted_executors={self.executor.kid},
        )
        command = DeviceCommandIssuer(self.executor).issue(
            self.claims, self.request, device.challenge()
        )
        return device, command

    def test_fragmented_command_executes_only_after_final_lf(self) -> None:
        device, command = self.device_and_command()
        frame = encode_frame(command)
        decoder = NDJSONStreamDecoder()
        self.assertEqual(decoder.feed(frame[:-1]), [])
        self.assertEqual(device.actuator_count, 0)
        objects = decoder.feed(frame[-1:])
        self.assertEqual(len(objects), 1)
        device.execute(objects[0])
        self.assertEqual(device.actuator_count, 1)
        decoder.close()

    def test_disconnect_with_partial_command_remains_locked(self) -> None:
        device, command = self.device_and_command()
        decoder = NDJSONStreamDecoder()
        self.assertEqual(decoder.feed(encode_frame(command)[:-1]), [])
        with self.assertRaisesRegex(PermissionError, "truncated"):
            decoder.close()
        self.assertTrue(decoder.faulted)
        self.assertEqual(device.actuator_count, 0)
        with self.assertRaises(PermissionError):
            decoder.feed(b"{}\n")

    def test_duplicate_keys_nonfinite_float_bom_and_crlf_are_rejected(self) -> None:
        invalid_frames = (
            b'{"a":1,"a":2}\n',
            b'{"a":NaN}\n',
            b'{"a":1.5}\n',
            b'\xef\xbb\xbf{}\n',
            b'{}\r\n',
            b'[]\n',
        )
        for frame in invalid_frames:
            with self.subTest(frame=frame):
                with self.assertRaises(PermissionError):
                    decode_frame(frame)
        with self.assertRaises(ValueError):
            encode_frame({"a": 1.5})

    def test_oversized_or_unterminated_frame_faults_connection(self) -> None:
        with self.assertRaises(ValueError):
            encode_frame({"value": "x" * MAX_FRAME_BYTES})
        decoder = NDJSONStreamDecoder()
        with self.assertRaisesRegex(PermissionError, "byte limit"):
            decoder.feed(b"{" + b"x" * (MAX_FRAME_BYTES - 1))
        self.assertTrue(decoder.faulted)

    def test_invalid_frame_faults_connection_without_recovery(self) -> None:
        decoder = NDJSONStreamDecoder()
        with self.assertRaisesRegex(PermissionError, "faulted the connection"):
            decoder.feed(b'{"a":1,"a":2}\n')
        with self.assertRaises(PermissionError):
            decoder.feed(b"{}\n")


if __name__ == "__main__":
    unittest.main()
