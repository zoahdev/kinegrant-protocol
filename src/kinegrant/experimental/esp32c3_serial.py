from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from ..crypto import verify_envelope
from ..gate import VerifiedCapability
from ..models import ActionRequest
from .esp32c3 import DeviceChallenge, DeviceCommandIssuer, verify_device_ack
from .esp32c3_transport import MAX_FRAME_BYTES, NDJSONStreamDecoder, encode_frame


class SerialTransport(Protocol):
    """Small transport boundary used by the real adapter and deterministic tests."""

    def read(self, size: int) -> bytes: ...

    def write(self, data: bytes) -> int: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class PySerialTransport:
    """Bounded pyserial adapter. Importing KineGrant does not require pyserial."""

    def __init__(
        self,
        port: str,
        *,
        baudrate: int = 115_200,
        read_timeout: float = 0.25,
        write_timeout: float = 1.0,
    ) -> None:
        if not isinstance(port, str) or not port.strip():
            raise ValueError("serial port must be a non-empty string")
        if not isinstance(baudrate, int) or isinstance(baudrate, bool) or baudrate < 1:
            raise ValueError("baudrate must be a positive integer")
        for name, value in (("read_timeout", read_timeout), ("write_timeout", write_timeout)):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be positive")
        try:
            import serial
        except ImportError as exc:  # pragma: no cover - exercised without hardware extra
            raise RuntimeError(
                "pyserial is required for a real port; install kinegrant-protocol[hardware]"
            ) from exc
        self._serial = serial.Serial(
            port=port,
            baudrate=baudrate,
            timeout=float(read_timeout),
            write_timeout=float(write_timeout),
        )
        self._serial.reset_input_buffer()
        self._serial.reset_output_buffer()

    def read(self, size: int) -> bytes:
        return bytes(self._serial.read(size))

    def write(self, data: bytes) -> int:
        return int(self._serial.write(data))

    def flush(self) -> None:
        self._serial.flush()

    def close(self) -> None:
        self._serial.close()

    def __enter__(self) -> "PySerialTransport":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def read_serial_object(
    transport: SerialTransport,
    *,
    timeout_seconds: float,
    max_frame_bytes: int = MAX_FRAME_BYTES,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Read exactly one bounded frame; timeout, truncation, or surplus data fail closed."""

    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
        raise ValueError("timeout_seconds must be numeric")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    decoder = NDJSONStreamDecoder(max_frame_bytes=max_frame_bytes)
    deadline = monotonic() + float(timeout_seconds)
    while monotonic() < deadline:
        chunk = transport.read(max_frame_bytes)
        if not isinstance(chunk, bytes):
            raise TypeError("serial transport must return bytes")
        if not chunk:
            continue
        objects = decoder.feed(chunk)
        if len(objects) > 1:
            raise PermissionError("serial peer sent surplus frames")
        if objects:
            decoder.close()  # rejects a complete frame followed by a partial frame
            return objects[0]
    try:
        decoder.close()
    except PermissionError as exc:
        raise TimeoutError("serial frame timed out after partial input") from exc
    raise TimeoutError("serial frame timed out")


def read_device_challenge(
    transport: SerialTransport,
    *,
    timeout_seconds: float = 3.0,
    monotonic: Callable[[], float] = time.monotonic,
) -> DeviceChallenge:
    try:
        value = read_serial_object(
            transport,
            timeout_seconds=timeout_seconds,
            monotonic=monotonic,
        )
        return DeviceChallenge.from_dict(value)
    except (TypeError, ValueError) as exc:
        raise PermissionError("device supplied an invalid challenge") from exc


@dataclass(frozen=True)
class SerialExchange:
    challenge: Mapping[str, Any]
    command: Mapping[str, Any]
    acknowledgement: Mapping[str, Any]
    command_frame: bytes


class PaperBarrierSerialClient:
    """Execute one already gate-consumed capability through the serial device gate."""

    def __init__(
        self,
        transport: SerialTransport,
        issuer: DeviceCommandIssuer,
        *,
        trusted_devices: set[str],
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not trusted_devices:
            raise ValueError("at least one trusted device key is required")
        self.transport = transport
        self.issuer = issuer
        self.trusted_devices = set(trusted_devices)
        self.monotonic = monotonic

    def execute_once(
        self,
        capability: VerifiedCapability,
        request: ActionRequest,
        *,
        challenge_timeout: float = 3.0,
        acknowledgement_timeout: float = 3.0,
    ) -> SerialExchange:
        challenge = read_device_challenge(
            self.transport,
            timeout_seconds=challenge_timeout,
            monotonic=self.monotonic,
        )
        command = self.issuer.issue(capability, request, challenge)
        command_frame = encode_frame(command)
        written = self.transport.write(command_frame)
        if written != len(command_frame):
            raise ConnectionError("serial transport did not write the complete command")
        self.transport.flush()
        acknowledgement = read_serial_object(
            self.transport,
            timeout_seconds=acknowledgement_timeout,
            monotonic=self.monotonic,
        )
        command_payload = verify_envelope(command)
        if not verify_device_ack(
            acknowledgement,
            trusted_devices=self.trusted_devices,
            expected_command_ids={command_payload["command_id"]},
            expected_device_ids={challenge.device_id},
            expected_capability_ids={command_payload["capability_id"]},
        ):
            raise PermissionError("device acknowledgement failed trust or binding verification")
        return SerialExchange(
            challenge=challenge.to_dict(),
            command=dict(command),
            acknowledgement=acknowledgement,
            command_frame=command_frame,
        )
