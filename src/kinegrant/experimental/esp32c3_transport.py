from __future__ import annotations

import json
from typing import Any, Mapping

from ..canonical import canonical_json

MAX_FRAME_BYTES = 8192


class _DuplicateKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _reject_float(value: str) -> None:
    raise ValueError(f"floating-point JSON number is not allowed: {value}")


def encode_frame(value: Mapping[str, Any], *, max_bytes: int = MAX_FRAME_BYTES) -> bytes:
    """Encode one bounded UTF-8 JSON object terminated by exactly one LF."""

    if not isinstance(value, Mapping):
        raise TypeError("serial frames must contain a JSON object")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 2:
        raise ValueError("max_bytes must be an integer of at least two")
    frame = canonical_json(dict(value)) + b"\n"
    if len(frame) > max_bytes:
        raise ValueError("serial frame exceeds the configured byte limit")
    try:
        decode_frame(frame, max_bytes=max_bytes)
    except PermissionError as exc:
        raise ValueError("value is not valid for the strict serial profile") from exc
    return frame


def decode_frame(frame: bytes, *, max_bytes: int = MAX_FRAME_BYTES) -> dict[str, Any]:
    """Decode one strict NDJSON object without applying authorization semantics."""

    if not isinstance(frame, bytes):
        raise TypeError("serial frame must be bytes")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 2:
        raise ValueError("max_bytes must be an integer of at least two")
    if not frame or len(frame) > max_bytes:
        raise PermissionError("serial frame is empty or exceeds the byte limit")
    if not frame.endswith(b"\n") or frame.count(b"\n") != 1:
        raise PermissionError("serial frame must end with exactly one LF")
    if b"\r" in frame or b"\x00" in frame or frame.startswith(b"\xef\xbb\xbf"):
        raise PermissionError("serial frame contains a forbidden byte sequence")
    try:
        text = frame[:-1].decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise PermissionError("serial frame is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise PermissionError("serial frame root must be a JSON object")
    return value


class NDJSONStreamDecoder:
    """Incremental fail-closed decoder for a single serial connection."""

    def __init__(self, *, max_frame_bytes: int = MAX_FRAME_BYTES) -> None:
        if (
            not isinstance(max_frame_bytes, int)
            or isinstance(max_frame_bytes, bool)
            or max_frame_bytes < 2
        ):
            raise ValueError("max_frame_bytes must be an integer of at least two")
        self.max_frame_bytes = max_frame_bytes
        self._buffer = bytearray()
        self._closed = False
        self._faulted = False

    @property
    def faulted(self) -> bool:
        return self._faulted

    def _fault(self, message: str, cause: Exception | None = None) -> None:
        self._buffer.clear()
        self._faulted = True
        if cause is None:
            raise PermissionError(message)
        raise PermissionError(message) from cause

    def feed(self, chunk: bytes) -> list[dict[str, Any]]:
        if self._closed or self._faulted:
            raise PermissionError("serial decoder is closed or faulted")
        if not isinstance(chunk, bytes):
            raise TypeError("serial data must be bytes")
        if not chunk:
            return []
        self._buffer.extend(chunk)
        decoded: list[dict[str, Any]] = []
        while True:
            try:
                newline = self._buffer.index(0x0A)
            except ValueError:
                if len(self._buffer) >= self.max_frame_bytes:
                    self._fault("unterminated serial frame reached the byte limit")
                return decoded
            frame = bytes(self._buffer[: newline + 1])
            del self._buffer[: newline + 1]
            try:
                decoded.append(decode_frame(frame, max_bytes=self.max_frame_bytes))
            except (TypeError, ValueError, PermissionError) as exc:
                self._fault("invalid serial frame faulted the connection", exc)
            if len(self._buffer) >= self.max_frame_bytes:
                self._fault("unterminated serial frame reached the byte limit")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._buffer:
            self._buffer.clear()
            self._faulted = True
            raise PermissionError("serial connection closed with a truncated frame")
