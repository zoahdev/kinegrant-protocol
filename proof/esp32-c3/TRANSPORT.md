# Bounded serial transport profile

Status: software framing model only; no serial port or firmware is connected.

The paper-barrier proof uses newline-delimited JSON solely as a transport for the
experimental challenge, command, and acknowledgement objects. Signatures and
authorization remain in those objects; serial framing grants no permission.

## Frame rules

- UTF-8 JSON object followed by one LF byte (`0x0A`);
- maximum complete frame size: 8192 bytes including LF;
- no UTF-8 BOM, NUL, raw carriage return, embedded LF, duplicate object keys,
  `NaN`, `Infinity`, or floating-point numbers;
- one complete object at the JSON root; arrays and scalar roots are rejected;
- fragmented reads are buffered without executing anything;
- an invalid, overlong, or truncated frame faults that connection;
- a faulted or closed decoder cannot be reused—open a new connection and obtain
  a new device challenge;
- parsing a command never invokes the actuator. The decoded object must still
  pass signature, exact-field, trust, challenge, expiry, sequence, replay, and
  parameter checks at the device-local gate.

The limit is a proof-profile bound, not a KGP-001 protocol limit. Firmware must
allocate a fixed buffer no larger than this value and reject overflow before
JSON parsing. It must not silently truncate or accept the first object from an
ambiguous frame.

## Host reference

```python
from kinegrant.experimental.esp32c3_transport import (
    NDJSONStreamDecoder,
    encode_frame,
)

wire_bytes = encode_frame(signed_command)
decoder = NDJSONStreamDecoder()
objects = decoder.feed(wire_bytes[:20])  # []: no complete frame, no action
objects += decoder.feed(wire_bytes[20:]) # one object for device verification
decoder.close()
```

`NDJSONStreamDecoder` models a single connection. A disconnect with buffered
bytes raises `PermissionError` and discards the partial object. Tests assert that
the simulated actuator count remains zero until the final LF arrives and the
fully decoded command passes the device gate.
