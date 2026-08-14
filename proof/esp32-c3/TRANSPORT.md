# Bounded serial transport profile

Status: host serial adapter implemented and software-tested; firmware and
physical validation are pending.

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

## Real host adapter

`kinegrant.experimental.esp32c3_serial` provides a lazy-loaded pyserial adapter
and `PaperBarrierSerialClient`. The client accepts only an `ActionGate`-produced
`VerifiedCapability`, reads one strict challenge, writes one complete signed
command, and accepts only a trusted acknowledgement bound to the exact device,
command, and capability. Timeouts, partial writes, surplus frames, malformed
challenges, and untrusted acknowledgements fail closed.

Install the optional dependency only on a hardware host:

```bash
python -m pip install -e '.[test,hardware]'
```

The preflight command captures one challenge and intentionally sends no actuator
command. It cannot produce `PHYSICAL_PASS`:

```bash
python proof/esp32-c3/hil_preflight.py \
  --port COM7 \
  --output evidence/preflight.json \
  --confirm-low-risk-paper-barrier
```
