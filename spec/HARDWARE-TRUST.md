# Hardware Trust Groundwork (v0.4)

> Status: v0.4 draft

Software-only trust is not enough for an actuator boundary. v0.4 builds the
protocol pieces that hardware backends plug into. The reference implementation
provides three testable foundations:

## TrustedClock

`TrustedClock` wraps a time source and rejects time that moves backwards or
jumps forward beyond a configured bound. The reference source is the platform
clock; deployments replace it with a secure time source (secure element,
attested network time, or a trusted edge gateway).

## Sensor-evidence commitments

`SensorReading` + `build_sensor_commitment` record what a sensor attested:
reading kind, hash of the raw value, source, confidence (0-1), and observation
time. Commitments can be signed by the sensor key (Ed25519 or ML-DSA-65) and
are bound into KGP receipts via `evidence_hash` (`evidence_hash_for_commitment`).
They prove attestation, not physical truth.

## Receipt checkpoints

`build_receipt_checkpoint` lets a notary sign a digest of a receipt chain
without exposing the receipts. `verify_receipt_checkpoint` checks the
signature, trust anchor, and content-addressed id, and returns the chain
digest for external comparison.

## Signing backends

`SigningBackend` is the narrow interface a secure element exposes: sign bytes
and reveal the public key id. `BackedKeyPair` adapts any backend to the
KineGrant envelope format, so capabilities and attestations can be signed by a
hardware key without changing the wire format. Private key material never
crosses the interface; the software backends are for tests only.

## Device attestation

`build_device_attestation` binds a device id to its firmware digest, a
persistent boot counter, and an ordered measured-boot chain, signed by the
device key. `verify_device_attestation` checks the signature, trust anchor,
field constraints, and content-addressed id. Attestations are claims about
software state; secure-boot enforcement is deployment hardware work.

Hardware-specific pieces (secure-element key storage, measured boot, signed
gate firmware) remain deployment work and are intentionally not simulated as
software claims of hardware security.

## Browser evidence verification

The browser verifier can re-verify
`kinegrant:ESP32C3PaperBarrierProofEvidence` locally
(`verifyEsp32c3Evidence`): schema fields, HWP-001..011 acceptance profiles,
NOT_RUN/PASS/FAIL consistency, trust-check flags, and physical-mode artifact,
role, and digest requirements; file-byte verification of artifacts remains in
the Python verifier with `--artifact-root`.
It also re-verifies `kinegrant:SensorEvidenceCommitment` and
`kinegrant:ReceiptCheckpoint` locally (`verifySensorCommitment` /
`sensorEvidenceHash` / `verifyReceiptCheckpoint`): reading structure and
digests, content-addressed ids, optional signatures, and the receipt
evidence-hash binding.
`kinegrant:DeviceAttestation` is re-verified in the browser as well
(`verifyDeviceAttestation`): device binding, firmware digest, boot counter,
measured-boot stage digests, and content-addressed attestation id.
