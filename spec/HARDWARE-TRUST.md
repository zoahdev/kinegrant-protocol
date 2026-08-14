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

Hardware-specific pieces (secure-element key storage, measured boot, signed
gate firmware) remain deployment work and are intentionally not simulated as
software claims of hardware security.
