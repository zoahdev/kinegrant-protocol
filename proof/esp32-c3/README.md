# Low-risk ESP32-C3 permission proof

Status: **software model only; physical validation is pending**.

Read the [hardware and power gate](HARDWARE.md) before buying or connecting any
component.
The [bounded serial transport profile](TRANSPORT.md) defines fail-closed framing
for later firmware and host integration.

This directory defines the non-normative
`kgp-esp32c3-paper-barrier/0.1` experiment for GitHub issue
[#7](https://github.com/zoahdev/kinegrant-protocol/issues/7). It is an
actuator-boundary profile for testing KGP-001 with one ESP32-C3, one SG90-class
micro servo, and a lightweight paper barrier. It is not a new KGP wire version,
a functional-safety control, or evidence that a physical run has occurred.

## Boundary

```text
ActionRequest + Policy
        |
        v
short-lived KGP capability
        |
        v
host ActionGate -- verify and atomically consume
        |
        v
signed device command -- exact target/action/parameters/capability
        |
        v
ESP32-C3 local gate -- live challenge + sequence + persistent replay state
        |
        v
paper-barrier servo attempt + device-signed acknowledgement
        |
        v
KGP receipt whose evidence hash commits to the acknowledgement/transcript
```

The host cannot issue a device command from raw capability claims. The Python
model requires `VerifiedCapability`, which only `ActionGate.authorize()` returns
after signature, trust, request-binding, time-window, and replay checks pass.
The bridge then atomically consumes that verified capability a second time in a
separate issuance store, so it can produce at most one device command. Use a
`SQLiteReplayStore` for crash-persistent issuance state; the default in-memory
store is only for one-process tests.

## Device command rules

The device accepts only an Ed25519-signed command from an explicitly configured
executor key. The signature covers:

- the experimental profile and exact device identifier;
- the KGP capability ID and ActionRequest digest;
- the allowlisted action `move_paper_barrier`;
- exactly one logical parameter: `position` = `open` or `closed`;
- a persistent boot counter, one live random challenge, and the next sequence;
- a content-derived command ID.

After signature, profile, and allowlist validation, the device atomically takes
the live challenge so concurrent deliveries cannot share it. The challenge
expires at exactly 10 seconds according to the device's monotonic clock. The
device must persist the command consumption and sequence **before** calling the
servo driver. A restart increments the persistent boot counter, invalidating
commands from every previous boot.

The restricted logical parameter prevents a signed request from supplying raw
PWM values outside the fixture's calibrated limits. Servo pulse widths and
travel limits belong in local firmware configuration, not in an agent request.

## Firmware invariants

An ESP-IDF implementation must preserve all of these properties:

1. Start locked: detach or hold the servo at the configured safe position until
   NVS state and the trusted-executor key load successfully.
2. Increment and commit `boot_counter` before publishing the first challenge.
3. Generate at least 128 bits of challenge entropy with a documented valid ESP-IDF
   entropy source; never assume an unseeded RNG is sufficient.
4. Parse bounded newline-delimited JSON into fixed limits and reject duplicate,
   unknown, missing, overlong, non-integer, or non-canonical fields.
5. Verify the Ed25519 envelope and exact field allowlist before touching replay
   state or actuator code.
6. Enforce a 10-second local monotonic challenge deadline; equality is expired.
7. Atomically commit the command ID and sequence in NVS before servo invocation.
8. Permit only the two compiled paper-barrier positions and a locally bounded
   travel interval.
9. Return a device-signed acknowledgement for a succeeded or failed attempt;
   silence, malformed serial input, host disconnect, and storage failure remain
   locked.
10. Never connect this experiment to a lock, vehicle, drone, alarm, industrial
    equipment, dangerous tool, or high-power motor.

The host implementation must also use one shared crash-persistent issuance store
across every process and executor key that can bridge the same capability
namespace. Creating a fresh in-memory `DeviceCommandIssuer` for every request,
or a separate store during key rotation, would discard the one-command bridge
invariant and is not a valid deployment.

Espressif documents both the ESP32-C3 hardware RNG conditions and the NVS API.
The firmware implementation must follow those constraints rather than treating
`esp_random()` as unconditionally strong:

- <https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/random.html>
- <https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/storage/nvs_flash.html>

## Run the software boundary tests

```bash
python -m pip install -e '.[test]'
python -m unittest discover -s tests -p 'test_esp32c3_proof.py' -v
```

The simulator in `kinegrant.experimental.esp32c3` has no serial or GPIO access.
It exercises the trust boundary, exact-expiry behavior, 64-way concurrent
replay, persistent restart rejection, strict parameter allowlist, and signed
acknowledgement verification before firmware is introduced.

## Evidence packet

Start from [`physical-proof-evidence.template.json`](physical-proof-evidence.template.json).
It is deliberately labelled `simulation` + `NOT_RUN`, with null hardware fields
and zero attempts, so publishing the untouched file cannot look like a completed
physical test.

The independent verifier enforces all 11 case IDs and their exact acceptance
counts. `SIMULATION_PASS` can never validate as `PHYSICAL_PASS`. A physical pass
also requires an exact source commit, provisioned device key, firmware and pinout
digests, evidence references from every case, and these byte-verified artifact
roles: firmware, pinout record, wiring photo, serial log, host log, video,
receipts, and device acknowledgements.

Validate the unexecuted template:

```bash
python proof/verify_esp32c3_evidence.py \
  proof/esp32-c3/physical-proof-evidence.template.json \
  --allow-not-run
```

Validate a completed physical packet and every referenced file:

```bash
python proof/verify_esp32c3_evidence.py evidence.json \
  --artifact-root ./evidence-packet
```

Without `--artifact-root`, `PHYSICAL_PASS` is invalid. Relative artifact paths
that escape the evidence directory are rejected. The manifest authenticates
artifact bytes by SHA-256 but is not itself a physical sensor or independent
witness; signed device acknowledgements and KGP receipts remain separate packet
artifacts.

## Explicit limitations

- Compromise of the configured host executor key lets an attacker issue commands
  that the device will trust. The host process and key remain inside the trusted
  computing base for this experiment.
- An ESP32-C3 key stored in ordinary flash is not hardware-backed. Secure boot,
  flash encryption, key provisioning, and extraction resistance are future work.
- NVS wear, brownout behavior, serial framing, firmware signature verification,
  GPIO timing, and servo power integrity are not modeled by the Python simulator.
- A valid device acknowledgement proves control of the configured device key and
  an accepted firmware code path. It does not prove that the paper barrier moved.
- Native mechanical stops, current limiting, stable power, and human supervision
  remain required even for this low-risk fixture.

## Physical acceptance gate

The physical proof is not complete until a public evidence packet records:

- 20 no-grant attempts with zero actuator calls;
- 20 valid single-use grants with exactly one call each;
- 20 replay attempts, all denied;
- rejection of changed device, action, parameter, issuer, and commands at or
  after the 10-second deadline;
- one winner under concurrent delivery and rejection after device restart;
- fail-closed host disconnect and malformed serial input;
- independently verified allow and deny receipts;
- 100 continuous cycles without abnormal reset or overheating.

Record failures as failures. A video or servo movement by itself is not protocol
evidence, and a signed acknowledgement still does not prove physical-world truth.
