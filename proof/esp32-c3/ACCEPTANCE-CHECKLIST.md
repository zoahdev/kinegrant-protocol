# ESP32-C3 Physical Proof — Acceptance Checklist

> Companion to issue #7. Status: **plan only; no physical run has occurred**.
> Use this checklist only after reading [HARDWARE.md](HARDWARE.md) and
> [TRANSPORT.md](TRANSPORT.md). Do not connect a lock, vehicle, drone, alarm,
> industrial machine, dangerous tool, or high-power actuator.

## Phase 0 — Procurement (before ordering)

- [ ] Total new-purchase cart within CNY 100–170 (hard ceiling 200 incl. shipping).
- [ ] ESP32-C3 SuperMini with visible USB connector and pin labels.
- [ ] One SG90-class 4.8–6 V servo from a traceable listing; voltage/connector order confirmed.
- [ ] SSD1306 OLED (I2C, 3.3 V), breadboard, jumpers, button, decoupling caps per HARDWARE.md.
- [ ] Separate regulated 5 V servo supply (≥1 A); no battery pack, relay, solenoid, or mains supply.
- [ ] Paper fixture only; no rigid latch.

## Phase 1 — Assembly and power safety

- [ ] Servo powered only from the separate 5 V rail, never from ESP32-C3 3.3 V.
- [ ] No 5 V on any ESP32-C3 GPIO (3.6 V absolute max).
- [ ] OLED at 3.3 V; grounds joined; caps placed per HARDWARE.md.
- [ ] Wiring inspected before power; power removed before rewiring.

## Phase 2 — Firmware and host tooling

- [ ] Firmware built from the pinned commit (see firmware README).
- [ ] `proof/verify_esp32c3_evidence.py` dry run passes with the template (`--allow-not-run`).
- [ ] Host serial adapter (`PySerialTransport`) software tests pass.

## Phase 3 — Preflight (no actuation)

- [ ] `hil_preflight.py --port <port> --confirm-low-risk-paper-barrier` captures one device challenge without moving the actuator.
- [ ] Challenge JSON validates against `schemas/device-challenge.schema.json`.
- [ ] Boot counter persists across reboot.

## Phase 4 — Authorized run

- [ ] Issue one short-lived capability bound to the exact action; replay attempt rejected.
- [ ] Untrusted issuer / tampered command rejected with zero actuator calls.
- [ ] Device acknowledgement validates against `schemas/device-ack.schema.json`.
- [ ] One continuous wide shot recorded per `VIDEO-SHOT-LIST.md` with commit, firmware digest, key ID, UTC clock, and run ID visible.

## Phase 5 — Evidence and publication

- [ ] Fill `physical-proof-evidence.template.json`; validate against `schemas/physical-proof-evidence.schema.json`.
- [ ] Run `python proof/verify_esp32c3_evidence.py <evidence.json>` — must PASS without `--allow-not-run`.
- [ ] Publish evidence + checksums in the repository and link from issue #7.
- [ ] Update status lines in `README.md` / `HARDWARE.md` from pending to run record, without safety claims.

## Definition of done

A physical run counts as evidence only when: Phase 3 preflight passed, Phase 4
run produced zero unauthorized actuations and one signed acknowledgement,
Phase 5 evidence validates, and the recording matches VIDEO-SHOT-LIST.md.