# Pilot Partnership Framework (no-fee technical validation)

> Companion to Discussion #205. Status: open for expressions of interest.

## What we are looking for

One or two pilot partners with a test robot or smart device (door, arm,
camera, access control) to validate action-level authorization end to end:
policy decision → short-lived capability → local gate → signed receipt.

## Principles

- **No fee, no lock-in, no production data.** The pilot uses test devices and
  synthetic data only.
- **We provide** the reference implementation, the browser verifier, and
  integration help.
- **You get** an auditable "who allowed this action, once, with a signed
  receipt" layer, plus public credit as a pilot partner (with your consent).

## Pilot scope

1. Define one physical action on a test device (e.g., open a door, move an
   arm within a limit, record from a camera prop).
2. Integrate the action gate before the actuator call (Python reference or
   adapter).
3. Run the Machine Permission Test on the same policy, then run the pilot
   scenario and capture a signed receipt.
4. Publish (with your consent) an auditable trace: policy → capability →
   gate → receipt, without production data.

## Boundaries

- No safety certification, no production-readiness claim, no standards
  recognition, no legal-entity relationship, no financial arrangement.
- The pilot is a software validation in a test environment; it does not move
  production machinery.
- Native safety systems remain authoritative and may veto any action.

## How to express interest

Reply to Discussion #205 or open an issue describing:

- the device and the one action you want to validate;
- the environment (simulator, lab, test rig);
- any constraints (offline, language/runtime, timeline).

## Review process

1. Maintainer triages the expression of interest within 7 days.
2. A short call or async exchange to confirm scope and environment.
3. Integration checklist is shared; pilot runs; results recorded publicly.