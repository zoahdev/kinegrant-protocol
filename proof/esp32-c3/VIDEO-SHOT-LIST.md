# Physical proof recording checklist

Status: recording plan only. It is not evidence that a physical run occurred.

Use one continuous wide shot where practical. Keep the low-risk paper barrier,
ESP32-C3, servo, separate 5 V supply, host screen, and a visible run identifier
in frame. Do not connect a lock, vehicle, drone, alarm, industrial machine,
dangerous tool, or high-power actuator.

## Before the run

- Show the exact source commit, firmware digest, pinout digest, device key ID,
  UTC clock, run ID, and empty evidence directory.
- Show the wiring and measured servo supply voltage without exposing private keys.
- Show that the servo can move only the lightweight paper barrier and has safe
  mechanical travel limits.
- Record a clean boot, persistent boot counter, fresh challenge, and zero
  actuator count.

## Required case coverage

Record labels and machine-readable timestamps for HWP-001 through HWP-011.
Keep serial and host logs running throughout. For repeated cases, show the first,
last, and a continuous count; retain every signed acknowledgement and receipt.

1. 20 no-grant attempts: zero movement.
2. 20 valid grants: exactly one movement per grant.
3. 20 replay attempts: every replay denied.
4. Changed device, action, and position: all denied.
5. Untrusted issuer: denied.
6. Just-before and exactly-at/after 10 seconds: boundary result visible.
7. 64 concurrent deliveries: one actuator call and 63 denials.
8. Restart, then replay the prior command: denied.
9. Disconnect and malformed frame: locked with zero movement.
10. Verify allow/deny receipts and device acknowledgements independently; show
    tampering and untrusted-executor rejection.
11. 100 continuous cycles: record reset counter, temperature/power observation,
    movement count, and final locked state.

## Closeout

- Show final actuator count, boot counter, zero abnormal resets/overheat events,
  and the physical fixture returned to its safe position.
- Generate SHA-256 digests without editing the original media or logs.
- Put the video, firmware, pinout, wiring photo, serial log, host log, receipts,
  and device acknowledgements in the evidence manifest.
- Run the independent verifier with `--artifact-root`; retain failures rather
  than re-labelling or deleting them.
