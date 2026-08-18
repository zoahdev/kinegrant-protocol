# Fleet-policy example

A walkthrough for a fleet operator: publish one signed policy bundle, distribute
it to two gates, evaluate allowed and denied actions, verify the distribution
report, then revoke the policy and confirm the previously allowed action is
denied.

## Run

```bash
python examples/fleet-policy/fleet_policy.py
```

## What it demonstrates

- `PolicyAuthority.publish` — one signed, versioned policy bundle.
- `PolicyDistributor.distribute` — apply the bundle to many `PolicyRegistry`
  gates idempotently, with a machine-readable fleet report.
- `verify_policy_distribution_report` — re-validate the fleet report against
  the bundle.
- `PolicyRegistry.revoke` — roll back the policy; default-deny then rejects the
  action that was previously allowed.

This is a software simulation; it does not move a real actuator.