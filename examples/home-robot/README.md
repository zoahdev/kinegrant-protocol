# Home Robot Deployment Example

Scenario: a delivery robot asks to open one door for a delivery. The space
policy allows the action only for the delivery purpose, in a defined zone,
with a bounded force, and the action must produce a signed receipt.

Run:

```bash
python examples/home-robot/home_robot.py
```

The script prints the full trace: request -> decision -> capability ->
gate verification -> actuator call -> signed receipt, and exits nonzero if any
invariant fails.
