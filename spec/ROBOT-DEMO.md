# Simulated Two-Stack Robot Demonstration

> Status: v0.3 draft

`kinegrant-robot-demo` runs two transport-shaped robot stacks -- a ROS 2-style
action client and a Matter-style command client -- against the **same**
external KineGrant policy, then injects faults:

- replay of an already-consumed capability;
- a capability signed by an untrusted issuer;
- a prompt-injection style request for an unlisted action;
- a physical-limit violation (force above the policy ceiling);
- a forbidden combination (record + open observed, then train requested).

Every attempt is recorded as a machine-readable outcome with expected vs.
observed behavior, and the report ends with `PASS` only when all eight
scenarios behave correctly. Actuator calls are counted per stack, so a denied
scenario must never move an actuator.

```bash
kinegrant-robot-demo
```

This is a software simulation of the v0.3 exit criterion ("two different robot
stacks obey the same external policy"). It does not move a real actuator and
does not prove functional safety.
