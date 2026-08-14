# ROS 2 / SROS2 Reference Bridge

> Status: v0.3 draft · non-normative

`kinegrant.bridges.ros2` provides two reference pieces for ROS 2 integration
without requiring a ROS 2 runtime:

- `Ros2GoalGate`: an action-goal shaped view over `ActionGate`
  (`accept_goal` / `try_accept_goal`); consumption, replay protection, and
  trust checks are unchanged.
- `Sros2PolicyMapping`: renders KineGrant rules as a deterministic
  machine-readable SROS2-style mapping (`to_dict()`) and a minimal XML policy
  document (`to_xml()`), with `kg/<action>/goal` topic patterns.

Both are **reference mappings, not certifications**. SROS2 conformance and
production DDS security policy generation require deployment-specific
validation against the actual ROS 2 distribution.

## Matter / OPC UA / ROS 2 bridge demo

`kinegrant-bridge-demo` drives Matter, OPC UA, and ROS 2-style adapters through
one shared policy and gate, and verifies adapter fidelity (transport context,
target shapes) plus a wrong-purpose denial. See `spec/ROBOT-DEMO.md` for the
fault-injection two-stack demo.
