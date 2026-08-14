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

## Cross-system ROS 2 + MCP demo

`kinegrant-ros2-demo` (non-normative, v0.6 draft) shows one shared KineGrant
policy governing two different execution stacks at the same time:

- a ROS 2-style stack whose action goals flow through `Ros2GoalGate`; and
- an MCP-style agent stack whose tool calls flow through
  `kinegrant.adapters.mcp.mcp_tool_request` (Model Context Protocol shaped,
  without requiring an MCP runtime).

Both stacks share the same `PolicyEngine`, `CapabilityIssuer`, `ActionGate`,
signed `ReceiptLog`, `ActionJournal`, and `SequencePolicy`, so a single
deployment policy answers "may this happen, on this stack, given what already
happened on the other stack". The demo injects and rejects:

- replay of an already consumed ROS 2 goal capability;
- a capability from an untrusted issuer on the MCP stack;
- a wrong-purpose request on the ROS 2 stack;
- a physical-limit violation (force above the policy ceiling) on the MCP
  stack; and
- a forbidden combination (`open` observed, then `enter` requested) across
  stacks.

Allowed actions produce signed receipts that verify as one chain; the journal
drives the sequence policy across both transports. The demo exits `0` with a
machine-readable `Ros2McpDemoReport` only when every expected outcome matches.
