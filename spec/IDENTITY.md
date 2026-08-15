# KineGrant Identifier Grammar

> Status: v0.2 draft

Agents, targets, and policies use canonical URNs so different implementations
refer to the same entity with the same string:

```text
urn:kinegrant:<kind>:<namespace>:<local-id>
```

`kind` is one of:

- `agent`: a robot, device, or software principal;
- `target`: a physical or cyber-physical object a request acts on;
- `policy`: a policy snapshot or rule collection.

Grammar:

- `namespace`: 1-63 chars, lowercase letters, digits, `-`, `.`;
- `local-id`: 1-128 chars, lowercase letters, digits, `-`, `_`, `.`, `:`, `#`.

Examples:

- `urn:kinegrant:agent:zoah:delivery-robot-07`
- `urn:kinegrant:target:zoah:door-7`
- `urn:kinegrant:policy:zoah:delivery-door#permission-0`

The reference implementation exposes `agent_id`, `target_id`, `policy_id`,
`parse_identifier`, and kind predicates in `src/kinegrant/identity.py`.
Random opaque ids are generated with a cryptographic RNG for private
namespaces; public namespaces should use their own registration policy.
The browser verifier and its Node CLI expose the same grammar as
`validateIdentitySyntax` (fail-closed on malformed identifiers), cross-tested
against the Python builders.

## Relationship to other schemes

RCAN uses `rcan://registry/manufacturer/model/version/serial` for robot
identity. KineGrant deliberately keeps identity URNs minimal and treats
manufacturer/model/version as attributes in a discovery or attestation layer,
not as part of the authorization identifier.
