# Forbidden Combinations and Sequence Policy

> Status: v0.2 draft

Some unsafe outcomes only exist across multiple actions: "record the space,
then train on that data", "open the enclosure, then enter it", or SINT-style
cross-system invariants such as "robot is moving, deny file-system writes".
KineGrant models these as **forbidden combinations**.

## Model

- `ActionJournal` records executed actions `(action, target, at)`.
- `ForbiddenCombination` is a set of `(action, target)` glob patterns that must
  never all be observed:
  - order-independent;
  - optional `window_seconds` (entries older than the window no longer count);
  - optional `trigger` pattern; without it every new request is denied once the
    combination is complete.
- `SequencePolicy.evaluate(request, journal)` returns a `SequenceVerdict` with
  `allowed`, `reason`, and matched combination ids for auditing.

## Composition with the gate

The sequence policy answers "may this happen given what already happened",
which is a different question from the action gate's "is this capability
valid". A deployment composes them in order:

1. `SequencePolicy.evaluate(request, journal)` fails closed on
   `forbidden_combination`;
2. `ActionGate.authorize(capability, request)` consumes the single-use
   capability;
3. on the terminal receipt, `journal.record(action, target)` appends the
   executed action.

Like every other KineGrant boundary, unknown or unparsable combinations are
rejected rather than guessed.
