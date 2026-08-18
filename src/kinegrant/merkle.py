"""Merkle selective disclosure (v0.5).

Upgrades the digest-only redaction draft to a Merkle-tree inclusion proof: a
prover reveals chosen fields plus per-field proofs against a root; the
verifier needs only the root, the field name, the value, and the proof -- not
the full document. This is an accumulator-style construction, a stepping stone
toward zero-knowledge disclosure.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .canonical import digest


def _leaf(field: str, value: Any) -> str:
    return digest({"field": field, "value": value})


def _node(left: str, right: str) -> str:
    return digest({"left": left, "right": right})


def _pad_to_power_of_two(size: int) -> int:
    power = 1
    while power < size:
        power *= 2
    return power


def _build_tree(leaves: list[str]) -> tuple[str, list[list[str]]]:
    size = _pad_to_power_of_two(len(leaves))
    layers = [leaves + [digest({"pad": True})] * (size - len(leaves))]
    while len(layers[-1]) > 1:
        current = layers[-1]
        layers.append(
            [_node(current[index], current[index + 1]) for index in range(0, len(current), 2)]
        )
    return layers[-1][0], layers


def merkle_proofs(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Return per-field values, roots, and proofs for *document*."""
    fields = sorted(document)
    leaves = [_leaf(field, document[field]) for field in fields]
    root, layers = _build_tree(leaves)
    proofs: dict[str, dict[str, Any]] = {}
    for index, field in enumerate(fields):
        path = []
        position = index
        for layer_index in range(len(layers) - 1):
            layer = layers[layer_index]
            sibling = position ^ 1
            if sibling < len(layer):
                path.append({"hash": layer[sibling], "left": sibling < position})
            else:
                path.append({"hash": digest({"pad": True}), "left": sibling < position})
            position //= 2
        proofs[field] = {"value": document[field], "root": root, "proof": path}
    return proofs


def verify_field(
    root: str,
    field: str,
    value: Any,
    proof: Iterable[Mapping[str, Any]],
) -> bool:
    """Verify one Merkle inclusion proof against *root*."""
    current = _leaf(field, value)
    for step in proof:
        sibling = step.get("hash")
        if not isinstance(sibling, str):
            return False
        if step.get("left"):
            current = _node(sibling, current)
        else:
            current = _node(current, sibling)
    return current == root


def merkle_redact(
    document: Mapping[str, Any],
    visible: Iterable[str],
) -> dict[str, Any]:
    """Build a selective-disclosure envelope with per-field Merkle proofs."""
    proofs = merkle_proofs(document)
    revealed = []
    root = None
    for field in visible:
        if field not in proofs:
            raise ValueError(f"unknown field {field!r}")
        entry = proofs[field]
        root = entry["root"]
        revealed.append(
            {
                "field": field,
                "value": entry["value"],
                "proof": entry["proof"],
            }
        )
    if root is None:
        raise ValueError("at least one visible field is required")
    return {
        "type": "kinegrant:MerkleRedaction",
        "schema_version": "0.1",
        "root": root,
        "visible": revealed,
    }


def verify_merkle_redaction(redaction: Mapping[str, Any]) -> bool:
    """Verify every revealed field in a Merkle redaction against its root."""
    if redaction.get("type") != "kinegrant:MerkleRedaction":
        return False
    if redaction.get("schema_version") != "0.1":
        return False
    root = redaction.get("root")
    visible = redaction.get("visible")
    if not isinstance(root, str) or not isinstance(visible, list) or not visible:
        return False
    return all(
        isinstance(entry, Mapping)
        and isinstance(entry.get("field"), str)
        and verify_field(root, entry["field"], entry.get("value"), entry.get("proof", []))
        for entry in visible
    )
