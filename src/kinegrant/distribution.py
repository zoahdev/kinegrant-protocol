"""Revocation distribution to multiple gates (v1.2 draft).

``RevocationDistributor`` applies one verified, signed revocation bundle to
many gates in a fleet. Distribution is fail-closed: the bundle must verify
under the caller-supplied revocation authorities (and an optional expected
previous-bundle digest) before any gate is touched, and application is
idempotent per capability id. The report records, per gate, how many
revocations were added and how many were already present.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .crypto import verify_envelope
from .revocation import RevocationList, verify_revocation_bundle


@dataclass(frozen=True)
class GateRevocationAck:
    gate_id: str
    bundle_id: str
    applied: bool
    added_count: int
    already_present: int
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "bundle_id": self.bundle_id,
            "applied": self.applied,
            "added_count": self.added_count,
            "already_present": self.already_present,
            "detail": self.detail,
        }


class RevocationDistributor:
    """Verify one revocation bundle and apply it to many gate revocation lists."""

    def __init__(
        self,
        *,
        trusted_authorities: set[str] | None = None,
        expected_previous_digest: str | None = None,
    ) -> None:
        self.trusted_authorities = set(trusted_authorities or ())
        self.expected_previous_digest = expected_previous_digest

    def distribute(
        self,
        bundle: Mapping[str, Any],
        gates: Mapping[str, RevocationList],
    ) -> dict[str, Any]:
        """Apply a verified bundle to every gate; return the fleet report."""
        revocations = verify_revocation_bundle(
            bundle,
            trusted_authorities=self.trusted_authorities or None,
            expected_previous_digest=self.expected_previous_digest,
        )
        payload = verify_envelope(bundle)
        bundle_id = payload.get("bundle_id")
        version = payload.get("version")
        acks: list[GateRevocationAck] = []
        for gate_id in sorted(gates):
            gate = gates[gate_id]
            added = 0
            already = 0
            for entry in revocations.entries:
                if gate.is_revoked(entry.capability_id):
                    already += 1
                else:
                    gate.revoke(entry.capability_id, reason=entry.reason, at=entry.at)
                    added += 1
            acks.append(
                GateRevocationAck(
                    gate_id=gate_id,
                    bundle_id=bundle_id,
                    applied=True,
                    added_count=added,
                    already_present=already,
                )
            )
        total_added = sum(ack.added_count for ack in acks)
        return {
            "type": "kinegrant:RevocationDistributionReport",
            "schema_version": "0.1",
            "bundle_id": bundle_id,
            "bundle_version": version,
            "overall_result": "PASS",
            "summary": {
                "gates": len(acks),
                "added_total": total_added,
                "already_present_total": sum(
                    ack.already_present for ack in acks
                ),
            },
            "acks": [ack.to_dict() for ack in acks],
        }


def _self_test() -> int:
    from .crypto import Ed25519KeyPair
    from .revocation import RevocationList, build_revocation_bundle, sign_revocation_bundle

    authority = Ed25519KeyPair.generate()
    rl = RevocationList()
    rl.revoke("kinegrant:cap:" + "a" * 64, reason="maintenance")
    bundle = sign_revocation_bundle(
        build_revocation_bundle(rl, issuer=authority.kid),
        authority,
    )
    gates = {
        "gate-1": RevocationList(),
        "gate-2": RevocationList(),
    }
    report = RevocationDistributor(
        trusted_authorities={authority.kid}
    ).distribute(bundle, gates)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_result"] == "PASS" else 1


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if "--self-test" in args:
        return _self_test()
    if len(args) < 3:
        print(
            "usage: kinegrant-revoke-distribute <bundle.json> <gates.json> "
            "<authorities.json>",
            file=sys.stderr,
        )
        return 2
    bundle_path, gates_path, authorities_path = args[0], args[1], args[2]
    bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    gates_raw = json.loads(Path(gates_path).read_text(encoding="utf-8"))
    authorities = json.loads(Path(authorities_path).read_text(encoding="utf-8"))
    gates = {
        gate_id: RevocationList.from_dict(value)
        for gate_id, value in gates_raw.items()
    }
    report = RevocationDistributor(
        trusted_authorities=set(authorities)
    ).distribute(bundle, gates)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0
