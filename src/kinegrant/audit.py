"""Receipt audit query interface (v1.1 draft).

``ReceiptAuditor`` turns a signed receipt chain into an accountable audit
surface: it verifies the chain, filters receipts by capability, agent, target,
action, purpose, result, and time, produces a machine-readable summary, and
can check obligation compliance for a specific capability. Auditing is
fail-closed: by default every query requires a valid chain under the
caller-supplied executor trust set.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from .capability import CapabilityIssuer
from .canonical import canonical_json
from .compliance import ObligationCompliance, ObligationComplianceVerdict
from .crypto import Ed25519KeyPair, verify_envelope
from .gate import ActionGate, InMemoryReplayStore
from .models import ActionRequest, PolicyRule, parse_time
from .policy import PolicyEngine
from .receipt import ReceiptLog, verify_receipt_chain


@dataclass(frozen=True)
class AuditFilter:
    capability_id: str | None = None
    agent: str | None = None
    target: str | None = None
    action: str | None = None
    purpose: str | None = None
    result: str | None = None
    since: datetime | None = None
    until: datetime | None = None


class ReceiptAuditor:
    """Query and summarize a verified KineGrant receipt chain."""

    def __init__(
        self,
        entries: Iterable[Mapping[str, Any]],
        *,
        trusted_executors: set[str] | None = None,
    ) -> None:
        self.entries = tuple(entries)
        self.trusted_executors = set(trusted_executors or ())
        self._chain_valid: bool | None = None
        self._verified: tuple[dict[str, Any], ...] | None = None

    def chain_valid(self) -> bool:
        """Verify the whole chain; False when any link or executor is bad."""
        if self._chain_valid is None:
            self._chain_valid = verify_receipt_chain(
                self.entries,
                trusted_executors=self.trusted_executors or None,
            )
        return self._chain_valid

    def _payloads(self, *, strict: bool) -> tuple[dict[str, Any], ...]:
        if strict and not self.chain_valid():
            raise ValueError(
                "receipt chain is invalid; refusing to audit an unverifiable chain"
            )
        if self._verified is None:
            payloads: list[dict[str, Any]] = []
            for envelope in self.entries:
                try:
                    payloads.append(dict(verify_envelope(envelope)))
                except (TypeError, ValueError):
                    continue
            self._verified = tuple(payloads)
        return self._verified

    def query(
        self,
        *,
        capability_id: str | None = None,
        agent: str | None = None,
        target: str | None = None,
        action: str | None = None,
        purpose: str | None = None,
        result: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        strict: bool = True,
    ) -> tuple[dict[str, Any], ...]:
        """Return verified receipt payloads matching every supplied filter."""
        payloads = self._payloads(strict=strict)
        matched: list[dict[str, Any]] = []
        for payload in payloads:
            if capability_id is not None and payload.get("capability_id") != capability_id:
                continue
            if agent is not None and payload.get("agent") != agent:
                continue
            if target is not None and payload.get("target") != target:
                continue
            if action is not None and payload.get("action") != action:
                continue
            if purpose is not None and payload.get("purpose") != purpose:
                continue
            if result is not None and payload.get("result") != result:
                continue
            try:
                started = parse_time(payload["started_at"])
            except (KeyError, TypeError, ValueError):
                started = None
            if since is not None and (started is None or started < since):
                continue
            if until is not None and (started is None or started > until):
                continue
            matched.append(payload)
        return tuple(matched)

    def summary(self, *, strict: bool = True) -> dict[str, Any]:
        """Machine-readable audit summary over the verified chain."""
        payloads = self._payloads(strict=strict)
        by_result: dict[str, int] = {}
        by_action: dict[str, int] = {}
        timestamps: list[datetime] = []
        for payload in payloads:
            result = payload.get("result")
            if isinstance(result, str):
                by_result[result] = by_result.get(result, 0) + 1
            action = payload.get("action")
            if isinstance(action, str):
                by_action[action] = by_action.get(action, 0) + 1
            try:
                timestamps.append(parse_time(payload["finished_at"]))
            except (KeyError, TypeError, ValueError):
                continue
        return {
            "type": "kinegrant:ReceiptAuditSummary",
            "schema_version": "0.1",
            "chain_valid": self.chain_valid(),
            "total": len(payloads),
            "by_result": dict(sorted(by_result.items())),
            "by_action": dict(sorted(by_action.items())),
            "first_finished_at": min(timestamps).isoformat() if timestamps else None,
            "last_finished_at": max(timestamps).isoformat() if timestamps else None,
        }

    def compliance_for(
        self,
        capability: Mapping[str, Any],
        *,
        trusted_executors: set[str] | None = None,
    ) -> ObligationComplianceVerdict:
        """Check that a capability's obligations are fulfilled by this chain."""
        executors = trusted_executors
        if executors is None:
            executors = self.trusted_executors
        if not executors:
            raise ValueError(
                "trusted_executors are required for obligation compliance"
            )
        return ObligationCompliance().evaluate(
            capability,
            self.entries,
            trusted_executors=executors,
        )

    def export_csv(
        self,
        *,
        capability_id: str | None = None,
        agent: str | None = None,
        target: str | None = None,
        action: str | None = None,
        purpose: str | None = None,
        result: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        strict: bool = True,
    ) -> str:
        """Render matched receipts as CSV for spreadsheets and archives."""
        payloads = self.query(
            capability_id=capability_id,
            agent=agent,
            target=target,
            action=action,
            purpose=purpose,
            result=result,
            since=since,
            until=until,
            strict=strict,
        )
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "receipt_id",
                "capability_id",
                "agent",
                "target",
                "action",
                "purpose",
                "result",
                "started_at",
                "finished_at",
                "evidence_hash",
                "previous_receipt_hash",
                "failure_reason",
                "obligation_results",
            ]
        )
        for payload in payloads:
            obligation_results = payload.get("obligation_results")
            writer.writerow(
                [
                    payload.get("receipt_id", ""),
                    payload.get("capability_id", ""),
                    payload.get("agent", ""),
                    payload.get("target", ""),
                    payload.get("action", ""),
                    payload.get("purpose", ""),
                    payload.get("result", ""),
                    payload.get("started_at", ""),
                    payload.get("finished_at", ""),
                    payload.get("evidence_hash") or "",
                    payload.get("previous_receipt_hash") or "",
                    payload.get("failure_reason") or "",
                    (
                        json.dumps(
                            obligation_results,
                            sort_keys=True,
                            ensure_ascii=False,
                        )
                        if obligation_results is not None
                        else ""
                    ),
                ]
            )
        return buffer.getvalue()

    def export_packet(
        self,
        *,
        capability_id: str | None = None,
        agent: str | None = None,
        target: str | None = None,
        action: str | None = None,
        purpose: str | None = None,
        result: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        strict: bool = True,
    ) -> dict[str, Any]:
        """Build a self-verifying evidence packet of matched receipts."""
        payloads = self.query(
            capability_id=capability_id,
            agent=agent,
            target=target,
            action=action,
            purpose=purpose,
            result=result,
            since=since,
            until=until,
            strict=strict,
        )
        packet: dict[str, Any] = {
            "type": "kinegrant:ReceiptEvidencePacket",
            "schema_version": "0.1",
            "summary": self.summary(strict=strict),
            "receipts": [dict(payload) for payload in payloads],
        }
        unsigned = {
            key: value for key, value in packet.items() if key != "packet_digest"
        }
        packet["packet_digest"] = (
            "sha256:" + hashlib.sha256(canonical_json(unsigned)).hexdigest()
        )
        return packet


def _self_test() -> int:
    authority = Ed25519KeyPair.generate()
    executor = Ed25519KeyPair.generate()
    issuer = CapabilityIssuer(authority)
    rule = PolicyRule(
        "urn:kinegrant:audit:self-test:rule",
        authority.kid,
        "urn:kinegrant:audit:target:*",
        "allow",
        ("open",),
        obligations=("emitActionReceipt",),
    )
    engine = PolicyEngine([rule], trusted_policy_issuers={authority.kid})
    gate = ActionGate(
        trusted_issuers={authority.kid},
        replay_store=InMemoryReplayStore(),
    )
    log = ReceiptLog(executor)
    for index in range(2):
        request = ActionRequest(
            f"urn:kinegrant:audit:request:{index}",
            "urn:kinegrant:audit:agent:1",
            "urn:kinegrant:audit:target:door-7",
            "open",
            "delivery",
        )
        decision = engine.evaluate(request)
        capability = issuer.issue(request, decision, ttl_seconds=300)
        verified = gate.authorize(capability, request)
        log.append(verified, result="succeeded")
    auditor = ReceiptAuditor(log.entries, trusted_executors={executor.kid})
    summary = auditor.summary()
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["chain_valid"] and summary["total"] == 2 else 1


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if "--self-test" in args:
        return _self_test()
    if len(args) < 2:
        print(
            "usage: kinegrant-audit <receipts.json> <executors.json> "
            "[--capability-id ID] [--agent ID] [--action ACTION] "
            "[--result RESULT] [--csv FILE] [--packet FILE]",
            file=sys.stderr,
        )
        return 2
    receipts_path, executors_path = args[0], args[1]

    def flag(name: str) -> str | None:
        if name in args:
            return args[args.index(name) + 1]
        return None

    entries = json.loads(Path(receipts_path).read_text(encoding="utf-8"))
    executors = json.loads(Path(executors_path).read_text(encoding="utf-8"))
    auditor = ReceiptAuditor(entries, trusted_executors=set(executors))
    if not auditor.chain_valid():
        print(json.dumps(auditor.summary(strict=False), indent=2, sort_keys=True))
        return 1
    matched = auditor.query(
        capability_id=flag("--capability-id"),
        agent=flag("--agent"),
        action=flag("--action"),
        result=flag("--result"),
    )
    report = dict(auditor.summary())
    report["matched"] = len(matched)
    csv_path = flag("--csv")
    if csv_path:
        target = Path(csv_path)
        target.write_text(auditor.export_csv(), encoding="utf-8")
        report["csv"] = str(target)
    packet_path = flag("--packet")
    if packet_path:
        target = Path(packet_path)
        target.write_text(
            json.dumps(auditor.export_packet(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        report["packet"] = str(target)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0
