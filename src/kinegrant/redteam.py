"""Executable red-team suite (v0.5).

The suite probes the reference implementation with adversarial scenarios:
replay, request mutation, confused deputy, policy conflict, downgrade,
clock manipulation, revocation bypass, delegation abuse, adapter confusion,
and forbidden combinations. Every probe records expected vs. observed
behavior; the suite passes only when every probe behaves as expected.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .adapters.odrl import odrl_to_rules
from .capability import CapabilityIssuer
from .compliance import ObligationCompliance
from .crypto import Ed25519KeyPair
from .gate import ActionGate, InMemoryReplayStore
from .models import ActionRequest, PolicyRule, parse_time
from .policy import PolicyEngine
from .revocation import RevocationList
from .sequence import ActionJournal, ForbiddenCombination, SequencePolicy

RED_TEAM_CASES: tuple[dict[str, str], ...] = (
    {"id": "RT-001", "category": "replay", "name": "Consumed capability cannot be replayed"},
    {"id": "RT-002", "category": "mutation", "name": "Modified request binding is rejected"},
    {"id": "RT-003", "category": "confused-deputy", "name": "Wrong agent cannot act"},
    {"id": "RT-004", "category": "conflict", "name": "Deny overrides allow"},
    {"id": "RT-005", "category": "downgrade", "name": "Unknown capability version is rejected"},
    {"id": "RT-006", "category": "clock", "name": "Expired capability is rejected"},
    {"id": "RT-007", "category": "revocation", "name": "Revoked capability is rejected"},
    {"id": "RT-008", "category": "delegation", "name": "Delegate outside allowlist is rejected"},
    {"id": "RT-009", "category": "adapter", "name": "Unknown ODRL constraint fails closed"},
    {"id": "RT-010", "category": "sequence", "name": "Forbidden combination is denied"},
    {"id": "RT-011", "category": "obligation", "name": "Suppressed receipt obligation is detected"},
)


class RedTeamSuite:
    def __init__(self) -> None:
        self.authority = Ed25519KeyPair.generate()
        self.issuer = CapabilityIssuer(self.authority)
        self.request = ActionRequest(
            "urn:kinegrant:redteam:request:1",
            "urn:kinegrant:redteam:agent:1",
            "urn:kinegrant:redteam:target:door-7",
            "open",
            "delivery",
        )
        allow = PolicyRule(
            "urn:kinegrant:redteam:policy:allow",
            self.authority.kid,
            "urn:kinegrant:redteam:target:*",
            "allow",
            ("open", "close"),
            subjects=("urn:kinegrant:redteam:agent:*",),
            purposes=("delivery",),
            obligations=("emitActionReceipt",),
        )
        deny = PolicyRule(
            "urn:kinegrant:redteam:policy:deny-close",
            self.authority.kid,
            "urn:kinegrant:redteam:target:*",
            "deny",
            ("close",),
        )
        self.engine = PolicyEngine(
            [allow, deny],
            trusted_policy_issuers={self.authority.kid},
        )
        self.gate = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
        )
        self.journal = ActionJournal()
        self.sequence = SequencePolicy(
            [
                ForbiddenCombination(
                    "record-open-train",
                    (("record", "*"), ("open", "*")),
                    trigger=("train_on_data", "*"),
                )
            ]
        )

    def _capability(self, request: ActionRequest | None = None, ttl: int = 30) -> dict:
        request = request or self.request
        decision = self.engine.evaluate(request)
        return self.issuer.issue(request, decision, ttl_seconds=ttl)

    def run(self) -> dict[str, Any]:
        probes: list[Callable[[], tuple[bool, str]]] = [
            self._probe_replay,
            self._probe_mutation,
            self._probe_confused_deputy,
            self._probe_conflict,
            self._probe_downgrade,
            self._probe_clock,
            self._probe_revocation,
            self._probe_delegation,
            self._probe_adapter,
            self._probe_sequence,
            self._probe_obligation,
        ]
        outcomes = []
        for case, probe in zip(RED_TEAM_CASES, probes):
            try:
                passed, detail = probe()
            except Exception as exc:  # a crashing probe is a failure
                passed, detail = False, f"ERROR: {type(exc).__name__}: {exc}"
            outcomes.append(
                {
                    **case,
                    "expected": "DENY",
                    "observed": "DENY" if passed else "ALLOW/ERROR",
                    "passed": passed,
                    "detail": detail,
                }
            )
        passed = sum(item["passed"] for item in outcomes)
        return {
            "type": "kinegrant:RedTeamReport",
            "schema_version": "0.1",
            "overall_result": "PASS" if passed == len(outcomes) else "FAIL",
            "summary": {"total": len(outcomes), "passed": passed, "failed": len(outcomes) - passed},
            "cases": outcomes,
        }

    def _denied(self, operation: Callable[[], object]) -> tuple[bool, str]:
        try:
            operation()
        except (PermissionError, ValueError) as exc:
            return True, f"{type(exc).__name__}: {exc}"
        return False, "accepted"

    def _probe_replay(self) -> tuple[bool, str]:
        capability = self._capability()
        self.gate.authorize(capability, self.request)
        return self._denied(lambda: self.gate.authorize(capability, self.request))

    def _probe_mutation(self) -> tuple[bool, str]:
        capability = self._capability()
        changed = ActionRequest(
            "urn:kinegrant:redteam:request:mutated",
            "urn:kinegrant:redteam:agent:attacker",
            "urn:kinegrant:redteam:target:other",
            "open",
            "delivery",
        )
        return self._denied(lambda: self.gate.authorize(capability, changed))

    def _probe_confused_deputy(self) -> tuple[bool, str]:
        capability = self._capability()
        other_agent = ActionRequest(
            "urn:kinegrant:redteam:request:deputy",
            "urn:kinegrant:redteam:agent:2",
            "urn:kinegrant:redteam:target:door-7",
            "open",
            "delivery",
        )
        return self._denied(lambda: self.gate.authorize(capability, other_agent))

    def _probe_conflict(self) -> tuple[bool, str]:
        decision = self.engine.evaluate(
            ActionRequest(
                "urn:kinegrant:redteam:request:close",
                "urn:kinegrant:redteam:agent:1",
                "urn:kinegrant:redteam:target:door-7",
                "close",
                "delivery",
            )
        )
        return (not decision.allowed, decision.reason)

    def _probe_downgrade(self) -> tuple[bool, str]:
        capability = self._capability()
        capability["payload"]["version"] = "9.9"
        return self._denied(lambda: self.gate.authorize(capability, self.request))

    def _probe_clock(self) -> tuple[bool, str]:
        capability = self._capability(ttl=10)
        expiry = parse_time(capability["payload"]["expires_at"])
        return self._denied(
            lambda: self.gate.authorize(capability, self.request, now=expiry)
        )

    def _probe_revocation(self) -> tuple[bool, str]:
        capability = self._capability()
        rl = RevocationList()
        rl.revoke(capability["payload"]["capability_id"])
        gate = ActionGate(
            trusted_issuers={self.authority.kid},
            replay_store=InMemoryReplayStore(),
            revocation_list=rl,
        )
        return self._denied(lambda: gate.authorize(capability, self.request))

    def _probe_delegation(self) -> tuple[bool, str]:
        decision = self.engine.evaluate(self.request)
        root = self.issuer.issue_scoped(
            self.request,
            decision,
            ttl_seconds=30,
            target="urn:kinegrant:redteam:target:*",
            actions=["open"],
            purposes=["delivery"],
            delegation_allowed=True,
            max_delegation_depth=1,
            delegate_allowlist=["urn:kinegrant:redteam:agent:2"],
        )
        outsider = ActionRequest(
            "urn:kinegrant:redteam:request:outsider",
            "urn:kinegrant:redteam:agent:3",
            "urn:kinegrant:redteam:target:door-7",
            "open",
            "delivery",
        )
        return self._denied(
            lambda: self.issuer.issue_attenuated(
                root,
                target="urn:kinegrant:redteam:target:door-7",
                delegate_agent=outsider.agent,
                delegate_request=outsider,
            )
        )

    def _probe_adapter(self) -> tuple[bool, str]:
        doc = {
            "@context": "http://www.w3.org/ns/odrl/2/",
            "@type": "Offer",
            "uid": "urn:kinegrant:redteam:odrl:1",
            "profile": "http://www.w3.org/ns/odrl/2/",
            "assigner": self.authority.kid,
            "permission": [
                {
                    "target": "urn:kinegrant:redteam:target:door-7",
                    "assignee": "*",
                    "action": "open",
                    "constraint": [
                        {"leftOperand": "maxForceNewtons", "operator": "eq", "rightOperand": 50}
                    ],
                }
            ],
        }
        return self._denied(lambda: odrl_to_rules(doc))

    def _probe_sequence(self) -> tuple[bool, str]:
        self.journal.record("record", "urn:kinegrant:redteam:target:door-7")
        self.journal.record("open", "urn:kinegrant:redteam:target:door-7")
        train = ActionRequest(
            "urn:kinegrant:redteam:request:train",
            "urn:kinegrant:redteam:agent:1",
            "urn:kinegrant:redteam:target:door-7",
            "train_on_data",
            "audit",
        )
        verdict = self.sequence.evaluate(train, self.journal)
        return (not verdict.allowed, verdict.reason)

    def _probe_obligation(self) -> tuple[bool, str]:
        capability = self._capability()
        self.gate.authorize(capability, self.request)
        executor = Ed25519KeyPair.generate()
        verdict = ObligationCompliance().evaluate(
            capability,
            [],
            trusted_executors={executor.kid},
        )
        if verdict.compliant:
            return False, "compliance accepted a suppressed receipt"
        detail = verdict.reason or "missing receipt"
        return True, detail


def main(argv: list[str] | None = None) -> int:
    report = RedTeamSuite().run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
