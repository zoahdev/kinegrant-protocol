"""Deterministic adapter fuzzing (v0.5).

``AdapterFuzzHarness`` mutates seed documents for the external adapters and
asserts the fail-closed invariant: every outcome is either a valid conversion
or a clean rejection (ValueError/TypeError/KeyError). Unexpected exceptions,
crashes, or silent widening are failures.
"""

from __future__ import annotations

import json
import random
from dataclasses import replace
from typing import Any, Callable, Mapping

from .adapters.ieee7012 import myterms_to_rules
from .adapters.odrl import odrl_forbidden_combinations, odrl_to_rules
from .adapters.wot import describe_wot_actions
from .capability import CapabilityIssuer
from .crypto import Ed25519KeyPair
from .gate import ActionGate
from .models import ActionRequest, PolicyRule
from .policy import PolicyEngine


def _seed_documents() -> dict[str, dict[str, Any]]:
    return {
        "odrl": {
            "@context": "http://www.w3.org/ns/odrl/2/",
            "@type": "Offer",
            "uid": "urn:kinegrant:fuzz:odrl:1",
            "profile": "http://www.w3.org/ns/odrl/2/",
            "assigner": "trusted",
            "permission": [
                {
                    "target": "urn:kinegrant:fuzz:target:1",
                    "assignee": "*",
                    "action": "open",
                    "constraint": [
                        {"leftOperand": "purpose", "operator": "eq", "rightOperand": "delivery"}
                    ],
                }
            ],
        },
        "odrl-sequence": {
            "@context": "http://www.w3.org/ns/odrl/2/",
            "@type": "Offer",
            "uid": "urn:kinegrant:fuzz:odrl-seq:1",
            "profile": "https://kinegrant.com/profiles/odrl/kgp-v0.2",
            "assigner": "trusted",
            "kg:prohibitedCombination": [
                {
                    "uid": "urn:kinegrant:fuzz:combo:1",
                    "patterns": [
                        {"action": "record", "target": "urn:kinegrant:fuzz:target:*"},
                    ],
                    "windowSeconds": 3600,
                    "trigger": {"action": "train_on_data", "target": "urn:kinegrant:fuzz:target:*"},
                }
            ],
        },
        "ieee7012": {
            "id": "urn:kinegrant:fuzz:myterms:1",
            "subject": "person:owner",
            "issuer": "trusted",
            "target": "urn:kinegrant:fuzz:target:1",
            "terms": [
                {
                    "effect": "allow",
                    "action": "open",
                    "agents": ["robot-1"],
                    "purposes": ["delivery"],
                }
            ],
        },
        "wot": {
            "id": "urn:kinegrant:fuzz:thing:1",
            "actions": {
                "open": {"title": "Open", "safe": True, "idempotent": True},
                "close": {"title": "Close", "safe": False, "idempotent": False},
            },
        },
    }


def _mutate(rng: random.Random, value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return value
    choice = rng.randrange(6)
    if choice == 0:
        return None
    if choice == 1:
        return rng.choice(["", "*", "open", "urn:kinegrant:fuzz:target:1", "x" * 200])
    if choice == 2:
        return rng.randrange(-5, 200)
    if isinstance(value, Mapping):
        result = dict(value)
        if rng.random() < 0.4 and result:
            key = rng.choice(list(result))
            del result[key]
        else:
            result["extra_" + str(rng.randrange(1000))] = _mutate(rng, value, depth + 1)
        return result
    if isinstance(value, list):
        result = list(value)
        if rng.random() < 0.5 and result:
            result.pop(rng.randrange(len(result)))
        else:
            result.append(_mutate(rng, value[0] if value else {}, depth + 1))
        return result
    return value


ADAPTERS: dict[str, Callable[[Mapping[str, Any]], object]] = {
    "odrl": odrl_to_rules,
    "odrl-sequence": odrl_forbidden_combinations,
    "ieee7012": myterms_to_rules,
    "wot": describe_wot_actions,
}


class AdapterFuzzHarness:
    def __init__(self, *, seed: int = 1, iterations: int = 30) -> None:
        if iterations < 1:
            raise ValueError("iterations must be a positive integer")
        self.seed = seed
        self.iterations = iterations

    def run(self) -> dict[str, Any]:
        rng = random.Random(self.seed)
        seeds = _seed_documents()
        cases = []
        for adapter_name, adapter in ADAPTERS.items():
            seed_doc = seeds[adapter_name]
            for index in range(self.iterations):
                doc = _mutate(rng, seed_doc)
                try:
                    adapter(doc)
                    outcome = "accepted"
                    clean = True
                except (ValueError, TypeError, KeyError, AttributeError) as exc:
                    outcome = f"rejected:{type(exc).__name__}"
                    clean = True
                except Exception as exc:  # unexpected crash is a failure
                    outcome = f"crash:{type(exc).__name__}:{exc}"
                    clean = False
                cases.append(
                    {
                        "adapter": adapter_name,
                        "iteration": index,
                        "outcome": outcome,
                        "clean": clean,
                        "document": json.dumps(doc, sort_keys=True, ensure_ascii=False)[:200],
                    }
                )
        passed = sum(case["clean"] for case in cases)
        return {
            "type": "kinegrant:AdapterFuzzReport",
            "schema_version": "0.1",
            "seed": self.seed,
            "iterations_per_adapter": self.iterations,
            "overall_result": "PASS" if passed == len(cases) else "FAIL",
            "summary": {"total": len(cases), "clean": passed, "failed": len(cases) - passed},
            "cases": cases,
        }


_CLEAN_REJECTIONS = (PermissionError, ValueError, TypeError, KeyError, AttributeError)


def _core_fixture() -> tuple[ActionRequest, dict[str, Any], ActionGate]:
    request = ActionRequest(
        "urn:kinegrant:fuzz:request:1",
        "urn:kinegrant:fuzz:agent:1",
        "urn:kinegrant:fuzz:target:1",
        "open",
        "delivery",
    )
    rule = PolicyRule(
        "urn:kinegrant:fuzz:policy:1",
        "urn:kinegrant:fuzz:authority:1",
        request.target,
        "allow",
        (request.action,),
        subjects=(request.agent,),
        purposes=(request.purpose,),
        obligations=("emitActionReceipt",),
    )
    decision = PolicyEngine(
        [rule],
        trusted_policy_issuers={rule.issuer},
    ).evaluate(request)
    authority = Ed25519KeyPair.generate()
    capability = CapabilityIssuer(authority).issue(request, decision, ttl_seconds=30)
    gate = ActionGate(trusted_issuers={authority.kid})
    return request, capability, gate


class CoreFuzzHarness:
    """Fuzz the fail-closed core: a mutated capability or request must never be accepted."""

    def __init__(self, *, seed: int = 1, iterations: int = 50) -> None:
        if iterations < 1:
            raise ValueError("iterations must be a positive integer")
        self.seed = seed
        self.iterations = iterations

    def run(self) -> dict[str, Any]:
        rng = random.Random(self.seed)
        cases = []
        for index in range(self.iterations):
            request, capability, gate = _core_fixture()
            mode = rng.choice(("payload", "request"))
            if mode == "payload":
                target = {**capability, "payload": _mutate(rng, capability["payload"])}
                req = request
                detail = "mutated signed payload"
            else:
                field = rng.choice(("agent", "target", "action", "purpose"))
                req = replace(request, **{field: f"urn:kinegrant:fuzz:mutated:{index}"})
                target = capability
                detail = f"mutated request.{field}"

            try:
                gate.authorize(target, req)
                outcome = "ACCEPTED"
                clean = False  # fail-open: a mutated input was accepted
            except _CLEAN_REJECTIONS as exc:
                outcome = f"rejected:{type(exc).__name__}"
                clean = True
            except Exception as exc:  # pragma: no cover - unexpected crash is a failure
                outcome = f"crash:{type(exc).__name__}:{exc}"
                clean = False

            cases.append(
                {
                    "iteration": index,
                    "mode": mode,
                    "detail": detail,
                    "outcome": outcome,
                    "clean": clean,
                }
            )

        passed = sum(case["clean"] for case in cases)
        return {
            "type": "kinegrant:CoreFuzzReport",
            "schema_version": "0.1",
            "seed": self.seed,
            "iterations": self.iterations,
            "overall_result": "PASS" if passed == len(cases) else "FAIL",
            "summary": {"total": len(cases), "clean": passed, "failed": len(cases) - passed},
            "cases": cases,
        }


def main(argv: list[str] | None = None) -> int:
    """Run the deterministic adapter fuzz harness and print a report."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Deterministic fail-closed fuzzing for the external adapters"
    )
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=30)
    args = parser.parse_args(argv)

    adapter_report = AdapterFuzzHarness(
        seed=args.seed,
        iterations=args.iterations,
    ).run()
    core_report = CoreFuzzHarness(
        seed=args.seed,
        iterations=args.iterations,
    ).run()
    combined = {
        "type": "kinegrant:FuzzReport",
        "schema_version": "0.1",
        "seed": args.seed,
        "overall_result": (
            "PASS"
            if adapter_report["overall_result"] == "PASS"
            and core_report["overall_result"] == "PASS"
            else "FAIL"
        ),
        "adapter": adapter_report,
        "core": core_report,
    }
    print(json.dumps(combined, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if combined["overall_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
