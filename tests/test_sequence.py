from __future__ import annotations

import unittest
from datetime import timedelta

from kinegrant.models import ActionRequest, utc_now
from kinegrant.sequence import (
    ActionJournal,
    ForbiddenCombination,
    SequencePolicy,
)


def request(action: str, target: str = "door-7") -> ActionRequest:
    return ActionRequest(
        request_id=f"req-seq-{action}-{target}",
        agent="robot-1",
        target=target,
        action=action,
        purpose="delivery",
    )


class SequencePolicyTests(unittest.TestCase):
    def test_completed_combination_denies_trigger_request(self) -> None:
        journal = ActionJournal()
        journal.record("open", "door-7")
        journal.record("record", "door-7")
        policy = SequencePolicy(
            [
                ForbiddenCombination(
                    combination_id="record-then-train",
                    patterns=(
                        ("open", "door-7"),
                        ("record", "door-7"),
                    ),
                )
            ]
        )
        verdict = policy.evaluate(request("train_on_data"), journal)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.reason, "forbidden_combination")
        self.assertEqual(verdict.matched_combination_ids, ("record-then-train",))

    def test_incomplete_combination_is_allowed(self) -> None:
        journal = ActionJournal()
        journal.record("open", "door-7")
        policy = SequencePolicy(
            [
                ForbiddenCombination(
                    combination_id="open-enter",
                    patterns=(("open", "door-7"), ("enter", "door-7")),
                )
            ]
        )
        self.assertTrue(policy.evaluate(request("enter"), journal).allowed)
        journal.record("enter", "door-7")
        self.assertFalse(policy.evaluate(request("enter"), journal).allowed)

    def test_combination_is_order_independent(self) -> None:
        journal = ActionJournal()
        journal.record("train_on_data", "door-7")
        journal.record("open", "door-7")
        policy = SequencePolicy(
            [
                ForbiddenCombination(
                    combination_id="open-train",
                    patterns=(("open", "door-7"), ("train_on_data", "door-7")),
                )
            ]
        )
        self.assertFalse(policy.evaluate(request("enter"), journal).allowed)

    def test_window_expiry_allows_request_again(self) -> None:
        now = utc_now()
        journal = ActionJournal()
        journal.record("open", "door-7", at=now - timedelta(seconds=60))
        journal.record("train_on_data", "door-7", at=now - timedelta(seconds=60))
        policy = SequencePolicy(
            [
                ForbiddenCombination(
                    combination_id="windowed",
                    patterns=(("open", "door-7"), ("train_on_data", "door-7")),
                    window_seconds=30,
                )
            ]
        )
        self.assertTrue(
            policy.evaluate(request("enter"), journal, now=now).allowed
        )

    def test_trigger_pattern_narrows_denial(self) -> None:
        journal = ActionJournal()
        journal.record("open", "door-7")
        journal.record("record", "door-7")
        policy = SequencePolicy(
            [
                ForbiddenCombination(
                    combination_id="record-after-open",
                    patterns=(("open", "door-7"), ("record", "door-7")),
                    trigger=("train_on_data", "*"),
                )
            ]
        )
        self.assertTrue(policy.evaluate(request("touch"), journal).allowed)
        self.assertFalse(
            policy.evaluate(request("train_on_data"), journal).allowed
        )

    def test_glob_patterns_match_multiple_targets(self) -> None:
        journal = ActionJournal()
        journal.record("open", "urn:kinegrant:target:demo:door-7")
        journal.record("enter", "urn:kinegrant:target:demo:door-7")
        policy = SequencePolicy(
            [
                ForbiddenCombination(
                    combination_id="globbed",
                    patterns=(("open", "urn:kinegrant:target:demo:*"), ("enter", "*")),
                )
            ]
        )
        self.assertFalse(
            policy.evaluate(request("touch", "urn:kinegrant:target:demo:door-7"), journal).allowed
        )

    def test_duplicate_combination_ids_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SequencePolicy(
                [
                    ForbiddenCombination("dup", (("open", "*"),)),
                    ForbiddenCombination("dup", (("enter", "*"),)),
                ]
            )

    def test_invalid_combination_construction(self) -> None:
        with self.assertRaises(ValueError):
            ForbiddenCombination("bad", ())
        with self.assertRaises(ValueError):
            ForbiddenCombination("bad", (("", "*"),))
        with self.assertRaises(ValueError):
            ForbiddenCombination("bad", (("open", "*"),), window_seconds=0)

    def test_journal_validates_entries(self) -> None:
        journal = ActionJournal()
        with self.assertRaises(ValueError):
            journal.record("", "door-7")
        with self.assertRaises(ValueError):
            journal.record("open", "")

    def test_verdict_is_serializable(self) -> None:
        journal = ActionJournal()
        journal.record("open", "door-7")
        journal.record("enter", "door-7")
        policy = SequencePolicy(
            [
                ForbiddenCombination(
                    "vc",
                    (("open", "door-7"), ("enter", "door-7")),
                )
            ]
        )
        verdict = policy.evaluate(request("touch"), journal)
        self.assertEqual(
            verdict.to_dict(),
            {
                "allowed": False,
                "reason": "forbidden_combination",
                "matched_combination_ids": ["vc"],
            },
        )


if __name__ == "__main__":
    unittest.main()
