"""Forbidden combinations and cross-action sequence policy.

Some dangerous outcomes cannot be expressed as one request. They emerge from
an ordered or unordered combination of actions, e.g. "record the space, then
train on that data" or "open the enclosure, then enter it". KineGrant models
these as *forbidden combinations*: a set of ``(action, target)`` patterns that
must never all be observed in an action journal.

Semantics (v0.2 draft):

- patterns are glob strings matched with :func:`fnmatch.fnmatchcase`;
- combinations are order-insensitive sets of pattern pairs;
- a combination may carry a time window; entries older than the window no
  longer count;
- a combination may carry a ``trigger`` pattern pair; without one, every new
  request is denied once the combination is complete;
- once a combination is complete and a matching request arrives, the policy
  fails closed: the request is denied and the matched combination ids are
  reported for auditing.

The journal and policy are intentionally separate from :class:`ActionGate`:
the gate proves a single capability, while the sequence policy answers "may
this happen given what already happened". Deployments compose them in order:
sequence check first, then gate consumption, then journal.record() on the
terminal receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from typing import Iterable

from .models import ActionRequest, utc_now


@dataclass(frozen=True)
class JournalEntry:
    action: str
    target: str
    at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.action, str) or not self.action.strip():
            raise ValueError("action must be a non-empty string")
        if not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("target must be a non-empty string")
        if self.at.tzinfo is None:
            raise ValueError("journal timestamps must include a timezone")


class ActionJournal:
    """Append-only record of executed physical actions."""

    def __init__(self) -> None:
        self._entries: list[JournalEntry] = []

    @property
    def entries(self) -> tuple[JournalEntry, ...]:
        return tuple(self._entries)

    def record(
        self,
        action: str,
        target: str,
        *,
        at: datetime | None = None,
    ) -> JournalEntry:
        entry = JournalEntry(action, target, at or utc_now())
        self._entries.append(entry)
        return entry

    def matches(
        self,
        action_pattern: str,
        target_pattern: str,
        *,
        now: datetime,
        window_seconds: int | None = None,
    ) -> bool:
        """Return True when any entry matches both patterns within the window."""
        if window_seconds is not None:
            if not isinstance(window_seconds, int) or isinstance(window_seconds, bool) or window_seconds < 1:
                raise ValueError("window_seconds must be a positive integer")
            cutoff = now - timedelta(seconds=window_seconds)
        else:
            cutoff = None
        for entry in self._entries:
            if cutoff is not None and entry.at < cutoff:
                continue
            if fnmatchcase(entry.action, action_pattern) and fnmatchcase(
                entry.target, target_pattern
            ):
                return True
        return False


@dataclass(frozen=True)
class ForbiddenCombination:
    """A set of action/target patterns that must never all be observed."""

    combination_id: str
    patterns: tuple[tuple[str, str], ...]
    window_seconds: int | None = None
    trigger: tuple[str, str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.combination_id, str) or not self.combination_id.strip():
            raise ValueError("combination_id must be a non-empty string")
        if not isinstance(self.patterns, tuple) or not self.patterns:
            raise ValueError("patterns must be a non-empty tuple")
        for action_pattern, target_pattern in self.patterns:
            if not isinstance(action_pattern, str) or not action_pattern.strip():
                raise ValueError("action patterns must be non-empty strings")
            if not isinstance(target_pattern, str) or not target_pattern.strip():
                raise ValueError("target patterns must be non-empty strings")
        if self.window_seconds is not None and (
            not isinstance(self.window_seconds, int)
            or isinstance(self.window_seconds, bool)
            or self.window_seconds < 1
        ):
            raise ValueError("window_seconds must be a positive integer or None")
        if self.trigger is not None:
            action_pattern, target_pattern = self.trigger
            if not isinstance(action_pattern, str) or not action_pattern.strip():
                raise ValueError("trigger action pattern must be a non-empty string")
            if not isinstance(target_pattern, str) or not target_pattern.strip():
                raise ValueError("trigger target pattern must be a non-empty string")

    def is_complete(
        self,
        journal: ActionJournal,
        *,
        now: datetime | None = None,
    ) -> bool:
        current = now or utc_now()
        return all(
            journal.matches(
                action_pattern,
                target_pattern,
                now=current,
                window_seconds=self.window_seconds,
            )
            for action_pattern, target_pattern in self.patterns
        )

    def denies(self, request: ActionRequest) -> bool:
        if self.trigger is None:
            return True
        action_pattern, target_pattern = self.trigger
        return fnmatchcase(request.action, action_pattern) and fnmatchcase(
            request.target, target_pattern
        )


@dataclass(frozen=True)
class SequenceVerdict:
    allowed: bool
    reason: str
    matched_combination_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "matched_combination_ids": list(self.matched_combination_ids),
        }


class SequencePolicy:
    """Fail-closed evaluator for forbidden action combinations."""

    def __init__(self, combinations: Iterable[ForbiddenCombination]) -> None:
        self._combinations = tuple(combinations)
        ids = [combination.combination_id for combination in self._combinations]
        if len(ids) != len(set(ids)):
            raise ValueError("combination_id values must be unique")

    @property
    def combinations(self) -> tuple[ForbiddenCombination, ...]:
        return self._combinations

    def evaluate(
        self,
        request: ActionRequest,
        journal: ActionJournal,
        *,
        now: datetime | None = None,
    ) -> SequenceVerdict:
        current = now or utc_now()
        if current.tzinfo is None:
            raise ValueError("evaluation time must include a timezone")
        matched = tuple(
            combination.combination_id
            for combination in self._combinations
            if combination.is_complete(journal, now=current)
            and combination.denies(request)
        )
        if matched:
            return SequenceVerdict(False, "forbidden_combination", matched)
        return SequenceVerdict(True, "sequence_allowed")
