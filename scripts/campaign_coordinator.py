"""Small sequential coordinator for bounded, discovery-backed campaign segments."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence


@dataclass(frozen=True)
class DiscoveryResult:
    scope: str
    evidence_fingerprint: str
    candidates_added: int = 0
    eligible_work: bool = False
    exhausted_reason: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class ContinuousCampaignCoordinator:
    """Run one campaign runner at a time under one deadline and attempt ceiling.

    Each discovery callback identifies the evidence snapshot it examined. A
    repeated snapshot cannot trigger another discovery pass, preventing queue-
    empty spin loops while allowing a genuinely changed snapshot to be retried.
    """

    run_segment: Callable[[float, int], Mapping[str, Any]]
    discovery_steps: Sequence[Callable[[float], DiscoveryResult]]
    attempts_used: Callable[[], int]
    stop_requested: Callable[[], bool]
    max_tasks: int
    duration_seconds: float
    monotonic: Callable[[], float] = time.monotonic
    _examined: set[tuple[str, str]] = field(default_factory=set, init=False)

    def run(self) -> dict[str, Any]:
        if self.max_tasks <= 0:
            raise ValueError("continuous campaign max_tasks must be positive")
        if self.duration_seconds <= 0:
            raise ValueError("continuous campaign duration_seconds must be positive")
        deadline = self.monotonic() + self.duration_seconds
        segments: list[dict[str, Any]] = []
        discoveries: list[dict[str, Any]] = []
        stop_reason = "discovery_exhausted"
        segment_external_work_remains = False

        while self.monotonic() < deadline:
            current_attempts = self.attempts_used()
            if current_attempts >= self.max_tasks:
                stop_reason = "attempt_ceiling"
                break
            if self.stop_requested():
                stop_reason = "stop_requested"
                break

            # The callback owns one CampaignRunner and waits for it to finish;
            # no second runner or SQLite connection owner is started here.
            segment = dict(self.run_segment(deadline, self.max_tasks))
            segments.append(segment)
            segment_external_work_remains = bool(
                segment.get("external_work_remains")
            )
            if self.stop_requested():
                stop_reason = "stop_requested"
                break
            if self.attempts_used() >= self.max_tasks:
                stop_reason = "attempt_ceiling"
                break
            if self.monotonic() >= deadline:
                stop_reason = "deadline"
                break

            added_work = False
            for discover in self.discovery_steps:
                if self.monotonic() >= deadline or self.stop_requested():
                    break
                result = discover(deadline)
                if not isinstance(result, DiscoveryResult):
                    raise TypeError("discovery callbacks must return DiscoveryResult")
                key = (result.scope, result.evidence_fingerprint)
                if key in self._examined:
                    continue
                self._examined.add(key)
                discoveries.append(
                    {
                        "scope": result.scope,
                        "evidence_fingerprint": result.evidence_fingerprint,
                        "candidates_added": result.candidates_added,
                        "eligible_work": result.eligible_work,
                        "exhausted_reason": result.exhausted_reason,
                        "details": dict(result.details),
                    }
                )
                if result.eligible_work:
                    added_work = True
                    break

            if added_work:
                continue
            if self.stop_requested():
                stop_reason = "stop_requested"
            elif self.monotonic() >= deadline:
                stop_reason = "deadline"
            else:
                stop_reason = (
                    "external_work_remains"
                    if segment_external_work_remains
                    else "discovery_exhausted"
                    if all(
                        result.get("eligible_work") or result.get("exhausted_reason")
                        for result in discoveries
                    )
                    else "external_work_remains"
                )
            break
        else:
            stop_reason = "deadline"

        return {
            "segments": segments,
            "discoveries": discoveries,
            "attempts_cumulative": self.attempts_used(),
            "attempt_ceiling": self.max_tasks,
            "deadline_monotonic": deadline,
            "stop_reason": stop_reason,
        }
