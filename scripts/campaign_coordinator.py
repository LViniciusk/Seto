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


def run_fair_segments(
    *,
    run_exports: Callable[[float, int, int], Mapping[str, Any]],
    run_internal: Callable[[float, int, int], Mapping[str, Any]],
    attempts_used: Callable[[], int],
    stop_requested: Callable[[], bool],
    deadline: float,
    max_tasks: int,
    monotonic: Callable[[], float] = time.monotonic,
    attempts_per_turn: int = 1,
    exports_work_remains: Callable[[], bool] | None = None,
    first_lane: str = "exports",
) -> dict[str, Any]:
    """Alternate bounded export/internal slices under the caller's shared limits."""
    if max_tasks <= 0 or attempts_per_turn <= 0:
        raise ValueError("fair segment attempt limits must be positive")
    if first_lane not in {"exports", "internal"}:
        raise ValueError("first fair segment lane must be exports or internal")
    callbacks = {"exports": run_exports, "internal": run_internal}
    order = (first_lane, "internal" if first_lane == "exports" else "exports")
    segments: list[dict[str, Any]] = []
    outcomes: dict[str, int] = {}
    export_boundary_outcomes: dict[str, int] = {}
    internal_outcomes: dict[str, int] = {}
    internal_boundary_outcomes: dict[str, int] = {}
    internal_stages: dict[str, int] = {}
    attempts = 0
    internal_attempts = 0
    recovery_only_call = attempts_used() >= max_tasks
    remaining_by_lane = {"exports": False, "internal": False}
    stop_reason = "queues_empty"

    while monotonic() < deadline:
        if stop_requested():
            stop_reason = "stop_requested"
            break
        if attempts_used() >= max_tasks:
            if exports_work_remains is not None:
                remaining_by_lane["exports"] = bool(exports_work_remains())
            if recovery_only_call:
                recovery = dict(run_internal(deadline, max_tasks, attempts_per_turn))
                if int(recovery.get("attempted", 0)) != 0:
                    raise RuntimeError("internal recovery segment exceeded the exhausted attempt ceiling")
                segments.append({"lane": "internal_recovery", **recovery})
                remaining_by_lane["internal"] = bool(
                    recovery.get("external_work_remains", False)
                )
                for name, count in recovery.get("outcomes", {}).items():
                    count = int(count)
                    outcomes[f"internal_{name}"] = outcomes.get(f"internal_{name}", 0) + count
                    internal_outcomes[str(name)] = internal_outcomes.get(str(name), 0) + count
                for name, count in recovery.get("boundary_outcomes", {}).items():
                    internal_boundary_outcomes[str(name)] = (
                        internal_boundary_outcomes.get(str(name), 0) + int(count)
                    )
                for name, count in recovery.get("stages", {}).items():
                    internal_stages[str(name)] = internal_stages.get(str(name), 0) + int(count)
            stop_reason = "attempt_ceiling"
            break

        round_attempts = 0
        round_boundary_work = 0
        round_stage_work = 0
        for lane in order:
            if stop_requested():
                stop_reason = "stop_requested"
                break
            if monotonic() >= deadline:
                stop_reason = "deadline"
                break
            if attempts_used() >= max_tasks:
                stop_reason = "attempt_ceiling"
                break
            result = dict(callbacks[lane](deadline, max_tasks, attempts_per_turn))
            segments.append({"lane": lane, **result})
            used = int(result.get("attempted", 0))
            attempts += used
            round_attempts += used
            if lane == "internal":
                internal_attempts += used
            remaining_by_lane[lane] = bool(result.get("external_work_remains", False))
            lane_outcomes = result.get("outcomes", {})
            if isinstance(lane_outcomes, Mapping):
                for name, count in lane_outcomes.items():
                    count = int(count)
                    key = name if lane == "exports" else f"internal_{name}"
                    outcomes[key] = outcomes.get(key, 0) + count
                    if lane == "internal":
                        internal_outcomes[str(name)] = internal_outcomes.get(str(name), 0) + count
            boundary = result.get("boundary_outcomes", {})
            if isinstance(boundary, Mapping):
                boundary_count = sum(int(count) for count in boundary.values())
                round_boundary_work += boundary_count
                target = export_boundary_outcomes if lane == "exports" else internal_boundary_outcomes
                for name, count in boundary.items():
                    target[str(name)] = target.get(str(name), 0) + int(count)
            stages = result.get("stages", {})
            if isinstance(stages, Mapping):
                round_stage_work += sum(int(count) for count in stages.values())
            if lane == "internal" and isinstance(stages, Mapping):
                for name, count in stages.items():
                    internal_stages[str(name)] = internal_stages.get(str(name), 0) + int(count)
        if stop_reason in {"stop_requested", "deadline", "attempt_ceiling"}:
            break
        if round_attempts == 0 and round_boundary_work == 0 and round_stage_work == 0:
            stop_reason = "external_work_remains" if any(remaining_by_lane.values()) else "queues_empty"
            break
        order = ("internal", "exports") if order[0] == "exports" else ("exports", "internal")
    else:
        stop_reason = "deadline"

    return {
        "segments": segments,
        "attempted": attempts,
        "attempts_cumulative": attempts_used(),
        "attempt_ceiling": max_tasks,
        "stop_reason": stop_reason,
        "external_work_remains": any(remaining_by_lane.values()),
        "outcomes": outcomes,
        "export_boundary_outcomes": export_boundary_outcomes,
        "internal_attempted": internal_attempts,
        "internal_outcomes": internal_outcomes,
        "internal_boundary_outcomes": internal_boundary_outcomes,
        "internal_stages": internal_stages,
    }


def prepare_internal_lane_before_inference(
    *,
    discover_internal: Callable[[float], DiscoveryResult],
    prepare_boundary: Callable[[float, int], Mapping[str, Any]],
    exact_pending_count: Callable[[], int],
    deadline: float,
    max_boundary_tasks: int = 8,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Discover and prove an EXACT internal task before any campaign inference."""
    if max_boundary_tasks <= 0:
        raise ValueError("initial internal boundary limit must be positive")
    exact_before = exact_pending_count()
    discovery: DiscoveryResult | None = None
    boundary: dict[str, Any] = {}
    if exact_before <= 0 and monotonic() < deadline:
        discovery = discover_internal(deadline)
        if not isinstance(discovery, DiscoveryResult):
            raise TypeError("initial internal discovery must return DiscoveryResult")
        if exact_pending_count() <= 0 and monotonic() < deadline:
            boundary = dict(prepare_boundary(deadline, max_boundary_tasks))
            if int(boundary.get("attempted", 0)) != 0:
                raise RuntimeError("initial internal boundary preparation consumed an inference attempt")
    exact_after = exact_pending_count()
    return {
        "ready": exact_after > 0,
        "exact_pending_before": exact_before,
        "exact_pending_after": exact_after,
        "discovery": None
        if discovery is None
        else {
            "scope": discovery.scope,
            "evidence_fingerprint": discovery.evidence_fingerprint,
            "candidates_added": discovery.candidates_added,
            "eligible_work": discovery.eligible_work,
            "exhausted_reason": discovery.exhausted_reason,
            "details": dict(discovery.details),
        },
        "boundary": boundary,
        "deadline_reached": monotonic() >= deadline,
    }


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

    def run(self, *, deadline: float | None = None) -> dict[str, Any]:
        if self.max_tasks <= 0:
            raise ValueError("continuous campaign max_tasks must be positive")
        if self.duration_seconds <= 0:
            raise ValueError("continuous campaign duration_seconds must be positive")
        local_deadline = self.monotonic() + self.duration_seconds
        if deadline is None:
            deadline = local_deadline
        else:
            deadline = min(deadline, local_deadline)
        segments: list[dict[str, Any]] = []
        discoveries: list[dict[str, Any]] = []
        stop_reason = "discovery_exhausted"
        segment_external_work_remains = False

        while self.monotonic() < deadline:
            current_attempts = self.attempts_used()
            if current_attempts >= self.max_tasks:
                # Give the bounded segment one chance to reconcile a persisted
                # promotion/source checkpoint. Its cumulative ceiling remains
                # closed, so no new inference may start.
                if not self.stop_requested():
                    segment = dict(self.run_segment(deadline, self.max_tasks))
                    segments.append(segment)
                    segment_external_work_remains = bool(
                        segment.get("external_work_remains")
                    )
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
