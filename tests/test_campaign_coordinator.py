from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from campaign_coordinator import ContinuousCampaignCoordinator, DiscoveryResult


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_empty_runner_queue_runs_discovery_then_reuses_same_runner_segment() -> None:
    clock = FakeClock()
    attempts = 0
    segments: list[tuple[float, int]] = []
    discoveries = 0

    def run_segment(deadline: float, max_tasks: int) -> dict[str, object]:
        nonlocal attempts
        segments.append((deadline, max_tasks))
        if len(segments) == 2:
            attempts += 1
            return {"attempted": 1, "outcomes": {"matched": 1}}
        return {"attempted": 0, "outcomes": {}}

    def discover_exports(deadline: float) -> DiscoveryResult:
        nonlocal discoveries
        discoveries += 1
        return DiscoveryResult(
            "eboot-exports",
            "triage-sha256",
            candidates_added=1 if discoveries == 1 else 0,
            eligible_work=discoveries == 1,
            exhausted_reason="no new proven exports" if discoveries > 1 else None,
        )

    coordinator = ContinuousCampaignCoordinator(
        run_segment=run_segment,
        discovery_steps=[discover_exports],
        attempts_used=lambda: attempts,
        stop_requested=lambda: False,
        max_tasks=725,
        duration_seconds=36000,
        monotonic=clock,
    )

    result = coordinator.run()

    assert len(segments) == 2
    assert segments[0] == segments[1]
    assert result["attempts_cumulative"] == 1
    assert result["attempt_ceiling"] == 725
    assert result["stop_reason"] == "discovery_exhausted"
    assert [item["scope"] for item in result["discoveries"]] == ["eboot-exports"]


def test_empty_scopes_are_examined_once_and_do_not_spin() -> None:
    clock = FakeClock()
    segment_calls = 0
    scope_calls: list[str] = []

    def run_segment(deadline: float, max_tasks: int) -> dict[str, object]:
        nonlocal segment_calls
        segment_calls += 1
        return {"attempted": 0, "outcomes": {}}

    def empty_scope(scope: str):
        def discover(deadline: float) -> DiscoveryResult:
            scope_calls.append(scope)
            return DiscoveryResult(scope, "same-evidence", exhausted_reason="no safe candidates")

        return discover

    result = ContinuousCampaignCoordinator(
        run_segment=run_segment,
        discovery_steps=[empty_scope("eboot"), empty_scope("internal"), empty_scope("prx")],
        attempts_used=lambda: 213,
        stop_requested=lambda: False,
        max_tasks=725,
        duration_seconds=20,
        monotonic=clock,
    ).run()

    assert segment_calls == 1
    assert scope_calls == ["eboot", "internal", "prx"]
    assert result["stop_reason"] == "discovery_exhausted"
    assert len(result["discoveries"]) == 3


def test_deadline_and_cumulative_attempt_ceiling_are_global_across_segments() -> None:
    clock = FakeClock()
    attempts = 213
    deadlines: list[float] = []

    def run_segment(deadline: float, max_tasks: int) -> dict[str, object]:
        nonlocal attempts
        deadlines.append(deadline)
        assert max_tasks == 215
        attempts += 1
        clock.now += 4
        return {"attempted": 1, "outcomes": {"matched": 1}}

    def discover(deadline: float) -> DiscoveryResult:
        assert deadline == 110.0
        clock.now += 3
        return DiscoveryResult("exports", "new-snapshot", eligible_work=True, candidates_added=1)

    result = ContinuousCampaignCoordinator(
        run_segment=run_segment,
        discovery_steps=[discover],
        attempts_used=lambda: attempts,
        stop_requested=lambda: False,
        max_tasks=215,
        duration_seconds=10,
        monotonic=clock,
    ).run()

    assert deadlines == [110.0, 110.0]
    assert attempts == 215
    assert result["attempts_cumulative"] == 215
    assert result["stop_reason"] == "attempt_ceiling"


def test_coordinator_stops_on_global_stop_request() -> None:
    calls = 0

    def run_segment(deadline: float, max_tasks: int) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {"attempted": 0}

    result = ContinuousCampaignCoordinator(
        run_segment=run_segment,
        discovery_steps=[],
        attempts_used=lambda: 0,
        stop_requested=lambda: True,
        max_tasks=10,
        duration_seconds=10,
        monotonic=FakeClock(),
    ).run()

    assert calls == 0
    assert result["stop_reason"] == "stop_requested"


def test_queued_work_without_new_discovery_reports_external_work_remains() -> None:
    clock = FakeClock()
    runs = 0
    discoveries = 0

    def run_segment(_deadline: float, _max_tasks: int) -> dict[str, object]:
        nonlocal runs
        runs += 1
        return {"attempted": 0, "external_work_remains": True}

    def discover(_deadline: float) -> DiscoveryResult:
        nonlocal discoveries
        discoveries += 1
        return DiscoveryResult("internal", "same-snapshot", eligible_work=True)

    result = ContinuousCampaignCoordinator(
        run_segment=run_segment,
        discovery_steps=[discover],
        attempts_used=lambda: 0,
        stop_requested=lambda: False,
        max_tasks=4,
        duration_seconds=30,
        monotonic=clock,
    ).run()

    assert runs == 2
    assert discoveries == 2
    assert result["stop_reason"] == "external_work_remains"
