from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from campaign_coordinator import (
    ContinuousCampaignCoordinator,
    DiscoveryResult,
    prepare_internal_lane_before_inference,
    run_fair_segments,
)


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


def test_fair_segments_alternate_when_both_queues_remain_busy() -> None:
    attempts = 0
    calls: list[str] = []
    deadline = 150.0

    def segment(lane: str):
        def run(received_deadline: float, ceiling: int, attempt_limit: int):
            nonlocal attempts
            assert received_deadline == deadline
            assert ceiling == 6
            assert attempt_limit == 1
            calls.append(lane)
            attempts += 1
            return {
                "attempted": 1,
                "outcomes": {"matched": 1},
                "external_work_remains": True,
            }

        return run

    result = run_fair_segments(
        run_exports=segment("exports"),
        run_internal=segment("internal"),
        attempts_used=lambda: attempts,
        stop_requested=lambda: False,
        deadline=deadline,
        max_tasks=6,
        monotonic=lambda: 100.0,
    )

    assert len(calls) == 6
    assert calls[:2] == ["exports", "internal"]
    assert calls[2:4] == ["internal", "exports"]
    assert calls.count("exports") == calls.count("internal") == 3
    assert result["attempted"] == result["attempts_cumulative"] == 6
    assert result["stop_reason"] == "attempt_ceiling"


def test_empty_internal_queue_is_discovered_and_bounded_before_first_inference() -> None:
    events: list[str] = []
    attempts = 0
    exact_pending = 0
    deadline = 200.0

    def discover(received_deadline: float) -> DiscoveryResult:
        nonlocal exact_pending
        assert received_deadline == deadline
        assert attempts == 0
        events.append("discover")
        return DiscoveryResult(
            scope="eboot-internal",
            evidence_fingerprint="manifest-hash",
            candidates_added=1,
            eligible_work=True,
        )

    def prepare_boundary(received_deadline: float, limit: int) -> dict[str, object]:
        nonlocal exact_pending
        assert received_deadline == deadline
        assert limit == 8
        assert attempts == 0
        events.append("boundary")
        exact_pending = 1
        return {
            "attempted": 0,
            "boundary_outcomes": {"exact": 1},
            "external_work_remains": True,
        }

    prepared = prepare_internal_lane_before_inference(
        discover_internal=discover,
        prepare_boundary=prepare_boundary,
        exact_pending_count=lambda: exact_pending,
        deadline=deadline,
        monotonic=lambda: 100.0,
    )
    assert prepared["ready"] is True
    assert prepared["exact_pending_before"] == 0
    assert prepared["exact_pending_after"] == 1
    assert events == ["discover", "boundary"]

    def inference(lane: str):
        def run(_deadline: float, _ceiling: int, _slice: int) -> dict[str, object]:
            nonlocal attempts
            events.append(f"inference:{lane}")
            attempts += 1
            return {"attempted": 1, "external_work_remains": True}

        return run

    run_fair_segments(
        run_exports=inference("exports"),
        run_internal=inference("internal"),
        attempts_used=lambda: attempts,
        stop_requested=lambda: False,
        deadline=deadline,
        max_tasks=2,
        first_lane="internal",
        monotonic=lambda: 150.0,
    )
    assert events == [
        "discover",
        "boundary",
        "inference:internal",
        "inference:exports",
    ]
    assert attempts == 2


def test_attempt_ceiling_allows_one_zero_attempt_internal_recovery_pass() -> None:
    calls = 0

    def run_segment(_deadline: float, ceiling: int) -> dict[str, object]:
        nonlocal calls
        calls += 1
        assert ceiling == 3
        return {"attempted": 0, "internal_reconciled": 1}

    result = ContinuousCampaignCoordinator(
        run_segment=run_segment,
        discovery_steps=[],
        attempts_used=lambda: 3,
        stop_requested=lambda: False,
        max_tasks=3,
        duration_seconds=30,
        monotonic=FakeClock(),
    ).run()

    assert calls == 1
    assert result["segments"][0]["internal_reconciled"] == 1
    assert result["stop_reason"] == "attempt_ceiling"
