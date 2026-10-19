"""Synthetic, private-media-free tests for SETO-DECOMP-018 triage."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Mapping

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
for _path in (REPO_ROOT / "src", REPO_ROOT / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from seto import elf, mips  # noqa: E402
from conftest import StubSpec, build_import_module, jr, jal, word  # noqa: E402

SCRIPT = REPO_ROOT / "scripts" / "triage_libtutoriallist.py"
SPEC = importlib.util.spec_from_file_location("seto_triage_libtutoriallist", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
triage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = triage
SPEC.loader.exec_module(triage)


def _synthetic_module():
    """One module with a direct local call, two imports sharing an NID, and returns."""
    shared_nid = 0x12345678
    code = (
        word(jal(0x10))
        + word(0)
        + word(jal(0x30))
        + word(0)
        + word(jr())
        + word(0)
        + word(jr())
        + word(0)
        + word(jr())
        + word(0)
        + word(jal(0x38))
        + word(0)
    )
    image = build_import_module(
        (StubSpec("libAlpha", (shared_nid,)), StubSpec("libBeta", (shared_nid,))),
        code=code,
        calls=(0, 8, 40),
    )
    return elf.parse(image.data, "synthetic.prx"), hashlib.sha256(image.data).hexdigest()


def _synthetic_unknown_call_module():
    shared_nid = 0x12345678
    code = (
        word(jal(0x10))
        + word(0)
        + word(jal(0x30))
        + word(0)
        + word(jr())
        + word(0)
        + word(jr())
        + word(0)
        + word(jr())
        + word(0)
        + word(jal(0x40))
        + word(0)
    )
    image = build_import_module(
        (StubSpec("libAlpha", (shared_nid,)), StubSpec("libBeta", (shared_nid,))),
        code=code,
        calls=(0, 8, 40),
    )
    return elf.parse(image.data, "synthetic-unknown.prx"), hashlib.sha256(image.data).hexdigest()


def _ghidra_report(baseline: Mapping[str, object], *, not_found: tuple[int, ...] = ()):
    functions = []
    for function in baseline["functions"]:
        address = int(str(function["start"]), 16)
        boundary = "NOT_FOUND" if address in not_found else "EXACT"
        functions.append(
            {
                "start": function["start"],
                "end": function["end"],
                "boundary_status": boundary,
                "decomp_status": "NOT_RUN" if boundary == "NOT_FOUND" else "OK",
                "body_start": function["start"] if boundary == "EXACT" else None,
                "body_end": function["end"] if boundary == "EXACT" else None,
                "body_addresses": function["size_bytes"] if boundary == "EXACT" else None,
                "body_ranges": 1 if boundary == "EXACT" else 0,
            }
        )
    return {"schema_version": 1, "module_sha256": baseline["module"]["sha256"], "functions": functions}


def test_intervals_tile_aligned_text_and_invalid_ranges_fail_closed() -> None:
    intervals = (mips.Function(0x100, 0x108), mips.Function(0x108, 0x110))
    assert triage.validate_function_intervals(intervals, 0x100, 0x110) is None

    for broken in (
        (mips.Function(0x100, 0x108), mips.Function(0x10C, 0x110)),
        (mips.Function(0x100, 0x10C), mips.Function(0x108, 0x110)),
        (mips.Function(0x102, 0x106),),
        (mips.Function(0x100, 0x100),),
        (mips.Function(0xFC, 0x110),),
        (mips.Function(0x100, 0x114),),
    ):
        with pytest.raises(triage.ProbeError):
            triage.validate_function_intervals(broken, 0x100, 0x110)


def test_baseline_is_deterministic_and_keeps_local_import_and_duplicate_nid_identity() -> None:
    module, module_sha = _synthetic_module()
    first = triage.build_baseline(module, module_sha, module_path="synthetic.prx")
    second = triage.build_baseline(module, module_sha, module_path="synthetic.prx")

    assert triage.canonical_json(first) == triage.canonical_json(second)
    assert first["module"]["sha256"] == module_sha
    assert first["layout"]["validation_issues"] == []
    starts = [int(str(function["start"]), 16) for function in first["functions"]]
    assert starts == sorted(starts)
    assert len(first["functions"]) == 5
    assert first["imports"]["call_kind_counts"] == {"local": 1, "import": 2}
    caller = first["functions"][0]
    assert [call["kind"] for call in caller["calls"]] == ["local", "import"]

    # Equal numeric NIDs remain distinct identities because library is part of the key.
    other_module, other_sha = _synthetic_module()
    other_baseline = triage.build_baseline(other_module, other_sha, module_path="synthetic.prx")
    identities = {
        (call["import"]["library"], call["import"]["nid"])
        for function in other_baseline["functions"]
        for call in function["calls"]
        if call.get("import")
    }
    assert identities == {("libAlpha", "0x12345678"), ("libBeta", "0x12345678")}
    assert triage.verify_module_sha256(module_sha, module_sha) is None
    with pytest.raises(triage.ProbeError, match="differs from the pinned baseline"):
        triage.verify_module_sha256("0" * 64, module_sha)


def test_triage_uses_evidence_and_does_not_promote_unproven_fragments() -> None:
    module, module_sha = _synthetic_module()
    baseline = triage.build_baseline(module, module_sha, module_path="synthetic.prx")
    evidence = _ghidra_report(baseline, not_found=(0x0,))
    result = triage.build_triage(baseline, evidence)

    first = result["functions"][0]
    assert first["decision"] == "FRAGMENT"
    assert result["function_count"] == 5
    assert result["selected_count"] == 3
    assert any("not cryptographic authenticity" in item for item in result["limitations"])
    selected = {item["start"] for item in result["selected_functions"]}
    assert selected == {"0x10", "0x18", "0x20"}


def test_data_locations_without_cross_artifact_identity_are_deferred() -> None:
    module, module_sha = _synthetic_module()
    baseline = triage.build_baseline(module, module_sha, module_path="synthetic.prx")
    baseline["functions"][0]["data_references"] = [
        {
            "kind": "hi16-lo16",
            "status": "PROVEN",
            "location": "PROVEN",
            "object_identity": "NOT_APPLICABLE",
            "target": {"section": ".data", "offset": "0x4"},
        }
    ]
    result = triage.build_triage(baseline, _ghidra_report(baseline))
    first = result["functions"][0]
    assert first["decision"] == "DEFERRED"
    assert any("cross-artifact object identity" in risk for risk in first["risks"])


def test_unknown_calls_are_not_selected_as_recovered_imports() -> None:
    module, module_sha = _synthetic_unknown_call_module()
    baseline = triage.build_baseline(module, module_sha, module_path="synthetic.prx")
    assert baseline["imports"]["call_kind_counts"]["unknown"] == 1
    result = triage.build_triage(baseline, _ghidra_report(baseline))
    final = result["functions"][-1]
    assert final["call_counts"]["unknown"] == 1
    assert final["decision"] == "DEFERRED"
    assert any("unresolved" in risk for risk in final["risks"])


def test_foreign_or_incomplete_ghidra_evidence_is_rejected() -> None:
    module, module_sha = _synthetic_module()
    baseline = triage.build_baseline(module, module_sha, module_path="synthetic.prx")
    foreign = _ghidra_report(baseline)
    foreign["module_sha256"] = "0" * 64
    with pytest.raises(triage.ProbeError, match="another module SHA-256"):
        triage.build_triage(baseline, foreign)

    for invalid_schema in (True, 1.0):
        malformed = _ghidra_report(baseline)
        malformed["schema_version"] = invalid_schema
        with pytest.raises(triage.ProbeError, match="schema_version 1"):
            triage.build_triage(baseline, malformed)

    incomplete = _ghidra_report(baseline)
    incomplete["functions"].pop()
    with pytest.raises(triage.ProbeError, match="does not cover every"):
        triage.build_triage(baseline, incomplete)

    wrong_body = _ghidra_report(baseline)
    wrong_body["functions"][0]["body_start"] = "0x4"
    with pytest.raises(triage.ProbeError, match="body evidence disagrees"):
        triage.build_triage(baseline, wrong_body)

    split_body = _ghidra_report(baseline)
    split_body["functions"][0]["body_ranges"] = 2
    with pytest.raises(triage.ProbeError, match="body evidence disagrees"):
        triage.build_triage(baseline, split_body)


def _match_envelope(*, status: str = "INCONCLUSIVE", module_sha: str = "a" * 64):
    record = {
        "function": "func_00000000",
        "address": "0x0",
        "section": ".text",
        "symbol": "func_00000000",
        "status": status,
        "evidence": "compiled-object",
        "equivalence": "function equivalence with canonically resolved relocations"
        if status == "MATCHED"
        else None,
        "verified_decompilation": status == "MATCHED",
        "exit_code": {"MATCHED": 0, "NONMATCHING": 3, "INCONCLUSIVE": 5}[status],
        "provenance": {
            "source": "decomp/src/libtutoriallist/func_00000000.c",
            "source_sha256": "b" * 64,
            "object": "build/seto018/matches/f0/attempt-1/func_00000000.o",
            "object_sha256": "c" * 64,
        },
        "match": {
            "name": "func_00000000",
            "address": 0,
            "status": status,
            "matching_words": 2,
            "total_words": 2,
            "difference_count": 0,
            "differences": [],
            "relocation_issues": [],
            "limitations": [] if status == "MATCHED" else ["data object identity is unknown"],
            "resolved_calls": [],
            "resolved_data": [],
            # Numeric address/word equality is not an identity proof and does not alter status.
            "equal_numeric_data_addresses": True,
            "object_identity": "NOT_APPLICABLE",
        },
    }
    return {
        "module_sha256": module_sha,
        "source_path": "decomp/src/libtutoriallist/func_00000000.c",
        "object_path": "build/seto018/matches/f0/attempt-1/func_00000000.o",
        "source_sha256": "b" * 64,
        "object_sha256": "c" * 64,
        "record": record,
        "saved_record": {key: value for key, value in record.items() if key != "match"},
    }


def test_match_report_sha_and_inconclusive_status_are_fail_closed() -> None:
    summary = triage.validate_match_envelope(
        _match_envelope(), expected_module_sha256="a" * 64, expected_function=0
    )
    assert summary["status"] == "INCONCLUSIVE"
    assert summary["verified_decompilation"] is False

    with pytest.raises(triage.ProbeError, match="another module SHA-256"):
        triage.validate_match_envelope(
            _match_envelope(module_sha="d" * 64),
            expected_module_sha256="a" * 64,
            expected_function=0,
        )

    bad_hash = _match_envelope()
    bad_hash["source_sha256"] = "e" * 64
    with pytest.raises(triage.ProbeError, match="invalid source_sha256"):
        triage.validate_match_envelope(
            bad_hash, expected_module_sha256="a" * 64, expected_function=0
        )

    bad_object_hash = _match_envelope()
    bad_object_hash["object_sha256"] = "e" * 64
    with pytest.raises(triage.ProbeError, match="invalid object_sha256"):
        triage.validate_match_envelope(
            bad_object_hash, expected_module_sha256="a" * 64, expected_function=0
        )

    wrong_function = _match_envelope()
    with pytest.raises(triage.ProbeError, match="another function"):
        triage.validate_match_envelope(
            wrong_function, expected_module_sha256="a" * 64, expected_function=4
        )


def test_matched_report_requires_zero_differences_and_no_limitations() -> None:
    valid = triage.validate_match_envelope(
        _match_envelope(status="MATCHED"),
        expected_module_sha256="a" * 64,
        expected_function=0,
        expected_total_words=2,
    )
    assert valid["status"] == "MATCHED"

    bad_diff = _match_envelope(status="MATCHED")
    bad_diff["record"]["match"].update(
        {"matching_words": 1, "difference_count": 1, "differences": [{"word_index": 0}]}
    )
    with pytest.raises(triage.ProbeError, match="MATCHED report contains differences"):
        triage.validate_match_envelope(
            bad_diff, expected_module_sha256="a" * 64, expected_function=0
        )

    bad_limit = _match_envelope(status="MATCHED")
    bad_limit["record"]["match"]["limitations"] = ["identity unresolved"]
    with pytest.raises(triage.ProbeError, match="MATCHED report contains differences"):
        triage.validate_match_envelope(
            bad_limit, expected_module_sha256="a" * 64, expected_function=0
        )

    bad_relocation = _match_envelope(status="MATCHED")
    bad_relocation["record"]["match"]["relocation_issues"] = ["unresolved relocation"]
    with pytest.raises(triage.ProbeError, match="MATCHED report contains differences"):
        triage.validate_match_envelope(
            bad_relocation, expected_module_sha256="a" * 64, expected_function=0
        )


def test_build_reports_are_deterministic_and_reject_symlinked_outputs(tmp_path: Path) -> None:
    module, module_sha = _synthetic_module()
    baseline = triage.build_baseline(module, module_sha, module_path="synthetic.prx")
    triage_report = triage.build_triage(baseline, _ghidra_report(baseline))
    repo = tmp_path / "repo"

    first_paths = triage.write_reports(baseline, triage_report, repo_root=repo)
    first_bytes = tuple(path.read_bytes() for path in first_paths)
    second_paths = triage.write_reports(baseline, triage_report, repo_root=repo)
    assert first_paths == second_paths
    assert first_bytes == tuple(path.read_bytes() for path in second_paths)

    outside = tmp_path / "outside.json"
    outside.write_text("keep", encoding="utf-8")
    baseline_path = first_paths[0]
    baseline_path.unlink()
    try:
        baseline_path.symlink_to(outside)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"platform does not permit local symlink creation: {exc}")
    with pytest.raises(triage.ProbeError, match="may not be a symlink"):
        triage.write_reports(baseline, triage_report, repo_root=repo)
    assert outside.read_text(encoding="utf-8") == "keep"


def test_build_reports_reject_a_broken_symlink_without_creating_its_target(
    tmp_path: Path,
) -> None:
    module, module_sha = _synthetic_module()
    baseline = triage.build_baseline(module, module_sha, module_path="synthetic.prx")
    triage_report = triage.build_triage(baseline, _ghidra_report(baseline))
    repo = tmp_path / "repo"
    build_root = repo / "build" / "seto018"
    build_root.mkdir(parents=True)
    destination = tmp_path / "external" / "missing.json"
    output = build_root / "baseline.json"
    try:
        output.symlink_to(destination)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"platform does not permit local symlink creation: {exc}")

    with pytest.raises(triage.ProbeError, match="may not be a symlink"):
        triage.write_reports(baseline, triage_report, repo_root=repo)

    assert output.is_symlink()
    assert not destination.exists()
    assert not destination.parent.exists()


def _create_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"platform does not permit local symlink creation: {exc}")


def test_match_outputs_reject_a_broken_report_symlink_before_deleting_the_object(
    tmp_path: Path,
) -> None:
    build_root = tmp_path / "build" / "seto018"
    build_root.mkdir(parents=True)
    obj = build_root / "func_00000000.o"
    obj.write_bytes(b"stale object")
    destination = tmp_path / "outside" / "func_00000000.c.match.json"
    report = build_root / "func_00000000.c.match.json"
    _create_symlink_or_skip(report, destination)

    with pytest.raises(triage.ProbeError, match="may not be a symlink"):
        triage._prepare_fresh_match_outputs((obj, report), build_root)

    # Both outputs are preflighted before any cleanup or subprocess write.
    assert obj.read_bytes() == b"stale object"
    assert report.is_symlink()
    assert not destination.exists()
    assert not destination.parent.exists()


def test_match_outputs_reject_a_valid_object_symlink_and_preserve_its_target(
    tmp_path: Path,
) -> None:
    build_root = tmp_path / "build" / "seto018"
    build_root.mkdir(parents=True)
    destination = tmp_path / "outside.o"
    destination.write_bytes(b"keep")
    obj = build_root / "func_00000000.o"
    _create_symlink_or_skip(obj, destination)
    report = build_root / "func_00000000.c.match.json"

    with pytest.raises(triage.ProbeError, match="may not be a symlink"):
        triage._prepare_fresh_match_outputs((obj, report), build_root)

    assert obj.is_symlink()
    assert destination.read_bytes() == b"keep"
    assert not report.exists()


def test_match_outputs_remove_stale_regular_object_and_report_for_fresh_compilation(
    tmp_path: Path,
) -> None:
    build_root = tmp_path / "build" / "seto018"
    build_root.mkdir(parents=True)
    obj = build_root / "func_00000000.o"
    report = build_root / "func_00000000.c.match.json"
    obj.write_bytes(b"stale object")
    report.write_text("stale report", encoding="utf-8")

    triage._prepare_fresh_match_outputs((obj, report), build_root)
    assert not obj.exists()
    assert not report.exists()

    # Missing outputs are normal on a fresh attempt (unlink is idempotent).
    triage._prepare_fresh_match_outputs((obj, report), build_root)
    assert not obj.exists()
    assert not report.exists()


def test_match_outputs_reject_paths_outside_the_build_root(tmp_path: Path) -> None:
    build_root = tmp_path / "build" / "seto018"
    build_root.mkdir(parents=True)
    outside = tmp_path / "outside.o"
    outside.write_bytes(b"keep")

    with pytest.raises(triage.ProbeError, match="escapes its allowed root"):
        triage._prepare_fresh_match_outputs((outside,), build_root)

    assert outside.read_bytes() == b"keep"


def test_match_outputs_reject_a_directory_instead_of_a_regular_file(tmp_path: Path) -> None:
    build_root = tmp_path / "build" / "seto018"
    build_root.mkdir(parents=True)
    unexpected = build_root / "func_00000000.o"
    unexpected.mkdir()

    with pytest.raises(triage.ProbeError, match="not a regular file"):
        triage._prepare_fresh_match_outputs((unexpected,), build_root)

    assert unexpected.is_dir()


def test_candidate_input_guard_rejects_a_symlinked_source_directory(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    actual = repo / "other-sources"
    actual.mkdir(parents=True)
    candidate = actual / "func_00001E94.c"
    candidate.write_text("int unrelated(void) { return 0; }\n", encoding="utf-8")
    source_root = repo / "decomp" / "src"
    source_root.mkdir(parents=True)
    link = source_root / "libtutoriallist"
    _create_symlink_or_skip(link, actual)
    aliased = link / candidate.name

    with pytest.raises(triage.ProbeError, match="symlink component"):
        triage._reject_repo_symlink_components(aliased, repo, "candidate source")

    assert candidate.read_text(encoding="utf-8") == "int unrelated(void) { return 0; }\n"
