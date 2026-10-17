"""Tests for projecting pending indexes from existing match limitations.

These use synthetic limitation strings only; they do not read private media,
compile C, or create a candidate-symbol identity verifier.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

from seto.binio import ParseError

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_data_identity.py"
SPEC = importlib.util.spec_from_file_location("seto_audit_data_identity", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


def test_pending_indexes_come_from_exact_identity_limitations() -> None:
    limitations = [
        "word 7: HI16/LO16 data identity cannot be proven (original: unresolved; candidate: unresolved)",
        "word 9: HI16/LO16 association relies on relocation order (symbol identity unavailable)",
        "word 11: HI16/LO16 data identity cannot be proven (original: original:.data+0x8; candidate: unresolved)",
    ]

    assert audit.pending_hi_indices(limitations, 16) == {
        7: limitations[0],
        11: limitations[2],
    }


def test_pending_indexes_are_not_guessed_from_a_count() -> None:
    # No qualifying per-word limitation means no index is invented, regardless
    # of any matching/total count a caller may have elsewhere.
    assert audit.pending_hi_indices([], 13) == {}


def test_duplicate_pending_word_is_rejected() -> None:
    limitation = (
        "word 3: HI16/LO16 data identity cannot be proven "
        "(original: unresolved; candidate: unresolved)"
    )
    with pytest.raises(ParseError, match="duplicate identity limitation"):
        audit.pending_hi_indices([limitation, limitation], 8)


def test_out_of_range_pending_word_is_rejected() -> None:
    limitation = (
        "word 8: HI16/LO16 data identity cannot be proven "
        "(original: unresolved; candidate: unresolved)"
    )
    with pytest.raises(ParseError, match="outside 8 words"):
        audit.pending_hi_indices([limitation], 8)


def _baseline_fixture(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    monkeypatch.setattr(audit, "REPO_ROOT", repo)
    function = "func_00000508"
    tag = "f508"
    build_dir = repo / "build" / "seto012"
    source = repo / "decomp" / "src" / f"{function}.c"
    obj = build_dir / "matches" / tag / f"{function}.o"
    source.parent.mkdir(parents=True)
    obj.parent.mkdir(parents=True)
    source.write_bytes(b"int func_00000508(void) { return 0; }\n")
    obj.write_bytes(b"synthetic object bytes")
    report = {
        "function": function,
        "symbol": function,
        "address": "0x508",
        "section": ".text",
        "status": "INCONCLUSIVE",
        "evidence": "compiled-object",
        "exit_code": 5,
        "verified_decompilation": False,
        "match": {
            "name": function,
            "address": 0x508,
            "status": "INCONCLUSIVE",
            "evidence": "binary-range",
            "total_words": 75,
            "matching_words": 63,
            "difference_count": 0,
            "differences": [],
            "relocation_issues": [],
            "limitations": [
                "word 4: HI16/LO16 data identity cannot be proven "
                "(original: unresolved; candidate: unresolved)"
            ],
            "candidate": {
                "path": obj.relative_to(repo).as_posix(),
                "section_offset": 0,
            },
        },
        "provenance": {
            "source": source.relative_to(repo).as_posix(),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "object": obj.relative_to(repo).as_posix(),
            "object_sha256": hashlib.sha256(obj.read_bytes()).hexdigest(),
        },
    }
    return repo, build_dir, source, obj, report


def _check_baseline(report, build_dir, *, tag="f508", function="func_00000508"):
    return audit._checked_baseline(
        report,
        tag=tag,
        function=function,
        address=0x508,
        expected_pending_words=12,
        expected_total_words=75,
        build_dir=build_dir,
    )


def test_checked_baseline_accepts_unchanged_source_and_object(tmp_path, monkeypatch) -> None:
    _repo, build_dir, source, obj, report = _baseline_fixture(tmp_path, monkeypatch)
    parsed = object()
    parsed_paths = []
    monkeypatch.setattr(audit.elf, "parse", lambda path: parsed_paths.append(path) or parsed)

    checked_source, checked_object, candidate = _check_baseline(report, build_dir)

    assert checked_source == source
    assert checked_object == obj
    assert candidate is parsed
    assert parsed_paths == [obj]


@pytest.mark.parametrize("kind", ["source", "object"])
def test_checked_baseline_rejects_modified_artifact_before_elf_parse(
    tmp_path, monkeypatch, kind
) -> None:
    _repo, build_dir, source, obj, report = _baseline_fixture(tmp_path, monkeypatch)
    modified = source if kind == "source" else obj
    modified.write_bytes(modified.read_bytes() + b" modified")
    parsed_paths = []
    monkeypatch.setattr(audit.elf, "parse", lambda path: parsed_paths.append(path))

    with pytest.raises(ParseError, match="SHA-256 mismatch"):
        _check_baseline(report, build_dir)

    assert parsed_paths == [], "a modified candidate must be rejected before elf.parse()"


@pytest.mark.parametrize("kind", ["source", "object"])
def test_checked_baseline_rejects_missing_artifact(tmp_path, monkeypatch, kind) -> None:
    _repo, build_dir, source, obj, report = _baseline_fixture(tmp_path, monkeypatch)
    (source if kind == "source" else obj).unlink()
    with pytest.raises(ParseError, match=f"{kind} file is missing"):
        _check_baseline(report, build_dir)


@pytest.mark.parametrize("kind", ["source", "object"])
@pytest.mark.parametrize("bad_hash", [None, "not-a-sha256"])
def test_checked_baseline_rejects_missing_or_malformed_hash(
    tmp_path, monkeypatch, kind, bad_hash
) -> None:
    _repo, build_dir, _source, _obj, report = _baseline_fixture(tmp_path, monkeypatch)
    report["provenance"][f"{kind}_sha256"] = bad_hash
    with pytest.raises(ParseError, match=f"invalid {kind} SHA-256"):
        _check_baseline(report, build_dir)


def test_checked_baseline_rejects_report_for_another_function(tmp_path, monkeypatch) -> None:
    _repo, build_dir, _source, _obj, report = _baseline_fixture(tmp_path, monkeypatch)
    report["function"] = "func_000004B8"
    with pytest.raises(ParseError, match="belongs to another function"):
        _check_baseline(report, build_dir)


def _artifact_review(tmp_path: Path, monkeypatch, filenames: tuple[str, ...]):
    repo = tmp_path / "repo"
    game = repo / "private" / "PSP_GAME"
    gmodule = game / "USRDIR" / "gmodule"
    gmodule.mkdir(parents=True)
    prx = gmodule / "libhtml_view.prx"
    prx.write_bytes(audit.elf.ELF_MAGIC)
    for filename in filenames:
        (gmodule / filename).write_bytes(b"candidate contents are not validation")

    # These are generated project files. Their presence must not turn an empty
    # distribution search into candidate evidence or a verified link.
    monkeypatch.setattr(audit, "REPO_ROOT", repo)
    generated = (
        repo / "config" / "splat" / "libhtml_view.yaml",
        repo / "build" / "libhtml_view.ld",
        repo / "build" / "seto011" / "shared-state.json",
    )
    for path in generated:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("generated locally", encoding="utf-8")
    original = SimpleNamespace(
        header=SimpleNamespace(file_type_name="ET_MIPS_PSP_PRX"),
        symbols=(),
        sections=(),
        comment=lambda: None,
    )
    return audit._bounded_local_artifact_review(prx, original, tmp_path / "audit")


def test_artifact_search_reports_no_candidates_and_excludes_generated_outputs(
    tmp_path, monkeypatch
) -> None:
    review = _artifact_review(tmp_path, monkeypatch, ())

    assert review["evidence_search_status"] == "NO_CANDIDATES"
    assert review["candidate_count"] == 0
    assert review["candidates"] == []
    assert review["finding"] == (
        "No candidate linker or symbol artifacts were found in the bounded search paths."
    )
    assert review["independent_identity_verified"] is False
    assert review["independent_original_link_artifact_found"] is False
    generated = review["generated_context_rejected_as_independent_evidence"]
    assert all(item["present"] and not item["independent_identity_evidence"] for item in generated)


def test_artifact_search_lists_candidates_deterministically_without_promoting_them(
    tmp_path, monkeypatch
) -> None:
    review = _artifact_review(tmp_path, monkeypatch, ("symbols.map", "a.o", "layout.map"))

    assert review["evidence_search_status"] == "CANDIDATES_UNVERIFIED"
    assert review["candidate_count"] == 3
    assert [item["filename"] for item in review["candidates"]] == [
        "a.o",
        "layout.map",
        "symbols.map",
    ]
    assert all("unverified" in item["classification"] for item in review["candidates"])
    assert review["finding"] == (
        "Candidate linker or symbol artifacts were found, but none has been independently "
        "validated. No cross-artifact identity is established."
    )
    assert review["independent_identity_verified"] is False
    assert review["independent_original_link_artifact_found"] is False
