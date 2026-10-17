"""Synthetic regression tests for SETO-DECOMP-013's aggregation logic."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from seto import elf, mips
from seto.binio import ParseError

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_module_coverage.py"
SPEC = importlib.util.spec_from_file_location("seto_audit_module_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


def test_contiguous_intervals_tile_the_text_range() -> None:
    functions = (mips.Function(0x100, 0x108), mips.Function(0x108, 0x110))
    assert audit.validate_intervals(functions, 0x100, 0x110) is None


@pytest.mark.parametrize(
    "functions,start,end,reason",
    [
        ((mips.Function(0x100, 0x104), mips.Function(0x108, 0x110)), 0x100, 0x110, "gap"),
        ((mips.Function(0x100, 0x108), mips.Function(0x104, 0x110)), 0x100, 0x110, "overlap"),
        ((mips.Function(0x100, 0x100),), 0x100, 0x104, "invalid function interval"),
        ((mips.Function(0x102, 0x106),), 0x102, 0x106, "aligned"),
        ((mips.Function(0x100, 0x108),), 0x100, 0x104, "invalid function interval"),
        ((mips.Function(0x104, 0x108),), 0x100, 0x108, "gap"),
        ((mips.Function(0xFC, 0x108),), 0x100, 0x108, "overlap"),
    ],
)
def test_interval_validator_rejects_gaps_overlaps_and_invalid_ranges(
    functions, start, end, reason
) -> None:
    with pytest.raises(ParseError, match=reason):
        audit.validate_intervals(functions, start, end)


def test_c_sources_match_parsed_addresses_and_0x84_is_a_classification(tmp_path) -> None:
    source_dir = tmp_path / "decomp" / "src"
    source_dir.mkdir(parents=True)
    c_source = source_dir / "func_00000034.c"
    c_source.write_text("void func_00000034(void);\n", encoding="utf-8")
    functions = (mips.Function(0x34, 0x84), mips.Function(0x84, 0x8C))

    sources, uncompiled = audit.reconcile_c_sources(functions, source_dir)

    assert sources == {0x34: c_source}
    assert uncompiled[0]["start"] == "0x84"
    assert uncompiled[0]["end"] == "0x8c"
    assert uncompiled[0]["classification"] == "CLASSIFIED_WITHOUT_C_SOURCE"
    assert uncompiled[0]["functional_identity"] == "UNKNOWN"


@pytest.mark.parametrize(
    "filename,functions,reason",
    [
        ("func_00000100.c", (mips.Function(0x200, 0x208),), "no discovered .text interval"),
        ("func_bad.c", (mips.Function(0x100, 0x108),), "non-canonical function name"),
        (
            "func_00000000.c",
            (mips.Function(0x0, 0x4), mips.Function(0x4, 0x8)),
            "no C source or explicit classification",
        ),
    ],
)
def test_c_source_reconciliation_rejects_strays_and_unclassified_missing_sources(
    tmp_path, filename, functions, reason
) -> None:
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / filename).write_text("void f(void);\n", encoding="utf-8")
    with pytest.raises(ParseError, match=reason):
        audit.reconcile_c_sources(functions, source_dir)


def test_allocated_section_mapping_distinguishes_pt_load_file_and_zero_fill() -> None:
    segment = elf.Segment(0, elf.PT_LOAD, 0x60, 0, 0, 0x100, 0x300, 7, 16)
    text = elf.Section(
        1, ".text", elf.SHT_PROGBITS, elf.SHF_ALLOC | mips.SHF_EXECINSTR,
        0, 0x60, 0x20, 0, 0, 16, 0,
    )
    zero = elf.Section(
        2, ".bss", elf.SHT_NOBITS, elf.SHF_ALLOC | 0x1,
        0x100, 0x160, 0x20, 0, 0, 16, 0,
    )

    assert audit.section_load_mappings(text, (segment,))[0]["relation"] == "FILE_BACKED"
    zero_mapping = audit.section_load_mappings(zero, (segment,))[0]
    assert zero_mapping["relation"] == "ZERO_FILL_SHT_NOBITS"
    assert zero_mapping["file_bytes_read"] is False


def test_relocation_count_groups_do_not_drop_duplicate_entries() -> None:
    relocation = elf.Relocation(
        offset=0x10,
        type=elf.R_MIPS_32,
        symbol_index=0,
        addend=0x20,
        symbol=None,
        target_section=".data",
        section_offset=4,
        file_offset=4,
    )
    assert audit._group_relocations((relocation, relocation)) == [
        {"application_section": ".data", "count": 2, "types": {"R_MIPS_32": 2}}
    ]


def test_matching_metrics_do_not_promote_inconclusive_functions() -> None:
    functions = (mips.Function(0, 4), mips.Function(4, 12))
    rows = (
        {"function": "func_00000000", "status": "MATCHED", "matching_words": 1, "total_words": 1, "difference_count": 0},
        {"function": "func_00000004", "status": "INCONCLUSIVE", "matching_words": 1, "total_words": 2, "difference_count": 0},
    )

    metrics = audit.summarize_match_results(functions, rows, ())

    assert metrics["matched_functions"] == 1
    assert metrics["inconclusive_functions"] == 1
    assert metrics["matched_function_words"] == 1
    assert metrics["inconclusive_function_words"] == 2
    assert metrics["certified_words"] == 2
    assert metrics["pending_words"] == 1


def test_match_report_words_must_equal_the_interval_size() -> None:
    fn = mips.Function(0, 8)
    row = {
        "function": fn.name(), "status": "MATCHED", "matching_words": 2,
        "total_words": 1, "difference_count": 0,
    }
    with pytest.raises(ParseError, match="do not agree"):
        audit.summarize_match_results((fn,), (row,), ())


def test_relocation_inventory_preserves_full_individual_records() -> None:
    relocation = elf.Relocation(
        offset=0x10, type=elf.R_MIPS_32, symbol_index=0, addend=0x20,
        symbol=None, target_section=".data", section_offset=4, file_offset=4,
    )
    records = audit._relocation_rows((relocation, relocation))
    groups = audit._group_relocations((relocation, relocation))
    assert len(records) == 2
    assert records[0] == records[1]
    assert sum(group["count"] for group in groups) == 2


def test_pytest_skip_is_blocked_and_assertion_failure_is_fail(tmp_path) -> None:
    junit = tmp_path / "result.xml"
    junit.write_text(
        '<testsuite><testcase name="one"/><testcase name="two"><skipped message="tool unavailable"/></testcase></testsuite>',
        encoding="utf-8",
    )
    skipped = audit._pytest_outcome(junit, 0, "nodeid")
    assert skipped["status"] == "BLOCKED"
    assert skipped["passed"] == 1 and skipped["skipped"] == 1
    assert skipped["skip_reasons"] == ["tool unavailable"]

    junit.write_text(
        '<testsuite><testcase name="one"><failure message="assertion failed"/></testcase></testsuite>',
        encoding="utf-8",
    )
    assert audit._pytest_outcome(junit, 1, "nodeid")["status"] == "FAIL"


def test_missing_module_input_is_reported_as_blocked() -> None:
    report = audit.blocked_report("libhtml_view.prx", "PRX unavailable")
    assert report["audit_status"] == "BLOCKED"
    assert report["module"]["sha256"] is None
    assert report["baseline_checks"][0]["status"] == "BLOCKED"


def test_canonical_json_does_not_depend_on_mapping_insertion_order() -> None:
    left = {"outer": {"second": 2, "first": 1}, "count": 3}
    right = {"count": 3, "outer": {"first": 1, "second": 2}}
    assert audit.canonical_json(left) == audit.canonical_json(right)


def _match_report_fixture(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    build_dir = repo / "build"
    monkeypatch.setattr(audit, "REPO_ROOT", repo)
    monkeypatch.setattr(audit.identity_audit, "REPO_ROOT", repo)

    function = mips.Function(0x34, 0x84)
    name = function.name()
    source = repo / "decomp" / "src" / "func_00000034.c"
    object_path = build_dir / "matches" / "f34" / "func_00000034.o"
    source.parent.mkdir(parents=True)
    object_path.parent.mkdir(parents=True)
    source.write_text("int func_00000034(void) { return 0; }\n", encoding="utf-8")
    object_path.write_bytes(b"synthetic compiled object")
    report = {
        "function": name,
        "symbol": name,
        "module_sha256": "a" * 64,
        "address": "0x34",
        "section": ".text",
        "status": "MATCHED",
        "exit_code": 0,
        "evidence": "compiled-object",
        "verified_decompilation": True,
        "match": {
            "name": name,
            "address": 0x34,
            "total_words": 20,
            "matching_words": 20,
            "status": "MATCHED",
            "difference_count": 0,
            "differences": [],
            "relocation_issues": [],
            "limitations": [],
            "candidate": {"section_offset": 0, "path": object_path.relative_to(repo).as_posix()},
        },
        "provenance": {
            "source": source.relative_to(repo).as_posix(),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "object": object_path.relative_to(repo).as_posix(),
            "object_sha256": hashlib.sha256(object_path.read_bytes()).hexdigest(),
            "compiler": "mwccpsp",
            "flags": ["-O4,p", "-sdatathreshold", "0"],
        },
    }
    expected = (0x34, "func_00000034.c", "MATCHED", 20, 20)
    return build_dir, report, function, source, expected


def test_consistent_match_report_is_accepted(tmp_path, monkeypatch) -> None:
    build_dir, report, function, source, expected = _match_report_fixture(tmp_path, monkeypatch)
    checked = audit._checked_match_report(
        report,
        build_dir=build_dir,
        module_sha256="a" * 64,
        function=function,
        source=source,
        expected_case=expected,
    )
    assert checked["baseline_check"] == {"status": "PASS", "errors": []}


def test_stale_match_report_from_another_module_version_is_rejected(tmp_path, monkeypatch) -> None:
    build_dir, report, function, source, expected = _match_report_fixture(tmp_path, monkeypatch)
    report["module_sha256"] = "b" * 64
    with pytest.raises(ParseError, match="another function, section, or PRX version"):
        audit._checked_match_report(
            report,
            build_dir=build_dir,
            module_sha256="a" * 64,
            function=function,
            source=source,
            expected_case=expected,
        )


def test_unaccounted_relocation_fails_the_reconciliation_check() -> None:
    metrics = {
        "text_words": 509,
        "interval_count": 16,
        "c_sources": 15,
        "stub_words": 2536,
        "matching": {
            "matched_functions": 7,
            "inconclusive_functions": 8,
            "nonmatching_functions": 0,
            "matched_function_words": 216,
            "inconclusive_function_words": 291,
            "inconclusive_certified_words": 231,
            "certified_words": 447,
            "pending_words": 60,
            "unreconstructed_words": 2,
            "reconstructed_functions": 15,
        },
    }
    table = SimpleNamespace(imports={}, tables=(), limitations=())
    relocations = {
        "count": 3,
        "entries": [{}, {}, {}],
        "source_sections": [{"application_section": ".text", "count": 2, "types": {}}],
        "psp_inventory": {"types": {}},
    }
    checks = audit._make_checks(metrics, (), table, relocations, (), ())
    by_claim = {check["claim"]: check for check in checks}
    assert by_claim["relocation_entries_preserved"]["status"] == "PASS"
    assert by_claim["relocation_groups_reconcile"]["status"] == "FAIL"


